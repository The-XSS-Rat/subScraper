#!/usr/bin/env python3
"""
Tests for per-tool worker scaling: the single "workers per tool" setting, its
inheritance rules, and the sharding that turns those workers into real
parallelism for httpx, nuclei and nikto.
"""

import json
import os
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(__file__))

with patch('main.ensure_dirs'), \
     patch('main.init_database'), \
     patch('main.migrate_json_to_sqlite'):
    import main  # noqa: E402


class TestWorkerLimits:
    def test_default_is_five(self):
        assert main.DEFAULT_TOOL_WORKERS == 5
        assert main.default_tool_workers({}) == 5

    def test_zero_means_inherit(self):
        cfg = {"default_tool_workers": 5, "max_parallel_nikto": 0}
        assert main.tool_worker_limit("nikto", cfg) == 5

    def test_blank_means_inherit(self):
        cfg = {"default_tool_workers": 7, "max_parallel_httpx": ""}
        assert main.tool_worker_limit("httpx", cfg) == 7

    def test_missing_key_means_inherit(self):
        assert main.tool_worker_limit("nuclei", {"default_tool_workers": 3}) == 3

    def test_explicit_override_wins(self):
        cfg = {"default_tool_workers": 5, "max_parallel_nuclei": 2}
        assert main.tool_worker_limit("nuclei", cfg) == 2

    def test_limits_are_clamped(self):
        assert main.tool_worker_limit("nikto", {"max_parallel_nikto": 9999}) == main.MAX_TOOL_WORKERS
        assert main.default_tool_workers({"default_tool_workers": 0}) == 5
        assert main.default_tool_workers({"default_tool_workers": -4}) == 1
        assert main.default_tool_workers({"default_tool_workers": "junk"}) == 5

    def test_every_tool_has_a_field(self):
        assert set(main.TOOL_PARALLEL_FIELDS) == set(main.TOOLS)

    def test_gates_start_at_the_default(self):
        for tool in main.TOOL_PARALLEL_FIELDS:
            assert main.TOOL_GATES[tool].snapshot()["limit"] >= 1

    def test_apply_concurrency_limits_updates_gates(self):
        original = {tool: gate.snapshot()["limit"] for tool, gate in main.TOOL_GATES.items()}
        try:
            cfg = dict(main.default_config())
            cfg["default_tool_workers"] = 4
            cfg["max_parallel_nikto"] = 2
            main.apply_concurrency_limits(cfg)
            assert main.TOOL_GATES["httpx"].snapshot()["limit"] == 4
            assert main.TOOL_GATES["nikto"].snapshot()["limit"] == 2
        finally:
            for tool, limit in original.items():
                main.TOOL_GATES[tool].update_limit(limit)


class TestSettingsValidation:
    def test_zero_slots_accepted_as_inherit(self):
        cfg = dict(main.default_config())
        with patch.object(main, "save_config"), patch.object(main, "apply_concurrency_limits"):
            ok, message, updated = main.update_config_settings({"max_parallel_nikto": 0})
        assert ok, message
        assert updated["max_parallel_nikto"] == 0

    def test_workers_must_be_a_number(self):
        with patch.object(main, "save_config"), patch.object(main, "apply_concurrency_limits"):
            ok, message, _ = main.update_config_settings({"default_tool_workers": "five"})
        assert not ok
        assert "Workers per tool" in message

    def test_workers_are_clamped_on_save(self):
        with patch.object(main, "save_config"), patch.object(main, "apply_concurrency_limits"):
            ok, _, cfg = main.update_config_settings({"default_tool_workers": 500})
        assert ok
        assert cfg["default_tool_workers"] == main.MAX_TOOL_WORKERS


class TestMigration:
    def test_old_all_ones_config_switches_to_inherit(self):
        cfg = dict(main.default_config())
        for field in main.TOOL_PARALLEL_FIELDS.values():
            cfg[field] = 1
        cfg["_tool_workers_migrated"] = False
        with patch.object(main, "save_config"):
            migrated = main._migrate_tool_worker_settings(cfg)
        assert all(migrated[field] == 0 for field in main.TOOL_PARALLEL_FIELDS.values())
        assert migrated["_tool_workers_migrated"] is True

    def test_deliberate_settings_are_left_alone(self):
        cfg = dict(main.default_config())
        for field in main.TOOL_PARALLEL_FIELDS.values():
            cfg[field] = 1
        cfg["max_parallel_nuclei"] = 3          # user raised this one on purpose
        cfg["_tool_workers_migrated"] = False
        with patch.object(main, "save_config"):
            migrated = main._migrate_tool_worker_settings(cfg)
        assert migrated["max_parallel_nuclei"] == 3
        assert migrated["max_parallel_nikto"] == 1

    def test_migration_runs_once(self):
        cfg = dict(main.default_config())
        for field in main.TOOL_PARALLEL_FIELDS.values():
            cfg[field] = 1
        cfg["_tool_workers_migrated"] = True
        with patch.object(main, "save_config"):
            migrated = main._migrate_tool_worker_settings(cfg)
        assert migrated["max_parallel_nikto"] == 1


class TestSharding:
    def test_even_split(self):
        assert [len(c) for c in main.split_into_shards(list(range(10)), 5)] == [2, 2, 2, 2, 2]

    def test_uneven_split_keeps_every_item(self):
        chunks = main.split_into_shards(list(range(11)), 5)
        assert sum(len(c) for c in chunks) == 11
        assert [item for chunk in chunks for item in chunk] == list(range(11))

    def test_fewer_items_than_workers(self):
        assert [len(c) for c in main.split_into_shards([1, 2, 3], 5)] == [1, 1, 1]

    def test_empty_and_single(self):
        assert main.split_into_shards([], 5) == []
        assert main.split_into_shards([1], 5) == [[1]]
        assert main.split_into_shards(list(range(4)), 1) == [[0, 1, 2, 3]]

    def test_shards_run_in_parallel(self, monkeypatch):
        monkeypatch.setattr(main, "get_config", lambda: {"default_tool_workers": 5})
        main.TOOL_GATES["nikto"].update_limit(5)
        active = {"now": 0, "peak": 0}
        lock = threading.Lock()

        def worker(chunk):
            with lock:
                active["now"] += 1
                active["peak"] = max(active["peak"], active["now"])
            time.sleep(0.2)
            with lock:
                active["now"] -= 1
            return list(chunk)

        started = time.time()
        results = main.run_tool_shards("nikto", list(range(10)), worker)
        elapsed = time.time() - started
        assert active["peak"] == 5              # five workers really ran at once
        assert elapsed < 0.8                    # serial would be ~1.0s
        assert sorted(item for chunk in results for item in chunk) == list(range(10))

    def test_worker_limit_is_respected(self, monkeypatch):
        monkeypatch.setattr(main, "get_config", lambda: {"default_tool_workers": 2})
        main.TOOL_GATES["nikto"].update_limit(2)
        active = {"now": 0, "peak": 0}
        lock = threading.Lock()

        def worker(chunk):
            with lock:
                active["now"] += 1
                active["peak"] = max(active["peak"], active["now"])
            time.sleep(0.1)
            with lock:
                active["now"] -= 1
            return chunk

        main.run_tool_shards("nikto", list(range(8)), worker)
        assert active["peak"] == 2

    def test_failing_shard_does_not_sink_the_rest(self, monkeypatch):
        monkeypatch.setattr(main, "get_config", lambda: {"default_tool_workers": 3})

        def worker(chunk):
            if 0 in chunk:
                raise RuntimeError("boom")
            return chunk

        results = main.run_tool_shards("nikto", list(range(6)), worker)
        assert any(result is None for result in results)
        assert any(result for result in results)


class TestBatchMerge:
    def test_shards_merge_into_one_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main, "DATA_DIR", tmp_path)
        monkeypatch.setattr(main, "get_config", lambda: {"default_tool_workers": 4})
        main.TOOL_GATES["httpx"].update_limit(4)
        hosts = [f"h{i}.example.com" for i in range(8)]
        seen = []
        lock = threading.Lock()

        def scanner(batch_file, suffix):
            chunk = [line.strip() for line in Path(batch_file).read_text().splitlines() if line.strip()]
            with lock:
                seen.append(suffix)
            out = tmp_path / f"httpx_example.com{suffix}.json"
            out.write_text("".join(json.dumps({"host": host}) + "\n" for host in chunk))
            return out

        merged = main.run_batch_sharded("httpx", hosts, "example.com", scanner)
        assert merged and merged.name == "httpx_example.com.json"
        lines = [json.loads(line) for line in merged.read_text().splitlines() if line.strip()]
        assert sorted(entry["host"] for entry in lines) == sorted(hosts)
        assert len(seen) == 4
        assert list(tmp_path.glob("httpx_example.com_w*.json")) == []   # shard files cleaned up
        assert list(tmp_path.glob("subs_*_httpx_batch*")) == []          # inputs cleaned up

    def test_single_worker_still_returns_results(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main, "DATA_DIR", tmp_path)
        monkeypatch.setattr(main, "get_config", lambda: {"default_tool_workers": 1})

        def scanner(batch_file, suffix):
            out = tmp_path / f"nuclei_example.com{suffix}.json"
            out.write_text('{"template-id": "x"}\n')
            return out

        merged = main.run_batch_sharded("nuclei", ["a.example.com"], "example.com", scanner)
        assert merged and merged.read_text().strip()

    def test_no_hosts_means_no_run(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main, "DATA_DIR", tmp_path)
        called = []
        assert main.run_batch_sharded("httpx", [], "example.com",
                                      lambda batch_file, suffix: called.append(suffix)) is None
        assert called == []

    def test_all_shards_failing_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main, "DATA_DIR", tmp_path)
        monkeypatch.setattr(main, "get_config", lambda: {"default_tool_workers": 2})
        merged = main.run_batch_sharded("httpx", ["a.com", "b.com"], "example.com",
                                        lambda batch_file, suffix: None)
        assert merged is None


class TestNiktoSharding:
    def test_hosts_are_split_across_workers(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main, "DATA_DIR", tmp_path)
        monkeypatch.setattr(main, "get_config", lambda: {"default_tool_workers": 5})
        monkeypatch.setattr(main, "ensure_tool_installed", lambda tool: True)
        main.TOOL_GATES["nikto"].update_limit(5)
        chunks = []
        lock = threading.Lock()

        def fake_hosts(subs, domain, config=None, job_domain=None):
            with lock:
                chunks.append(list(subs))
            return [{"host": host, "msg": "finding", "severity": "LOW"} for host in subs]

        monkeypatch.setattr(main, "_nikto_scan_hosts", fake_hosts)
        hosts = [f"h{i}.example.com" for i in range(10)]
        out = main.nikto_scan(hosts, "example.com")
        findings = json.loads(Path(out).read_text())
        assert len(chunks) == 5
        assert sorted(host for chunk in chunks for host in chunk) == sorted(hosts)
        assert len(findings) == 10          # every shard's findings kept

    def test_single_host_runs_inline(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main, "DATA_DIR", tmp_path)
        monkeypatch.setattr(main, "get_config", lambda: {"default_tool_workers": 5})
        monkeypatch.setattr(main, "ensure_tool_installed", lambda tool: True)
        calls = []
        monkeypatch.setattr(main, "_nikto_scan_hosts",
                            lambda subs, domain, config=None, job_domain=None: calls.append(list(subs)) or [])
        main.nikto_scan(["only.example.com"], "example.com")
        assert calls == [["only.example.com"]]


class TestToolGateConcurrency:
    def test_queue_runs_items_in_parallel(self):
        gate = main.ToolGate(4)
        active = {"now": 0, "peak": 0}
        lock = threading.Lock()

        def work():
            with lock:
                active["now"] += 1
                active["peak"] = max(active["peak"], active["now"])
            time.sleep(0.2)
            with lock:
                active["now"] -= 1
            return "done"

        try:
            for _ in range(4):
                gate.enqueue(work)
            deadline = time.time() + 3
            while active["peak"] < 4 and time.time() < deadline:
                time.sleep(0.05)
            assert active["peak"] == 4      # a limit of 4 must mean 4 at once
        finally:
            gate.stop_worker()

    def test_queue_never_exceeds_the_limit(self):
        gate = main.ToolGate(2)
        active = {"now": 0, "peak": 0}
        lock = threading.Lock()

        def work():
            with lock:
                active["now"] += 1
                active["peak"] = max(active["peak"], active["now"])
            time.sleep(0.15)
            with lock:
                active["now"] -= 1

        try:
            for _ in range(6):
                gate.enqueue(work)
            time.sleep(1.2)
            assert active["peak"] == 2
        finally:
            gate.stop_worker()


class TestUiAndCli:
    def test_workers_setting_in_ui(self):
        assert 'id="settings-default-tool-workers"' in main.INDEX_HTML
        assert 'name="default_tool_workers"' in main.INDEX_HTML
        assert 'id="settings-reset-tool-slots"' in main.INDEX_HTML

    def test_slot_inputs_accept_zero(self):
        assert 'name="max_parallel_nikto" min="0"' in main.INDEX_HTML
        assert 'name="max_parallel_httpx" min="0"' in main.INDEX_HTML

    def test_slots_load_without_defaulting_to_one(self):
        # `|| 1` here would silently turn "inherit" back into an override.
        assert "config.max_parallel_nikto ?? 0" in main.INDEX_HTML
        assert "config.max_parallel_nikto || 1" not in main.INDEX_HTML

    def test_cli_flag_exists(self):
        source = Path(main.__file__).read_text(encoding="utf-8")
        assert '"--tool-workers"' in source
