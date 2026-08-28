#!/usr/bin/env python3
"""
Tests for OS-aware tool installation and the JS findings overview.

The install tests simulate macOS, Debian, Kali, Arch and Windows so the
install plans and instructions can be checked without those machines.
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(__file__))

with patch('main.ensure_dirs'), \
     patch('main.init_database'), \
     patch('main.migrate_json_to_sqlite'):
    import main  # noqa: E402


@pytest.fixture(autouse=True)
def clear_platform_cache():
    main._PLATFORM_CACHE.clear()
    main._PKG_AVAILABILITY_CACHE.clear()
    yield
    main._PLATFORM_CACHE.clear()
    main._PKG_AVAILABILITY_CACHE.clear()


def fake_platform(monkeypatch, system, binaries, os_release=None, euid=1000, sudo_ok=False):
    """Pretend we are on another OS with a given set of installed binaries."""
    monkeypatch.setattr(main.platform, "system", lambda: system)
    monkeypatch.setattr(main.platform, "release", lambda: "test-release")
    monkeypatch.setattr(main.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(main, "_read_os_release", lambda: os_release or {})
    monkeypatch.setattr(main, "_which", lambda name: f"/usr/bin/{name}" if name in binaries else None)
    if hasattr(os, "geteuid"):
        monkeypatch.setattr(main.os, "geteuid", lambda: euid)

    def fake_run(cmd, *args, **kwargs):
        class Result:
            returncode = 0 if sudo_ok else 1
            stdout = ""
            stderr = ""
        return Result()

    monkeypatch.setattr(main.subprocess, "run", fake_run)
    main._PLATFORM_CACHE.clear()
    main._PKG_AVAILABILITY_CACHE.clear()


class TestPlatformDetection:
    def test_macos_detected_with_brew(self, monkeypatch):
        fake_platform(monkeypatch, "Darwin", {"brew", "go"})
        info = main.detect_platform(refresh=True)
        assert info["system"] == "macos"
        assert info["system_label"] == "macOS"
        assert set(info["package_managers"]) == {"brew", "go"}

    def test_debian_family_detected(self, monkeypatch):
        fake_platform(monkeypatch, "Linux", {"apt-get", "go"},
                      os_release={"ID": "ubuntu", "ID_LIKE": "debian", "PRETTY_NAME": "Ubuntu 24.04"})
        info = main.detect_platform(refresh=True)
        assert info["system"] == "linux"
        assert info["distro_family"] == "debian"
        assert "apt" in info["package_managers"]

    def test_arch_family_detected(self, monkeypatch):
        fake_platform(monkeypatch, "Linux", {"pacman"}, os_release={"ID": "manjaro", "ID_LIKE": "arch"})
        assert main.detect_platform(refresh=True)["distro_family"] == "arch"

    def test_rhel_family_detected(self, monkeypatch):
        fake_platform(monkeypatch, "Linux", {"dnf"}, os_release={"ID": "rocky", "ID_LIKE": "rhel centos fedora"})
        assert main.detect_platform(refresh=True)["distro_family"] == "rhel"

    def test_windows_never_offers_unix_managers(self, monkeypatch):
        fake_platform(monkeypatch, "Windows", {"winget", "scoop", "go", "apt-get", "brew"})
        info = main.detect_platform(refresh=True)
        assert info["system"] == "windows"
        assert set(info["package_managers"]) <= {"winget", "scoop", "choco", "go", "pip"}
        assert "apt" not in info["package_managers"]
        assert "brew" not in info["package_managers"]

    def test_root_needs_no_sudo(self, monkeypatch):
        fake_platform(monkeypatch, "Linux", {"apt-get"}, os_release={"ID": "debian"}, euid=0)
        info = main.detect_platform(refresh=True)
        assert info["is_root"] is True
        assert info["can_elevate"] is True
        assert main._sudo_prefix("apt") == []

    def test_password_sudo_blocks_unattended_install(self, monkeypatch):
        fake_platform(monkeypatch, "Linux", {"apt-get", "sudo"}, os_release={"ID": "debian"}, sudo_ok=False)
        info = main.detect_platform(refresh=True)
        assert info["sudo"] == "password-required"
        assert info["can_elevate"] is False
        assert main._sudo_prefix("apt") is None      # would prompt: never run it
        assert main._sudo_prefix("brew") == []       # brew needs no root

    def test_passwordless_sudo_allowed(self, monkeypatch):
        fake_platform(monkeypatch, "Linux", {"apt-get", "sudo"}, os_release={"ID": "debian"}, sudo_ok=True)
        assert main.detect_platform(refresh=True)["sudo"] == "passwordless"
        assert main._sudo_prefix("apt") == ["sudo", "-n"]


class TestInstallPlans:
    def test_macos_prefers_brew_over_go(self, monkeypatch):
        fake_platform(monkeypatch, "Darwin", {"brew", "go"})
        monkeypatch.setattr(main, "_package_available", lambda manager, package: True)
        plan = main.build_install_plan("nuclei")
        assert [step["manager"] for step in plan] == ["brew", "go"]
        assert plan[0]["display_command"] == "brew install nuclei"
        assert plan[0]["needs_root"] is False

    def test_debian_uses_apt_with_sudo(self, monkeypatch):
        fake_platform(monkeypatch, "Linux", {"apt-get", "sudo", "go"},
                      os_release={"ID": "debian"}, sudo_ok=True)
        monkeypatch.setattr(main, "_package_available", lambda manager, package: True)
        plan = main.build_install_plan("nikto")
        assert plan[0]["manager"] == "apt"
        assert plan[0]["display_command"] == "sudo apt-get install -y nikto"
        assert plan[0]["can_run_unattended"] is True

    def test_unavailable_package_is_not_offered(self, monkeypatch):
        fake_platform(monkeypatch, "Linux", {"apt-get", "sudo", "go"},
                      os_release={"ID": "ubuntu", "ID_LIKE": "debian"}, sudo_ok=True)
        # Ubuntu has no 'gau' package; go install must be the runnable path.
        monkeypatch.setattr(main, "_package_available",
                            lambda manager, package: manager != "apt")
        plan = main.build_install_plan("gau")
        apt_step = next(step for step in plan if step["manager"] == "apt")
        go_step = next(step for step in plan if step["manager"] == "go")
        assert apt_step["can_run_unattended"] is False
        assert apt_step["blocked_reason"] == "package not offered by this manager"
        assert go_step["can_run_unattended"] is True

    def test_windows_plan_has_no_apt_or_brew(self, monkeypatch):
        fake_platform(monkeypatch, "Windows", {"go"})
        monkeypatch.setattr(main, "_package_available", lambda manager, package: True)
        plan = main.build_install_plan("httpx", include_unavailable=True)
        managers = {step["manager"] for step in plan}
        assert "apt" not in managers and "brew" not in managers
        assert "go" in managers
        assert all(step["needs_root"] is False for step in plan)

    def test_httpx_never_installed_from_pip_or_apt(self):
        # The Python package named httpx is a different tool entirely.
        assert "pip" not in main.TOOL_PACKAGES["httpx"]
        assert "apt" not in main.TOOL_PACKAGES["httpx"]

    def test_crtsh_is_virtual(self, monkeypatch):
        fake_platform(monkeypatch, "Linux", {"apt-get"}, os_release={"ID": "debian"})
        assert main.build_install_plan("crtsh") == []
        assert main.ensure_tool_installed("crtsh") is True

    def test_every_tool_has_a_doc_link(self):
        for tool in main.TOOLS:
            assert main.TOOL_DOCS.get(tool), f"{tool} has no documentation link"


class TestInstructions:
    def test_instructions_name_the_detected_system(self, monkeypatch):
        fake_platform(monkeypatch, "Linux", {"pacman", "go"},
                      os_release={"ID": "arch", "PRETTY_NAME": "Arch Linux"})
        monkeypatch.setattr(main, "_package_available", lambda manager, package: True)
        text = main.get_tool_installation_instructions("nuclei")
        assert "Arch Linux" in text
        assert "pacman -S --noconfirm nuclei" in text
        assert "apt-get" not in text.split("Other options:")[0]

    def test_macos_instructions_do_not_lead_with_apt(self, monkeypatch):
        fake_platform(monkeypatch, "Darwin", {"brew"})
        monkeypatch.setattr(main, "_package_available", lambda manager, package: True)
        text = main.get_tool_installation_instructions("amass")
        assert "macOS" in text
        assert text.index("brew install amass") < text.index("Docs")
        assert "sudo apt-get" not in text

    def test_missing_go_is_called_out(self, monkeypatch):
        fake_platform(monkeypatch, "Windows", set())
        text = main.get_tool_installation_instructions("gau")
        assert "Go is not installed" in text
        assert "go.dev/dl" in text

    def test_virtual_tool_says_nothing_to_install(self, monkeypatch):
        fake_platform(monkeypatch, "Darwin", {"brew"})
        text = main.get_tool_installation_instructions("crtsh")
        assert "Nothing to install" in text


class TestUnattendedInstallSafety:
    def test_install_skipped_when_sudo_would_prompt(self, monkeypatch):
        fake_platform(monkeypatch, "Linux", {"apt-get", "sudo"},
                      os_release={"ID": "debian"}, sudo_ok=False)
        monkeypatch.setattr(main, "_package_available", lambda manager, package: True)
        monkeypatch.setattr(main, "_resolve_tool_path", lambda tool: None)
        ran = []
        monkeypatch.setattr(main, "_run_install_step", lambda tool, step: ran.append(step) or True)
        assert main.ensure_tool_installed("nikto") is False
        assert ran == []       # never shell out to a command that would block on a prompt

    def test_install_runs_and_reports_success(self, monkeypatch):
        fake_platform(monkeypatch, "Darwin", {"brew"})
        monkeypatch.setattr(main, "_package_available", lambda manager, package: True)
        calls = {"n": 0}

        def resolve(tool):
            calls["n"] += 1
            return "/opt/homebrew/bin/nuclei" if calls["n"] > 1 else None

        monkeypatch.setattr(main, "_resolve_tool_path", resolve)
        steps = []
        monkeypatch.setattr(main, "_run_install_step", lambda tool, step: steps.append(step["manager"]) or True)
        assert main.ensure_tool_installed("nuclei") is True
        assert steps == ["brew"]


class TestWindowsBinaryResolution:
    def test_exe_suffix_checked_in_go_bin(self, monkeypatch):
        monkeypatch.setattr(main, "_running_on_windows", lambda: True)
        monkeypatch.setattr(main.shutil, "which", lambda name: None)
        monkeypatch.setenv("GOBIN", r"C:\\gobin")
        candidates = main._candidate_tool_paths("nuclei")
        assert any(candidate.endswith("nuclei.exe") for candidate in candidates)

    def test_unix_checks_common_bin_dirs(self, monkeypatch):
        monkeypatch.setattr(main, "_running_on_windows", lambda: False)
        monkeypatch.setattr(main.shutil, "which", lambda name: None)
        candidates = main._candidate_tool_paths("nuclei")
        assert any(candidate.endswith("/go/bin/nuclei") for candidate in candidates)
        assert any("/.local/bin/nuclei" in candidate for candidate in candidates)


class TestJsFindingsSummary:
    def test_summarize_counts_and_types(self):
        summary = main.summarize_js_scan({
            "scanned_at": "2026-01-01T00:00:00Z",
            "summary": {"files": 3, "files_ok": 2, "secrets": 2, "endpoints": 4, "params": 5},
            "secrets": [
                {"type": "aws_key", "match": "AKIA***", "source": "https://a/app.js"},
                {"type": "aws_key", "match": "AKIA***", "source": "https://a/b.js"},
            ],
            "endpoints": ["/a", "/b", "/c", "/d"],
            "params": ["id", "q", "r", "s", "t"],
        })
        assert summary["summary"]["secrets"] == 2
        assert summary["secret_types"] == {"aws_key": 2}
        assert len(summary["top_secrets"]) == 2

    def test_summarize_handles_missing_scan(self):
        assert main.summarize_js_scan(None) is None
        assert main.summarize_js_scan("nonsense") is None

    def test_summarize_is_bounded(self):
        summary = main.summarize_js_scan(
            {"secrets": [{"type": "t", "match": "m", "source": "s"}] * 50}, max_secrets=5)
        assert len(summary["top_secrets"]) == 5
        assert summary["summary"]["secrets"] == 50


@pytest.fixture(scope="module")
def http_api():
    """Real server on a throwaway database, for the tools/JS endpoints."""
    tmpdir = Path(tempfile.mkdtemp(prefix="tooling-test-"))
    saved = {name: getattr(main, name) for name in
             ("DATA_DIR", "DB_FILE", "STATE_FILE", "LOCK_FILE", "CONFIG_FILE",
              "HISTORY_DIR", "SCREENSHOTS_DIR", "BACKUPS_DIR")}
    saved_conn = main.DB_CONN
    main.DATA_DIR = tmpdir
    main.DB_FILE = tmpdir / "recon.db"
    main.STATE_FILE = tmpdir / "state.json"
    main.LOCK_FILE = tmpdir / ".lock"
    main.CONFIG_FILE = tmpdir / "config.json"
    main.HISTORY_DIR = tmpdir / "history"
    main.SCREENSHOTS_DIR = tmpdir / "screenshots"
    main.BACKUPS_DIR = tmpdir / "backups"
    main.DB_CONN = None

    main.ensure_dirs()
    main.ensure_database()
    main.create_user("tooling-admin", "tooling-pass", True)
    session = main.create_session(main.authenticate_user("tooling-admin", "tooling-pass"))

    server = ThreadingHTTPServer(("127.0.0.1", 0), main.CommandCenterHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def call(method, path, body=None, authenticated=True):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if authenticated:
            req.add_header("Cookie", f"session_token={session}")
        try:
            with urllib.request.urlopen(req) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
        try:
            return status, json.loads(raw)
        except json.JSONDecodeError:
            return status, {"_body": raw.decode("utf-8", errors="replace")}

    yield call

    server.shutdown()
    try:
        main.DB_CONN.close()
    except Exception:
        pass
    for name, value in saved.items():
        setattr(main, name, value)
    main.DB_CONN = saved_conn
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture(scope="module")
def seeded_state(http_api):
    state = main.load_state()
    main.add_subdomains_to_state(state, "jsdemo.com", ["www.jsdemo.com"], "test")
    target = main.ensure_target_state(state, "jsdemo.com")
    target["endpoints"] = ["https://www.jsdemo.com/api/v1/me"]
    target["js_scan"] = {
        "scanned_at": "2026-01-01T00:00:00Z",
        "summary": {"files": 4, "files_ok": 4, "secrets": 2, "endpoints": 7, "params": 3},
        "secrets": [
            {"type": "aws_key", "match": "AKIA***", "source": "https://www.jsdemo.com/app.js"},
            {"type": "jwt", "match": "eyJ***", "source": "https://www.jsdemo.com/app.js"},
        ],
        "endpoints": ["/a"] * 7,
        "params": ["id", "next", "token"],
        "files": [],
    }
    main.save_state(state)
    return "jsdemo.com"


class TestToolingEndpoints:
    def test_tools_endpoint_reports_platform_and_plans(self, http_api):
        status, payload = http_api("GET", "/api/tools")
        assert status == 200
        assert payload["success"] is True
        assert payload["platform"]["system"] in ("macos", "linux", "windows")
        assert payload["total_count"] == len(main.TOOLS)
        crtsh = next(tool for tool in payload["tools"] if tool["tool"] == "crtsh")
        assert crtsh["installed"] is True and crtsh["virtual"] is True

    def test_missing_tool_carries_instructions(self, http_api, monkeypatch):
        monkeypatch.setattr(main, "_resolve_tool_path", lambda tool: None)
        status, payload = http_api("GET", "/api/tools")
        assert status == 200
        nuclei = next(tool for tool in payload["tools"] if tool["tool"] == "nuclei")
        assert nuclei["installed"] is False
        assert nuclei["instructions"]
        assert payload["platform"]["system_label"] in nuclei["instructions"]

    def test_install_rejects_unknown_tool(self, http_api):
        status, payload = http_api("POST", "/api/tools/install", {"tools": ["definitely-not-a-tool"]})
        assert status == 400
        assert "Unknown tool" in payload["message"]

    def test_install_accepts_known_tool(self, http_api, monkeypatch):
        installed = []
        monkeypatch.setattr(main, "ensure_tool_installed", lambda tool: installed.append(tool) or True)
        status, payload = http_api("POST", "/api/tools/install", {"tools": ["nuclei"]})
        assert status == 200
        assert payload["success"] is True
        assert payload["tools"] == ["nuclei"]

    def test_tools_endpoint_requires_login(self, http_api):
        # No session cookie: the login page comes back instead of tool data.
        status, payload = http_api("GET", "/api/tools", authenticated=False)
        assert "success" not in payload
        assert "Login" in payload.get("_body", "")


class TestJsOverviewEndpoints:
    def test_state_summary_includes_js_scan(self, http_api, seeded_state):
        status, payload = http_api("GET", "/api/state")
        assert status == 200
        target = payload["targets"][seeded_state]
        assert target["js_scan"]["summary"]["secrets"] == 2
        assert target["js_scan"]["secret_types"] == {"aws_key": 1, "jwt": 1}
        assert target["endpoint_count"] == 1
        # The heavy fields stay out of the summary payload.
        assert "secrets" not in target["js_scan"]

    def test_js_findings_endpoint_rolls_up(self, http_api, seeded_state):
        status, payload = http_api("GET", "/api/js-findings")
        assert status == 200
        assert payload["totals"]["secrets"] == 2
        assert payload["totals"]["endpoints"] == 7
        assert payload["targets"][0]["domain"] == seeded_state
        assert payload["secret_types"] == {"aws_key": 1, "jwt": 1}
        assert payload["secrets"][0]["match"] == "AKIA***"

    def test_js_findings_limit_is_bounded(self, http_api, seeded_state):
        status, payload = http_api("GET", "/api/js-findings?limit=1")
        assert status == 200
        assert len(payload["secrets"]) <= 1


class TestUiWiring:
    """The dashboard is one big HTML string; check the pieces are actually there."""

    def test_howto_nav_and_view_exist(self):
        assert 'data-view="howto" href="#howto">How to use this tool</a>' in main.INDEX_HTML
        assert '<section class="module" data-view="howto">' in main.INDEX_HTML

    def test_overview_has_js_findings(self):
        assert 'id="stat-js-secrets"' in main.INDEX_HTML
        assert 'id="stat-js-endpoints"' in main.INDEX_HTML
        assert 'id="overview-js-findings"' in main.INDEX_HTML
        assert 'renderJsFindingsOverview(data.targets || {})' in main.INDEX_HTML

    def test_howto_view_loads_tool_status(self):
        assert "loadHowtoTools" in main.INDEX_HTML
        assert "'/api/tools/install'" in main.INDEX_HTML


class TestBundledNucleiTemplates:
    """Templates shipped in nuclei-templates/ must run alongside the official set."""

    def test_templates_are_present_and_parse(self):
        templates = main.bundled_nuclei_templates()
        assert len(templates) >= 34
        for path in templates:
            text = path.read_text(encoding="utf-8")
            assert text.startswith("id: "), f"{path.name} has no id as first key"
            assert "info:" in text and "severity:" in text

    def test_template_ids_are_unique_and_match_filenames(self):
        seen = {}
        for path in main.bundled_nuclei_templates():
            first = path.read_text(encoding="utf-8").splitlines()[0]
            template_id = first.split("id:", 1)[1].strip()
            assert template_id == path.stem, f"{path.name} declares id {template_id}"
            assert template_id not in seen, f"duplicate template id {template_id}"
            seen[template_id] = path

    def test_default_and_bundled_dirs_are_both_passed(self, monkeypatch, tmp_path):
        default_dir = tmp_path / "nuclei-templates"
        default_dir.mkdir()
        monkeypatch.setattr(main, "nuclei_default_templates_dir", lambda: default_dir)
        args = main.nuclei_template_args({"use_bundled_nuclei_templates": True})
        assert args == ["-t", str(default_dir), "-t", str(main.BUNDLED_NUCLEI_TEMPLATES_DIR)]

    def test_no_narrowing_when_official_templates_missing(self, monkeypatch):
        # Passing only the bundled dir would shrink the scan to 34 templates.
        monkeypatch.setattr(main, "nuclei_default_templates_dir", lambda: None)
        assert main.nuclei_template_args({"use_bundled_nuclei_templates": True}) == []

    def test_toggle_disables_them(self, monkeypatch, tmp_path):
        monkeypatch.setattr(main, "nuclei_default_templates_dir", lambda: tmp_path)
        assert main.nuclei_template_args({"use_bundled_nuclei_templates": False}) == []

    def test_scan_command_includes_templates(self, monkeypatch, tmp_path):
        default_dir = tmp_path / "official"
        default_dir.mkdir()
        monkeypatch.setattr(main, "nuclei_default_templates_dir", lambda: default_dir)
        monkeypatch.setattr(main, "ensure_tool_installed", lambda tool: True)
        monkeypatch.setitem(main.TOOLS, "nuclei", "/usr/bin/nuclei")
        captured = {}

        def fake_run(cmd, outfile=None, job_domain=None, step=None, **kwargs):
            captured["cmd"] = cmd
            return False

        monkeypatch.setattr(main, "run_subprocess", fake_run)
        main.nuclei_scan(tmp_path / "subs.txt", "example.com",
                         config={"use_bundled_nuclei_templates": True})
        assert captured["cmd"].count("-t") == 2
        assert str(main.BUNDLED_NUCLEI_TEMPLATES_DIR) in captured["cmd"]

    def test_settings_toggle_in_ui(self):
        assert 'id="settings-bundled-nuclei-templates"' in main.INDEX_HTML
        assert "use_bundled_nuclei_templates" in main.INDEX_HTML
