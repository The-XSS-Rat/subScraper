#!/usr/bin/env python3
"""
Tests for the bug bounty agent API (/api/agent/*).

Covers scoped API keys, program CRUD, scope evaluation, investigation dispatch,
and the asset/finding/surface read models. Runs against a real HTTP server bound
to a throwaway SQLite database.
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

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from unittest.mock import patch  # noqa: E402

with patch('main.ensure_dirs'), \
     patch('main.init_database'), \
     patch('main.migrate_json_to_sqlite'):
    import main  # noqa: E402


@pytest.fixture(scope="module")
def api():
    """Spin up the HTTP server against an isolated data directory."""
    tmpdir = Path(tempfile.mkdtemp(prefix="agent-api-test-"))
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
    main.create_user("apitest-admin", "apitest-pass", True)

    server = ThreadingHTTPServer(("127.0.0.1", 0), main.CommandCenterHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    session = main.create_session(main.authenticate_user("apitest-admin", "apitest-pass"))

    def call(method, path, body=None, key=None, cookie=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if key:
            req.add_header("Authorization", f"Bearer {key}")
        if cookie:
            req.add_header("Cookie", f"session_token={cookie}")
        try:
            with urllib.request.urlopen(req) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
        try:
            return status, json.loads(raw)
        except json.JSONDecodeError:
            return status, {}

    client = type("Client", (), {"call": staticmethod(call), "session": session})

    yield client

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
def keys(api):
    """Create the API keys used across the tests."""
    _, full = api.call("POST", "/api/agent/keys", {
        "name": "full-agent",
        "scopes": ["programs:read", "programs:write", "scan:run", "assets:read", "findings:read"],
    }, cookie=api.session)
    _, readonly = api.call("POST", "/api/agent/keys",
                           {"name": "read-only", "scopes": ["programs:read", "assets:read"]},
                           cookie=api.session)
    return {"full": full["key"], "readonly": readonly["key"]}


@pytest.fixture(scope="module")
def program(api, keys):
    """A program with a realistic mixed scope, plus seeded recon results."""
    api.call("POST", "/api/agent/programs", {
        "id": "testcorp",
        "name": "TestCorp BBP",
        "platform": "hackerone",
        "in_scope": ["*.testcorp.com", "https://api.testcorp-labs.com/graphql"],
        "out_of_scope": ["*.internal.testcorp.com", "blog.testcorp.com"],
    }, key=keys["full"]["api_key"])

    state = main.load_state()
    main.add_subdomains_to_state(state, "testcorp.com",
                                 ["www.testcorp.com", "admin.testcorp.com", "blog.testcorp.com",
                                  "dev.testcorp.com", "vpn.internal.testcorp.com"], "test")
    target = main.ensure_target_state(state, "testcorp.com")
    subs = target["subdomains"]
    subs["admin.testcorp.com"]["httpx"] = {"url": "https://admin.testcorp.com", "status_code": 403,
                                           "title": "Admin Login", "webserver": "nginx",
                                           "tech": ["Jenkins"], "content_length": 120}
    subs["admin.testcorp.com"]["nuclei"] = [{"template_id": "jenkins-panel", "name": "Jenkins Panel",
                                             "severity": "high", "matched_at": "https://admin.testcorp.com"}]
    subs["www.testcorp.com"]["httpx"] = {"url": "https://www.testcorp.com", "status_code": 200,
                                         "title": "Home", "tech": []}
    subs["blog.testcorp.com"]["nuclei"] = [{"template_id": "x", "name": "Out of scope finding",
                                            "severity": "critical", "matched_at": "https://blog.testcorp.com"}]
    subs["dev.testcorp.com"]["nikto"] = [{"host": "dev.testcorp.com", "msg": "Directory indexing found",
                                          "severity": "low", "uri": "https://dev.testcorp.com/files/"}]
    target["endpoints"] = ["https://www.testcorp.com/api/v1/users?id=1",
                           "https://www.testcorp.com/static/app.js"]
    target["js_scan"] = {"secrets": [{"type": "aws_key", "match": "AKIA***",
                                      "source": "https://www.testcorp.com/static/app.js"}],
                         "params": ["id", "redirect"], "endpoints": [], "files": [], "summary": {}}
    main.save_state(state)
    return "testcorp"


class TestAgentAuth:
    """Authentication and scope enforcement."""

    def test_index_is_public(self, api):
        status, payload = api.call("GET", "/api/agent")
        assert status == 200
        assert "GET /api/agent/whoami" in payload["endpoints"]

    def test_missing_key_is_unauthorized(self, api):
        status, payload = api.call("GET", "/api/agent/programs")
        assert status == 401
        assert payload["error"] == "unauthorized"

    def test_bogus_key_is_unauthorized(self, api):
        status, _ = api.call("GET", "/api/agent/programs", key="rcc_dead_beef")
        assert status == 401

    def test_whoami_reports_scopes(self, api, keys):
        status, payload = api.call("GET", "/api/agent/whoami", key=keys["full"]["api_key"])
        assert status == 200
        assert payload["principal"]["type"] == "api_key"
        assert "scan:run" in payload["principal"]["scopes"]

    def test_session_acts_as_principal(self, api):
        status, payload = api.call("GET", "/api/agent/whoami", cookie=api.session)
        assert status == 200
        assert payload["principal"]["type"] == "session"

    def test_missing_scope_is_forbidden(self, api, keys):
        status, payload = api.call("GET", "/api/agent/keys", key=keys["readonly"]["api_key"])
        assert status == 403
        assert payload["error"] == "insufficient_scope"
        assert payload["required_scope"] == "keys:manage"


class TestApiKeyManagement:
    """Creating, restricting and revoking scoped keys."""

    def test_unknown_scope_rejected(self, api):
        status, payload = api.call("POST", "/api/agent/keys",
                                   {"name": "bad", "scopes": ["not-a-scope"]}, cookie=api.session)
        assert status == 400
        assert "Unknown scope" in payload["message"]

    def test_no_scope_rejected(self, api):
        status, _ = api.call("POST", "/api/agent/keys", {"name": "bad", "scopes": []},
                             cookie=api.session)
        assert status == 400

    def test_wildcard_scope_expands(self, api):
        status, payload = api.call("POST", "/api/agent/keys",
                                   {"name": "wildcard", "scopes": "*", "expires_days": 30},
                                   cookie=api.session)
        assert status == 201
        assert set(payload["key"]["scopes"]) == set(main.AGENT_API_SCOPES)
        assert payload["key"]["expires_at"]

    def test_secret_is_not_stored_in_plaintext(self, api):
        _, created = api.call("POST", "/api/agent/keys",
                              {"name": "storage-check", "scopes": ["programs:read"]},
                              cookie=api.session)
        raw = created["key"]["api_key"]
        cursor = main.get_db().cursor()
        cursor.execute("SELECT key_hash FROM agent_api_keys WHERE key_id = ?",
                       (created["key"]["key_id"],))
        stored = cursor.fetchone()["key_hash"]
        assert raw.split("_", 2)[2] not in stored
        assert main.validate_agent_api_key(raw) is not None

    def test_list_never_returns_secrets(self, api):
        status, payload = api.call("GET", "/api/agent/keys", cookie=api.session)
        assert status == 200
        assert all("api_key" not in key and "key_hash" not in key for key in payload["keys"])

    def test_revoked_key_stops_working(self, api):
        _, created = api.call("POST", "/api/agent/keys",
                              {"name": "temp", "scopes": ["programs:read"]}, cookie=api.session)
        raw = created["key"]["api_key"]
        assert api.call("GET", "/api/agent/programs", key=raw)[0] == 200
        assert api.call("POST", "/api/agent/keys/revoke",
                        {"key_id": created["key"]["key_id"]}, cookie=api.session)[0] == 200
        assert api.call("GET", "/api/agent/programs", key=raw)[0] == 401

    def test_delete_key(self, api):
        _, created = api.call("POST", "/api/agent/keys",
                              {"name": "doomed", "scopes": ["programs:read"]}, cookie=api.session)
        key_id = created["key"]["key_id"]
        assert api.call("POST", "/api/agent/keys/delete", {"key_id": key_id}, cookie=api.session)[0] == 200
        assert api.call("POST", "/api/agent/keys/delete", {"key_id": key_id}, cookie=api.session)[0] == 400

    def test_key_restricted_to_program(self, api, keys, program):
        api.call("POST", "/api/agent/programs", {"id": "othercorp", "name": "Other",
                                                 "in_scope": ["othercorp.com"]},
                 key=keys["full"]["api_key"])
        _, scoped = api.call("POST", "/api/agent/keys",
                             {"name": "one-program", "scopes": ["programs:read"],
                              "programs": [program]}, cookie=api.session)
        raw = scoped["key"]["api_key"]
        assert api.call("GET", f"/api/agent/programs/{program}", key=raw)[0] == 200
        status, payload = api.call("GET", "/api/agent/programs/othercorp", key=raw)
        assert status == 403
        assert payload["error"] == "program_forbidden"
        _, listed = api.call("GET", "/api/agent/programs", key=raw)
        assert [item["id"] for item in listed["programs"]] == [program]

    def test_key_restricted_to_unknown_program_rejected(self, api):
        status, _ = api.call("POST", "/api/agent/keys",
                             {"name": "ghost", "scopes": ["programs:read"], "programs": ["ghost"]},
                             cookie=api.session)
        assert status == 400


class TestScopeEvaluation:
    """Wildcards, out-of-scope precedence and suffix confusion."""

    @pytest.mark.parametrize("asset,expected", [
        ("testcorp.com", True),               # wildcard covers the apex
        ("www.testcorp.com", True),
        ("blog.testcorp.com", False),         # explicit exclusion
        ("vpn.internal.testcorp.com", False),  # wildcard exclusion
        ("https://api.testcorp-labs.com/graphql", True),
        ("evil.com", False),
        ("testcorp.com.evil.com", False),     # suffix confusion
    ])
    def test_program_scope_check(self, api, keys, program, asset, expected):
        status, payload = api.call("POST", f"/api/agent/programs/{program}/scope/check",
                                   {"assets": [asset]}, key=keys["full"]["api_key"])
        assert status == 200
        assert payload["results"][0]["in_scope"] is expected
        assert payload["results"][0]["reason"]

    def test_adhoc_scope_check(self, api, keys):
        status, payload = api.call("POST", "/api/agent/scope/check", {
            "in_scope": ["*.foo.com"], "out_of_scope": ["dev.foo.com"],
            "assets": ["a.foo.com", "dev.foo.com", "foo.com.attacker.net"],
        }, key=keys["full"]["api_key"])
        assert status == 200
        assert [r["in_scope"] for r in payload["results"]] == [True, False, False]

    def test_scope_check_requires_assets(self, api, keys, program):
        status, payload = api.call("POST", f"/api/agent/programs/{program}/scope/check", {},
                                   key=keys["full"]["api_key"])
        assert status == 400
        assert payload["error"] == "missing_assets"

    def test_root_targets_exclude_wildcards_and_exclusions(self, api, keys, program):
        status, payload = api.call("GET", f"/api/agent/programs/{program}/scope",
                                   key=keys["full"]["api_key"])
        assert status == 200
        assert set(payload["root_targets"]) == {"testcorp.com", "api.testcorp-labs.com"}


class TestProgramCrud:
    def test_program_requires_scope(self, api, keys):
        status, _ = api.call("POST", "/api/agent/programs", {"name": "No Scope"},
                             key=keys["full"]["api_key"])
        assert status == 400

    def test_duplicate_id_rejected(self, api, keys, program):
        status, _ = api.call("POST", "/api/agent/programs",
                             {"id": program, "name": "dupe", "in_scope": ["x.com"]},
                             key=keys["full"]["api_key"])
        assert status == 400

    def test_unknown_program_is_404(self, api, keys):
        status, _ = api.call("GET", "/api/agent/programs/does-not-exist", key=keys["full"]["api_key"])
        assert status == 404

    def test_update_requires_write_scope(self, api, keys, program):
        status, _ = api.call("POST", f"/api/agent/programs/{program}", {"notes": "nope"},
                             key=keys["readonly"]["api_key"])
        assert status == 403

    def test_partial_update(self, api, keys, program):
        status, payload = api.call("POST", f"/api/agent/programs/{program}",
                                   {"notes": "No DoS."}, key=keys["full"]["api_key"])
        assert status == 200
        assert payload["program"]["notes"] == "No DoS."
        assert payload["program"]["name"] == "TestCorp BBP"  # untouched

    def test_delete_program(self, api, keys):
        api.call("POST", "/api/agent/programs", {"id": "temp-prog", "name": "Temp",
                                                 "in_scope": ["temp.com"]}, key=keys["full"]["api_key"])
        assert api.call("POST", "/api/agent/programs/temp-prog/delete", {},
                        key=keys["full"]["api_key"])[0] == 200
        assert api.call("GET", "/api/agent/programs/temp-prog", key=keys["full"]["api_key"])[0] == 404

    def test_unknown_route_is_404(self, api, keys, program):
        assert api.call("GET", "/api/agent/bogus", key=keys["full"]["api_key"])[0] == 404
        assert api.call("POST", f"/api/agent/programs/{program}/bogus", {},
                        key=keys["full"]["api_key"])[0] == 404


class TestAssetsAndFindings:
    def test_assets_hide_out_of_scope_hosts(self, api, keys, program):
        status, payload = api.call("GET", f"/api/agent/programs/{program}/assets?per_page=50",
                                   key=keys["full"]["api_key"])
        assert status == 200
        hosts = {asset["host"] for asset in payload["assets"]}
        assert {"www.testcorp.com", "admin.testcorp.com", "dev.testcorp.com"} <= hosts
        assert "blog.testcorp.com" not in hosts
        assert "vpn.internal.testcorp.com" not in hosts

    def test_include_out_of_scope_opt_in(self, api, keys, program):
        _, payload = api.call("GET", f"/api/agent/programs/{program}/assets?include_out_of_scope=true",
                              key=keys["full"]["api_key"])
        blog = next(a for a in payload["assets"] if a["host"] == "blog.testcorp.com")
        assert blog["in_scope"] is False

    def test_live_only_filter(self, api, keys, program):
        _, payload = api.call("GET", f"/api/agent/programs/{program}/assets?live_only=true",
                              key=keys["full"]["api_key"])
        assert payload["assets"] and all(asset["live"] for asset in payload["assets"])

    def test_pagination(self, api, keys, program):
        _, payload = api.call("GET", f"/api/agent/programs/{program}/assets?per_page=1&page=2",
                              key=keys["full"]["api_key"])
        assert payload["pagination"]["per_page"] == 1
        assert payload["pagination"]["page"] == 2
        assert len(payload["assets"]) == 1

    def test_findings_normalized_across_tools(self, api, keys, program):
        status, payload = api.call("GET", f"/api/agent/programs/{program}/findings",
                                   key=keys["full"]["api_key"])
        assert status == 200
        assert {f["source"] for f in payload["findings"]} == {"nuclei", "nikto", "js_secret"}
        assert payload["findings"][0]["severity"] == "high"  # sorted worst-first
        assert all(f["host"] != "blog.testcorp.com" for f in payload["findings"])

    def test_findings_severity_filter(self, api, keys, program):
        _, payload = api.call("GET", f"/api/agent/programs/{program}/findings?severity=high",
                              key=keys["full"]["api_key"])
        assert [f["severity"] for f in payload["findings"]] == ["high"]

    def test_findings_require_findings_scope(self, api, keys, program):
        status, _ = api.call("GET", f"/api/agent/programs/{program}/findings",
                             key=keys["readonly"]["api_key"])
        assert status == 403

    def test_endpoints_and_params(self, api, keys, program):
        _, payload = api.call("GET", f"/api/agent/programs/{program}/endpoints?search=api",
                              key=keys["full"]["api_key"])
        assert [e["url"] for e in payload["endpoints"]] == ["https://www.testcorp.com/api/v1/users?id=1"]
        assert "id" in payload["params"]

    def test_surface_ranks_with_reasons(self, api, keys, program):
        status, payload = api.call("GET", f"/api/agent/programs/{program}/surface?limit=10",
                                   key=keys["full"]["api_key"])
        assert status == 200
        top = payload["surface"][0]
        assert top["host"] == "admin.testcorp.com"
        assert top["score"] > 0
        assert any("auth-gated" in reason for reason in top["reasons"])


class TestInvestigation:
    def test_status_reports_coverage(self, api, keys, program):
        status, payload = api.call("GET", f"/api/agent/programs/{program}/status",
                                   key=keys["full"]["api_key"])
        assert status == 200
        assert payload["totals"]["subdomains"] == 5
        assert payload["severity_totals"]["high"] == 1
        assert {t["target"] for t in payload["targets"]} == {"testcorp.com", "api.testcorp-labs.com"}

    def test_investigate_requires_scan_scope(self, api, keys, program):
        status, _ = api.call("POST", f"/api/agent/programs/{program}/investigate", {},
                             key=keys["readonly"]["api_key"])
        assert status == 403

    def test_out_of_scope_targets_refused(self, api, keys, program):
        status, payload = api.call("POST", f"/api/agent/programs/{program}/investigate",
                                   {"targets": ["blog.testcorp.com", "vpn.internal.testcorp.com"]},
                                   key=keys["full"]["api_key"])
        assert status == 400
        assert len(payload["refused"]) == 2
        assert not payload["dispatched"]

    def test_investigate_dispatches_in_scope_target(self, api, keys, program, monkeypatch):
        dispatched = []
        monkeypatch.setattr(main, "start_pipeline_job",
                            lambda domain, wordlist, skip_nikto, interval:
                            (dispatched.append(domain) or (True, f"Recon started for {domain}.")))
        status, payload = api.call("POST", f"/api/agent/programs/{program}/investigate",
                                   {"targets": ["www.testcorp.com"], "skip_nikto": True},
                                   key=keys["full"]["api_key"])
        assert status == 202
        assert dispatched == ["www.testcorp.com"]
        assert payload["dispatched"][0]["success"] is True

    def test_investigate_whole_scope(self, api, keys, program, monkeypatch):
        dispatched = []
        monkeypatch.setattr(main, "start_pipeline_job",
                            lambda domain, wordlist, skip_nikto, interval:
                            (dispatched.append(domain) or (True, "started")))
        status, _ = api.call("POST", f"/api/agent/programs/{program}/investigate", {},
                             key=keys["full"]["api_key"])
        assert status == 202
        assert set(dispatched) == {"testcorp.com", "api.testcorp-labs.com"}


class TestStatePersistence:
    """targets.data must survive the save/load round-trip."""

    def test_endpoints_and_js_scan_persist(self, api, program):
        state = main.load_state()
        target = state["targets"]["testcorp.com"]
        assert target["endpoints"]
        assert target["js_scan"]["secrets"]
        main.save_state(state)
        reloaded = main.load_state()["targets"]["testcorp.com"]
        assert reloaded["endpoints"] == target["endpoints"]
        assert reloaded["js_scan"]["secrets"] == target["js_scan"]["secrets"]


class TestProgramIdValidation:
    """Program ids end up in URLs, so they are constrained."""

    @pytest.mark.parametrize("bad_id", ["../etc", "has space", "-leading", "a/b"])
    def test_invalid_id_rejected(self, api, keys, bad_id):
        status, payload = api.call("POST", "/api/agent/programs",
                                   {"id": bad_id, "name": "Bad", "in_scope": ["bad.com"]},
                                   key=keys["full"]["api_key"])
        assert status == 400
        assert "Program id" in payload["message"]

    def test_id_derived_from_name_when_omitted(self, api, keys):
        status, payload = api.call("POST", "/api/agent/programs",
                                   {"name": "Derived Name Co", "in_scope": ["derived.com"]},
                                   key=keys["full"]["api_key"])
        assert status == 201
        assert payload["program"]["id"] == "derived-name-co"
        api.call("POST", "/api/agent/programs/derived-name-co/delete", {}, key=keys["full"]["api_key"])
