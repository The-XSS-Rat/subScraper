# Bug Bounty Agent API

A machine-facing API that lets an autonomous agent load the **full scope of a bug bounty
program**, launch recon over that scope, and read back assets, findings and a ranked
attack surface — all gated by **scoped API keys**.

Base path: `/api/agent`. Everything speaks JSON.

---

## 1. Authentication

Two ways to authenticate:

| Caller | How |
|---|---|
| Agent / script | `Authorization: Bearer <api_key>` or `X-API-Key: <api_key>` |
| Browser / UI user | Existing `session_token` cookie |

A UI session gets `programs:read`, `programs:write`, `scan:run`, `assets:read`,
`findings:read`. Admin sessions additionally get `keys:manage`.

Failures are explicit:

* `401 unauthorized` – no/invalid/revoked/expired key
* `403 insufficient_scope` – valid key, missing scope (response lists required + granted scopes)
* `403 program_forbidden` – key is restricted to other programs

### Scopes

| Scope | Grants |
|---|---|
| `programs:read` | List/read programs, resolve scope, check assets against scope |
| `programs:write` | Create, update, delete programs |
| `scan:run` | Dispatch recon jobs for a program |
| `assets:read` | Read discovered hosts and endpoints |
| `findings:read` | Read findings and the ranked attack surface |
| `keys:manage` | Create, list, revoke, delete API keys |

`"scopes": "*"` expands to every scope at creation time.

### Key storage

Keys look like `rcc_<key_id>_<secret>`. Only a SHA-256 digest of the secret half is
stored (`agent_api_keys.key_hash`); the plaintext key is returned **once**, at creation.
Comparison is constant-time. Keys optionally carry an expiry (`expires_days`) and a
program allow-list.

### Managing keys

```bash
# Create a key (admin session or a key with keys:manage)
curl -s -X POST localhost:8000/api/agent/keys \
  -H 'Content-Type: application/json' \
  -b 'session_token=<session>' \
  -d '{
        "name": "hunter-agent",
        "scopes": ["programs:read", "scan:run", "assets:read", "findings:read"],
        "programs": ["acme"],       // optional: restrict to these program ids
        "expires_days": 30          // optional
      }'
# => {"success":true,"key":{"key_id":"...","api_key":"rcc_...","scopes":[...]}}

curl -s localhost:8000/api/agent/keys -b 'session_token=<session>'                      # list (no secrets)
curl -s -X POST localhost:8000/api/agent/keys/revoke -d '{"key_id":"..."}' -b '...'     # revoke
curl -s -X POST localhost:8000/api/agent/keys/delete -d '{"key_id":"..."}' -b '...'     # delete
```

`GET /api/agent/whoami` returns the resolved principal, its scopes and program
restrictions — the first call an agent should make.

---

## 2. Scope model

A program holds two lists. Entries may be bare domains, wildcards or URLs:

```json
{
  "in_scope":     ["*.acme.com", "https://api.acme-labs.com/graphql", "shop.acme.io"],
  "out_of_scope": ["*.internal.acme.com", "blog.acme.com"]
}
```

Matching rules:

* `*.acme.com` matches `acme.com` **and** every subdomain (the usual bug bounty reading).
* Other `*` placements are glob-matched (`acme-*.com`).
* URLs are reduced to their host for matching.
* **Out-of-scope always wins.** Excluded hosts are never scanned, never returned as
  assets, and their findings are suppressed unless you explicitly pass
  `include_out_of_scope=true`.

Root targets for enumeration are derived by stripping `*.` from in-scope entries and
dropping anything the out-of-scope list excludes.

---

## 3. Endpoints

### Index

```
GET /api/agent            # endpoint index + scope list (no auth required)
GET /api/agent/whoami     # identity, scopes, program restrictions
```

### Programs

```
GET  /api/agent/programs                  programs:read    list (filtered by key restrictions)
POST /api/agent/programs                  programs:write   create
GET  /api/agent/programs/{id}             programs:read    detail + derived root targets
POST /api/agent/programs/{id}             programs:write   partial update
POST /api/agent/programs/{id}/delete      programs:write   delete (recon data is kept)
GET  /api/agent/programs/{id}/scope       programs:read    resolved scope + root targets
```

Create a program from a full scope:

```bash
curl -s -X POST localhost:8000/api/agent/programs \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{
        "id": "acme",
        "name": "Acme Corp BBP",
        "platform": "hackerone",
        "handle": "acme",
        "in_scope": ["*.acme.com", "https://api.acme-labs.com/graphql"],
        "out_of_scope": ["*.internal.acme.com", "blog.acme.com"],
        "notes": "No DoS, no social engineering."
      }'
```

### Investigate

```
POST /api/agent/programs/{id}/investigate     scan:run
```

Runs the full pipeline (subdomain enum → dnsx/httpx → ffuf → screenshots → nuclei →
JS scan → nikto) for every in-scope root. Returns `202` with per-target dispatch results.

```json
{"targets": ["acme.com"], "skip_nikto": true, "wordlist": "/path/wl.txt", "interval": 600}
```

* `targets` is optional — omit it to investigate the whole scope.
* Targets outside the scope are **refused, not dropped**: they come back under
  `refused` with the reason, so the agent learns why.

### Read results

```
GET /api/agent/programs/{id}/status        programs:read   per-target pipeline progress + coverage totals
GET /api/agent/programs/{id}/assets        assets:read     discovered hosts
GET /api/agent/programs/{id}/endpoints     assets:read     archived + JS-discovered URLs, JS params
GET /api/agent/programs/{id}/findings      findings:read   normalized nuclei + nikto + JS secrets
GET /api/agent/programs/{id}/surface       findings:read   ranked attack surface with reasons
```

Query parameters:

| Endpoint | Parameters |
|---|---|
| `assets` | `live_only`, `interesting_only`, `with_findings`, `status_code`, `search`, `include_out_of_scope`, `page`, `per_page` |
| `findings` | `severity` (csv), `source` (`nuclei,nikto,js_secret`), `host`, `include_out_of_scope`, `page`, `per_page` |
| `endpoints` | `search`, `page`, `per_page` |
| `surface` | `limit` |

`surface` scores each in-scope host and returns *why*: auth-gated status codes, finding
severity, hostname keywords (`admin`, `staging`, `jenkins`, `graphql`, …), interesting
tech fingerprints, suggestive titles, and manual "interesting" marks.

```json
{
  "host": "admin.acme.com",
  "score": 63,
  "status_code": 403,
  "reasons": ["live host", "auth-gated (403)", "1 high finding(s)",
              "hostname keywords: admin", "tech: jenkins", "interesting title"]
}
```

### Scope checking

```
POST /api/agent/programs/{id}/scope/check   programs:read   check assets against a program
POST /api/agent/scope/check                 programs:read   check assets against an ad-hoc scope
```

```bash
curl -s -X POST localhost:8000/api/agent/programs/acme/scope/check \
  -H "Authorization: Bearer $KEY" \
  -d '{"assets": ["www.acme.com", "blog.acme.com", "shop.acme.io.evil.com"]}'
```

Each result carries `in_scope`, the rule that `matched`, and a human `reason` — this is
the call an agent should make before touching anything it discovered elsewhere.

---

## 4. Typical agent loop

```bash
KEY=rcc_...

curl -s -H "Authorization: Bearer $KEY" localhost:8000/api/agent/whoami
curl -s -X POST -H "Authorization: Bearer $KEY" localhost:8000/api/agent/programs \
     -d '{"id":"acme","name":"Acme","in_scope":["*.acme.com"],"out_of_scope":["blog.acme.com"]}'
curl -s -X POST -H "Authorization: Bearer $KEY" localhost:8000/api/agent/programs/acme/investigate -d '{}'

# poll until investigation_state != "running"
curl -s -H "Authorization: Bearer $KEY" localhost:8000/api/agent/programs/acme/status

curl -s -H "Authorization: Bearer $KEY" 'localhost:8000/api/agent/programs/acme/surface?limit=25'
curl -s -H "Authorization: Bearer $KEY" 'localhost:8000/api/agent/programs/acme/findings?severity=critical,high'
curl -s -H "Authorization: Bearer $KEY" 'localhost:8000/api/agent/programs/acme/endpoints?search=api'
```

---

## 5. Storage

Two tables, created automatically on startup:

* `agent_api_keys` — `key_id`, `name`, `key_hash`, `scopes`, `programs`, `created_by`,
  `created_at`, `expires_at`, `last_used_at`, `revoked`
* `programs` — `id`, `name`, `platform`, `data` (scope + metadata), timestamps

Recon results are read from the existing target state, so programs are a view over the
same data the dashboard shows. Deleting a program leaves its recon data intact.
