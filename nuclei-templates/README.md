# Nuclei templates for CVEs missing from the official repo

34 hand-authored Nuclei templates for high/critical CVEs that (as of 2026-07-14) have **no template in the official `projectdiscovery/nuclei-templates` repository**. Every candidate was cross-checked against a fresh clone of that repo (4,259 existing CVE templates) to confirm it is genuinely missing, and every field (slug, path, fixed version, matcher) was verified against an authoritative source (NVD, vendor advisory, Wordfence, Patchstack, WPScan, GHSA).

All templates pass `nuclei -validate` (engine v3.11.0). The version-detection and extraction logic was unit-tested to confirm vulnerable versions match and patched versions do **not** (no false positives).

## Design principles

- **Safe by default.** No template sends a destructive or memory-corrupting payload. Detection uses unauthenticated version disclosure, benign exposure probes, or product fingerprinting.
- **Honest severity.** Templates that can programmatically distinguish vulnerable from patched carry the CVE severity. Templates that can only confirm *presence/exposure* (where the version/patch level can't be read remotely) are marked `info` and clearly say "verify manually" — flagging attack surface without over-claiming.

## `webapps/` — self-hosted apps & appliances (version-detection & exposure)

| CVE | Product | Method | Severity |
|-----|---------|--------|----------|
| CVE-2025-6000 | HashiCorp Vault < 1.20.1 | `/v1/sys/seal-status` JSON version | critical* |
| CVE-2026-35031 | Jellyfin < 10.11.7 | `/System/Info/Public` JSON version | critical* |
| CVE-2024-42327 | Zabbix < 6.0.32/6.4.17/7.0.1 | unauth `apiinfo.version` JSON-RPC | critical |
| CVE-2024-31989 | Argo CD < 2.8.19/2.9.15/2.10.10 | `/api/version` JSON version | critical* |
| CVE-2024-37285 | Kibana < 7.17.23/8.14.2 | `/api/status` version.number | critical* |
| CVE-2024-32019 | Netdata 1.45.0–1.45.2 | `/api/v1/info` JSON version | high* |
| CVE-2025-46619 | Couchbase Server (Windows) | `/pools` implementationVersion | high* |
| CVE-2025-24364 | Vaultwarden < 1.33.0 | `/api/config` server.version | high* |
| CVE-2024-22278 | Harbor < 2.9.5/2.10.3 | `/api/v2.0/systeminfo` harbor_version | high* |
| CVE-2024-45410 | Traefik < 2.11.9/3.1.3 | `/api/version` (API-exposed) | critical* |
| CVE-2024-58259 | Rancher | `/v3-public/authProviders` fingerprint | info |
| CVE-2025-48927 | TeleMessage / Spring Boot | exposed `/heapdump` (capped read) | high |
| CVE-2025-27364 | MITRE Caldera | benign `/file/download` ELF probe | high |
| CVE-2025-53690 | Sitecore XM/XP | `/sitecore/blocked.aspx` ViewState fingerprint | info |

\* version-gated; exploitation requires additional preconditions noted in each template (privileged account, in-cluster access, admin panel, etc.).

## `appliances/` — network appliance fingerprint / surface detection

| CVE | Product | Method | Severity |
|-----|---------|--------|----------|
| CVE-2025-20333 | Cisco ASA/FTD WebVPN | config-auth version disclosure | info |
| CVE-2025-20337 | Cisco ISE 3.3/3.4 | admin portal fingerprint | info |

## `wordpress/` — plugin readme.txt version detection (unauthenticated, passive)

| CVE | Plugin (slug) | Fixed | Severity |
|-----|---------------|-------|----------|
| CVE-2024-28890 | Forminator (`forminator`) | 1.29.0 | critical |
| CVE-2024-4345 | Startklar Elementor Addons (`startklar-elmentor-forms-extwidgets`) | 1.7.14 | critical |
| CVE-2025-1128 | Everest Forms (`everest-forms`) | 3.0.9.5 | critical |
| CVE-2024-6328 | MStore API (`mstore-api`) | 4.15.0 | critical |
| CVE-2024-5450 | Bug Library (`bug-library`) | 2.1.1 | critical |
| CVE-2025-48274 | WP Job Portal (`wp-job-portal`) | 2.3.3 | critical |
| CVE-2024-10508 | RegistrationMagic (`custom-registration-form-builder-with-submission-manager`) | 6.0.2.7 | critical |
| CVE-2025-24000 | Post SMTP (`post-smtp`) | 3.3.0 | high |
| CVE-2025-6691 | SureForms (`sureforms`) | 1.7.4 | high |
| CVE-2024-11816 | WP Extended (`wpextended`) | 3.0.12 | high |
| CVE-2024-32830 | BuddyForms (`buddyforms`) | 2.8.9 | high |
| CVE-2023-2276 | WCFM Membership (`wc-multivendor-membership`) | 2.11.0 | critical |
| CVE-2024-11721 | Frontend Admin by DynamiApps (`acf-frontend-form-element`) | 3.24.6 | critical |
| CVE-2024-9636 | Post Grid (`post-grid`) | 2.3.4 | high |
| CVE-2024-5441 | Modern Events Calendar (`modern-events-calendar-lite`) | 7.12.0 | high |
| CVE-2024-8275 | The Events Calendar (`the-events-calendar`) | 6.6.4.1 | high |
| CVE-2024-1207 | Booking Calendar (`booking`) | 9.9.1 † | critical |
| CVE-2024-25918 | InstaWP Connect (`instawp-connect`) | 0.1.0.9 | high |

† Booking Calendar fixed version is the logical next release after the confirmed affected build; verify against the plugin changelog.

## Usage

```bash
# validate
nuclei -validate -t "Nuclei template/"

# run the whole set
nuclei -t "Nuclei template/" -u https://target

# run just the WordPress checks against a list
nuclei -t "Nuclei template/wordpress/" -l wp-hosts.txt
```

## Notes & caveats

- WordPress readme detection reads `Stable tag:` from the public `readme.txt`; it flags the *installed* plugin version. Sites that hide/remove readme.txt won't be detected (safe miss).
- The two commercial WP plugins with real high/critical CVEs (WPML, Jupiter X Core) were intentionally excluded — no reliable unauthenticated version source over HTTP.
- `info`-severity templates identify a potentially-vulnerable instance whose patch level must be confirmed manually (the product doesn't disclose it pre-auth).
- Several unauth "version endpoint" checks (Kibana `/api/status`, Traefik `/api/version`, Vault, Netdata) depend on the endpoint being reachable/anonymous; hardened deployments that require auth will simply not match (safe miss).
- Authored for authorized security testing only. Use exclusively against systems you are permitted to test.
