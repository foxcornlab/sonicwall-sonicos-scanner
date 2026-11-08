# `sonicwall-sonicos-scanner`

Local triage for `CVE-2026-19868`, the `SonicWall SonicOS SSLVPN` authentication flaw that lets a user with valid credentials for an alternate login method skip `SAML` authentication, and with it `SAML`-enforced `MFA`. Give it a firewall generation and a firmware build you own, and it tells you whether that firewall is still open. It never touches the network, never probes a firewall, never attempts a login.

## `The flaw`

The bug is an authentication-enforcement weakness, `CWE-308` use of single-factor authentication, in the `SSLVPN` service of `SonicOS`. A user who already holds valid credentials for another login method can bypass `SAML` authentication controls. Where `SAML` is where the `MFA` lives, the `MFA` is not broken, it is never asked. The attacker still needs those alternate credentials, so this is not an unauthenticated takeover, and it only matters where `SAML` handles `SSLVPN` logins.

`SonicWall` published advisory `SNWLID-2026-0014` on `6 November 2026` and `CISA` added the flaw to its `Known Exploited Vulnerabilities` catalog the same day, with a federal remediation deadline of `20 November 2026`. The flaw was reported by `Ryan Harris` of `The Electronic Office`. `SonicWall` lists no workaround; upgrading is the only fix. The advisory bundles seven vulnerabilities in total; this flaw is the only one with confirmed exploitation, and this tool grades only this flaw.

`CISA-ADP` scores it `CVSS 3.1 7.5 High` (`AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N`). `SonicWall` scores it `7.1` with a `PR:L` vector instead of `PR:N`; this tool follows `CISA-ADP`'s `7.5` as the headline score and notes the disagreement rather than picking a winner. The score is below `9`, but the `KEV` listing is the trigger: confirmed exploitation in the wild, two days from disclosure to this check.

## `The traps`

| `Signal` | `Grade` | `Why` |
| --- | --- | --- |
| `Gen8` on `8.2.2-8015` | `VULNERABLE` | **The build-number trap.** `8.2.2-8015` and the fixed `8.2.3-8015` share the build number `8015` and only the middle digit changes. A check on the build number alone clears this firewall by mistake. |
| `Gen7` on `7.3.4-7013` | `PATCHED` | `7.3.4-7013` is already the fix. `7.3.4-7015` shipped later, on `5 November`, but a check demanding `7015` or higher wrongly flags a fixed firewall. |
| `Gen7` on `7.3.3-7015`, or `Gen8` on `8.2.2-8015` | `VULNERABLE` | The advisory boundary builds, the newest affected build on each line. |
| A `Gen7` version graded as `Gen8`, or the reverse | `UNKNOWN` | The two generations are independent lines. A build from another generation cannot grade this firewall. |
| A bare version with no build number, for example `7.3.3` | `UNKNOWN` | The build number is part of the version. Without it the firewall has not been cleared, only left ungraded. |
| `Gen6` or older, for example `6.5.4-44` | `UNKNOWN` | End of support and outside the advisory's `Gen7`/`Gen8` table. There is no fix on that line; migrate to `Gen8` hardware. Do not treat it as cleared. |
| A vulnerable build with `SAML` not handling `SSLVPN` logins | `NOT-EXPOSED` | The bypass has nothing to bypass. Still upgrade: the code is vulnerable, and a config change can expose it. |

## `What it checks`

- `One firewall` (`--generation gen7 --version '7.3.3-7015'`): graded against that generation's fixed build
- `One firewall without SAML on SSLVPN` (`--no-saml`): a vulnerable build grades `NOT-EXPOSED` instead of `VULNERABLE`
- `A fleet, offline` (`--inventory-json firewalls.json`): a `JSON` list of `{label, generation, version, saml_sslvpn}` entries. `saml_sslvpn` defaults to `true` when omitted
- `The full table` (`--list`): both generations and their fixed builds
- `Machine output` (`--json`): the same grades as `JSON`

```sh
python3 sonicos_scanner.py --generation gen7 --version '7.3.3-7015'
python3 sonicos_scanner.py --generation gen8 --version '8.2.3-8015'
python3 sonicos_scanner.py --generation gen7 --version '7.3.3-7015' --no-saml
python3 sonicos_scanner.py --inventory-json firewalls.json
```

```json
[
  {"label": "fw-edge", "generation": "gen7", "version": "7.3.3-7015"},
  {"label": "fw-core", "generation": "gen8", "version": "8.2.3-8015", "saml_sslvpn": false}
]
```

Exit codes: `0` nothing vulnerable found, `2` vulnerable finding, `1` scan error. `UNKNOWN` does not change the exit code, but it is not clean.

## `The table`

| `Generation` | `Affected` | `Fixed in` |
| --- | --- | --- |
| `Gen7` (`TZ`, `NSa`, `NSsp`, `NSv`) | `7.3.3-7015` and older | `7.3.4-7013` and later |
| `Gen8` (`TZ`, `NSa`, `NSv`) | `8.2.2-8015` and older | `8.2.3-8015` and later |

Find the firmware version in the `SonicOS` management interface under `Device > Settings > Firmware and Settings`, or in a settings export. This tool reads version strings you supply; it does not log in to a firewall to fetch one.

## `What this tool does not do`

It does not test the bypass. Testing it would mean attempting a login with alternate credentials against a live `SSLVPN` service, which is an authentication attempt, not a version check. It does not scan the network for firewalls, and it does not grade a firewall from a banner or a login page: `SonicOS` version fingerprinting without authentication is unreliable, and guessing wrong in either direction is worse than refusing to grade.

## `Tests`

```sh
python3 -m unittest discover -s tests -v
```

`25` tests, all passing: version and generation parsing, both fixed builds, later builds, the boundary builds, the `Gen8` build-number trap, the `Gen7 7.3.4-7013` fix, one-build-below-fix grades, cross-generation and bare-version `UNKNOWN` grades, `Gen6` end-of-life handling, the `--no-saml` verdicts, `CLI` exit codes, `JSON` output, and inventory grading.

## `Sources`

- `SonicWall` advisory `SNWLID-2026-0014`, published `6 November 2026`: the affected and fixed builds for both generations, `CWE-308`, no workaround, reporter `Ryan Harris` (`The Electronic Office`)
- `CISA Known Exploited Vulnerabilities` catalog, `CVE-2026-19868`, added `6 November 2026`, due `20 November 2026`, exploitation active, `CVSS 3.1 7.5` (`CISA-ADP`)
- `GHSA-mq8w-j7h6-7q9w`: published `6 November 2026`, `CVSS 7.5`, fixed in `7.3.4-7013` / `8.2.3-8015`
- `SecurityWeek`, `7 November 2026`: `SonicWall`'s own score is `7.1`, `KEV` added the same day as disclosure
- `BleepingComputer`, via reporting `7 November 2026`: `7.3.4-7013` available `20 October`, `7.3.4-7015` on `5 November`, `8.2.3-8015` scheduled `6 November`

Two disagreements to note. First, the score: `SonicWall` says `7.1` (`PR:L`), `CISA-ADP` says `7.5` (`PR:N`). This tool follows `CISA-ADP` and notes the difference. Second, the proof of concept: one tracker lists a single public `GitHub` repository for this `CVE`, while several write-ups report no public proof of concept as of `7 November`. This tool does not fetch or use exploit code either way, so the disagreement does not change any grade. One more caution from the reporting: at least one government bulletin summarized the `Gen8` range slightly differently from the advisory table. This tool follows the advisory table, `8.2.2-8015` and older affected, `8.2.3-8015` and later fixed.

No public detection-only scanner for this `CVE` was found at publication time: no `nuclei` template exists for `CVE-2026-19868`, and no `foxcornlab` repo covered `SonicWall` or `SonicOS` before this one. `Qualys` added commercial detection (`QID 735993`) on `6 November`; that is a paid scanner, not a public triage tool.

## `Disclaimer`

Defensive triage only, for systems you own or are authorized to assess. This tool grades exposure from firmware version strings you supply. It does not exploit anything, and it is not a substitute for the vendor update.

## `Thanks to`

- `SonicWall PSIRT` for the advisory and the fixed builds
- `Ryan Harris` (`The Electronic Office`) for reporting the flaw
- `CISA` for the `KEV` listing that confirmed exploitation

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
