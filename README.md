# `react2shell-scanner`

Triage scanner for `CVE-2025-55182` (`React2Shell`), the `unauthenticated` `RCE` in the `React Server Components` protocol, plus its `Next.js` downstream `CVE-2025-66478`. Built from my `AdverXarial` research on popping a `react`-based target through `React2Shell` for initial access.

> `Detection` only. This tool never sends `deserialization` payloads or exploit traffic. Version checks and fingerprinting, nothing more.

## The `bug`

`React Server Components` unsafely `deserialize` data from `HTTP` requests hitting `Server Function` endpoints. One crafted `POST` body and an unauthenticated attacker runs arbitrary code in the `Node.js` server process. `CVSS 10.0`, in `CISA KEV` since `Dec 2025`, exploited in the wild within hours of disclosure.

| `Package` | `Vulnerable` | `Fixed` |
|---|---|---|
| `react-server-dom-webpack` | `19.0.0`, `19.1.0`, `19.1.1`, `19.2.0` | `19.0.1` / `19.1.2` / `19.2.1` |
| `react-server-dom-parcel` | `19.0.0`, `19.1.0`, `19.1.1`, `19.2.0` | `19.0.1` / `19.1.2` / `19.2.1` |
| `react-server-dom-turbopack` | `19.0.0`, `19.1.0`, `19.1.1`, `19.2.0` | `19.0.1` / `19.1.2` / `19.2.1` |
| `next` | `14.3.0-15.0.4`, `15.1.0-15.1.8`, `15.2.0-15.2.5`, `15.3.0-15.3.5`, `15.4.0-15.4.7`, `15.5.0-15.5.6`, `16.0.0-16.0.6` | `15.0.5`, `15.1.9`, `15.2.6`, `15.3.6`, `15.4.8`, `15.5.7`, `16.0.7` |

## Usage

No dependencies, `standard library` only.

**Audit a local project** (most reliable signal, reads the resolved tree):

```shell
python3 react2shell_scanner.py audit /path/to/project
```

**Fingerprint a remote host:**

```shell
python3 react2shell_scanner.py scan app.example.com
python3 react2shell_scanner.py scan https://app.example.com -k --json
```

Verdicts: `VULNERABLE`, `PATCHED`, `NEEDS-MANUAL-CHECK`, `NOT-NEXTJS`, `UNREACHABLE`.

> `Note`: remote `Next.js` version is rarely exposed, so most live hosts land on `NEEDS-MANUAL-CHECK`. Run `audit` against the deployed build for a hard answer.

**Hunt logs for exploitation attempts:**

```shell
python3 react2shell_scanner.py logcheck /var/log/nginx/access.log
```

Flags `POST`s carrying `RSC` / `Flight` markers (`text/x-component`, `Next-Action`). Heuristic, treat hits as leads. Exits `1` on hits for monitoring pipelines.

## Remediation

1. Upgrade `react-server-dom-*` to `19.0.1` / `19.1.2` / `19.2.1` and `next` to the fixed release in your line.
2. Don't trust the top-level `react` version, inspect the resolved tree (`npm ls`, lockfile).
3. Assume `compromise` on anything internet-facing that ran a vulnerable build: rotate secrets, check for persistence, review logs back to `Dec 2025`.

## References

- `React` security advisory for `CVE-2025-55182`
- `Next.js` security release tracking `CVE-2025-66478`
- `CISA KEV` entry
- My write-up: `AdverXarial` on Substack

## Disclaimer

For `educational` and `authorized` testing only. Only scan systems you own or have `permission` to test.

## `Foxcorn Lab`

> Research by `Vineeth Kumar`, `Foxcorn Lab`. Found a bug or want a feature, open an `issue`.
