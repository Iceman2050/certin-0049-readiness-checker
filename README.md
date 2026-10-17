# certin-0049-readiness-checker


## ⚡ GitHub Action

Run it in CI — fails the build on findings at or above your threshold:

```yaml
- uses: actions/checkout@v4
- uses: Iceman2050/certin-0049-readiness-checker@v1
      with:
        evidence: '.certin-0049-evidence.json'
        fail-on-failure: 'true' # default
```

Full input reference: [`action.yml`](./action.yml).

**Are you ready for CERT-In's AI-agent advisory — or are you the next undetected breach?**

On October 17, 2026, India's CERT-In issued critical advisory CIAD-2026-0049 ("AI Agents as Attack Vectors"): autonomous AI agents accessed live systems and confidential data of Indian organizations **without authorization** — and none of the affected organizations detected it themselves. The advisory demands five things: 180-day tamper-resistant logs, dormant API retirement, exposed-secret rotation, least-privilege + MFA on agent credentials, and forensic clearance of agent-exposed environments.

Government advisories ship as PDFs. This tool turns CIAD-2026-0049 into a **machine-checkable readiness audit**: you declare your evidence per demand (JSON), and it scores each demand pass / fail / unknown with exact evidence references.

## What it checks (the five demands)

| Demand | What "pass" means |
|--------|-------------------|
| `log-retention` | 180-day tamper-resistant (append-only) logs exist |
| `dormant-api` | Dormant APIs are inventoried and retired |
| `secret-hygiene` | Exposed secrets rotated and purged |
| `least-privilege` | Agent credentials are least-privilege + MFA |
| `forensic-clearance` | Agent-exposed environments forensically cleared |

## Usage

```bash
# start from a blank template
python3 certin_0049_readiness_checker.py --template > evidence.json
# edit evidence.json, then audit
python3 certin_0049_readiness_checker.py --evidence evidence.json
python3 certin_0049_readiness_checker.py --evidence evidence.json --markdown report.md
python3 certin_0049_readiness_checker.py --evidence evidence.json --json report.json
```

Overall verdict: `NOT READY` if anything fails, `INCOMPLETE` if anything is unknown, `READY (declared)` only when all five pass.

## What this does NOT do

- It audits **declared** evidence — a "pass" means you stated passing evidence, not that an independent auditor confirmed it. It is not a compliance certification.
- It does not scan your infrastructure. Pair it with real log and IAM audits.

Python standard library only. No network, no dependencies.

## Built by Ingenious AI

This tool is built and maintained by **Ingenious AI**. Get early access to our AI security platforms:

- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI


> Built by Ingenious AI with Muse — get free tokens with invite code `2HCQH1`
