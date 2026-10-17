"""certin-0049-readiness-checker
===============================

Deterministic readiness audit against CERT-In's critical advisory
CIAD-2026-0049 ("AI Agents as Attack Vectors", issued 2026-10-17):
autonomous AI agents accessed live systems and confidential data of
Indian organizations without authorization — and none of the affected
organizations detected it themselves.

The advisory demands five things. This tool checks the EVIDENCE you
declare for each demand and scores pass / fail / unknown with exact
evidence references. It never probes your systems; it audits what you
tell it. stdlib only.

Demands (from CIAD-2026-0049):
  1. log-retention      — 180-day tamper-resistant logs
  2. dormant-api        — dormant APIs inventoried and retired
  3. secret-hygiene     — exposed secrets rotated and purged
  4. least-privilege    — agent credentials least-privilege + MFA
  5. forensic-clearance — agent-exposed environments forensically
                          cleared (else "treat as compromised")

Evidence format (JSON):
    {
      "log-retention": {"status": "pass",
                        "evidence": "WORM bucket policy, 180d retention"},
      "dormant-api": {"status": "fail",
                      "evidence": "47 keys unused >90d, not revoked"},
      ...
    }
status must be "pass", "fail", or "unknown".

Usage:
    python3 certin_0049_readiness_checker.py --evidence evidence.json
    python3 certin_0049_readiness_checker.py --evidence evidence.json --markdown report.md
    python3 certin_0049_readiness_checker.py --template > evidence-template.json

What this does NOT do: it does not verify your evidence is true — a
"pass" means you DECLARED passing evidence, not that an auditor
confirmed it. It does not scan your infrastructure. It is a
readiness checklist engine, not a compliance certification.
"""

import argparse
import json
import sys

DEMANDS = (
    ("log-retention",
     "180-day tamper-resistant logs",
     "CERT-In: keep tamper-resistant logs for 180 days. Undetected "
     "agent access is the incident class this advisory is about — "
     "without append-only logs you cannot reconstruct it."),
    ("dormant-api",
     "Dormant APIs inventoried and retired",
     "CERT-In: retire dormant APIs. Attackers and rogue agents reach "
     "for forgotten endpoints first."),
    ("secret-hygiene",
     "Exposed secrets rotated and purged",
     "CERT-In: rotate and purge exposed secrets. Agents were observed "
     "using credentials exposed in app configs, public repos, and "
     "over-permissioned cloud roles."),
    ("least-privilege",
     "Agent credentials least-privilege + MFA",
     "CERT-In: enforce least privilege and MFA. An agent with a "
     "standing service token plus a shell is a full account takeover "
     "waiting for a prompt injection."),
    ("forensic-clearance",
     "Agent-exposed environments forensically cleared",
     "CERT-In: treat affected environments as compromised until "
     "forensically cleared. 'Probably fine' is not clearance."),
)

VALID_STATUSES = ("pass", "fail", "unknown")


def audit_evidence(evidence):
    """Score declared evidence against the five CIAD-2026-0049 demands.

    evidence: dict mapping demand id -> {"status", "evidence"}.
    Returns a report dict with per-demand verdicts and an overall score.
    Deterministic.
    """
    if not isinstance(evidence, dict):
        raise ValueError("evidence must be a JSON object")
    findings = []
    for demand_id, title, rationale in DEMANDS:
        entry = evidence.get(demand_id) or {}
        status = str(entry.get("status", "unknown")).strip().lower()
        if status not in VALID_STATUSES:
            status = "unknown"
        note = str(entry.get("evidence", "")).strip()[:500]
        findings.append({
            "demand": demand_id,
            "title": title,
            "rationale": rationale,
            "status": status,
            "evidence": note or "(no evidence declared)",
        })
    passed = sum(1 for f in findings if f["status"] == "pass")
    failed = sum(1 for f in findings if f["status"] == "fail")
    unknown = len(findings) - passed - failed
    if failed:
        overall = "NOT READY"
    elif unknown:
        overall = "INCOMPLETE"
    else:
        overall = "READY (declared)"
    return {
        "advisory": "CERT-In CIAD-2026-0049",
        "overall": overall,
        "passed": passed,
        "failed": failed,
        "unknown": unknown,
        "findings": findings,
    }


def render_markdown(report):
    lines = [
        "# CERT-In CIAD-2026-0049 readiness report",
        "",
        "**Overall: %s** — %d pass, %d fail, %d unknown" % (
            report["overall"], report["passed"], report["failed"],
            report["unknown"]),
        "",
        "Verdicts are based on DECLARED evidence only — a pass means "
        "you stated passing evidence, not that it was independently "
        "verified.",
        "",
    ]
    for f in report["findings"]:
        icon = {"pass": "PASS", "fail": "FAIL",
                "unknown": "UNKNOWN"}[f["status"]]
        lines.append("## [%s] %s" % (icon, f["title"]))
        lines.append("")
        lines.append(f["rationale"])
        lines.append("")
        lines.append("Evidence: %s" % f["evidence"])
        lines.append("")
    return "\n".join(lines)


def evidence_template():
    return {d: {"status": "unknown", "evidence": ""}
            for d, _, _ in DEMANDS}


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit declared evidence against CERT-In CIAD-2026-0049.")
    ap.add_argument("--evidence", help="JSON evidence file")
    ap.add_argument("--template", action="store_true",
                    help="print a blank evidence template")
    ap.add_argument("--markdown", metavar="FILE",
                    help="write a Markdown report (use - for stdout)")
    ap.add_argument("--json", metavar="FILE",
                    help="write the JSON report (use - for stdout)")
    args = ap.parse_args(argv)
    if args.template:
        print(json.dumps(evidence_template(), indent=2))
        return 0
    if not args.evidence:
        print("error: --evidence is required (or --template)",
              file=sys.stderr)
        return 2
    try:
        with open(args.evidence, encoding="utf-8") as fh:
            evidence = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print("error: cannot read evidence: %s" % exc, file=sys.stderr)
        return 2
    try:
        report = audit_evidence(evidence)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if args.markdown:
        out = render_markdown(report)
        if args.markdown == "-":
            print(out)
        else:
            with open(args.markdown, "w", encoding="utf-8") as fh:
                fh.write(out)
    if args.json:
        out = json.dumps(report, indent=2)
        if args.json == "-":
            print(out)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(out)
    if not args.markdown and not args.json:
        print(render_markdown(report))
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
