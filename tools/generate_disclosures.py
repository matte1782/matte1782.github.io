#!/usr/bin/env python3
"""Render the portfolio's PUBLIC disclosures from a single data file.

This is the modularity asset: the site's ``#disclosures`` section and the
sota-bench README "public findings" block are both GENERATED from one curated
source of truth, ``tools/public-findings.json``. Adding a credit is then a
one-line data change plus a regenerate, never a hand-edit of HTML.

Two safety properties, by construction:

1. **Fail-closed.** A record renders only if ``proof.published`` is true AND it
   carries a ``url`` and the display fields. A finding without a published-state
   proof is silently never rendered (it cannot leak onto the site).

2. **Live embargo gate (``--verify``).** ``--verify`` re-checks each record's
   proof against the LIVE GitHub state (repo advisory ``state == published`` or
   presence in the global advisory DB) via ``gh``, NEVER trusting the stored
   string. A record whose advisory is still triage / withdrawn / absent fails
   the verify and blocks the build. This is what keeps an embargoed or
   not-yet-realized finding (e.g. a pending GHSA, or a credit that has not
   published yet) off the public site.

Stdlib-only, no LLM. Usage::

    python tools/generate_disclosures.py --check                 # validate + fail-closed report
    python tools/generate_disclosures.py --verify                # ALSO live-check each proof (needs gh)
    python tools/generate_disclosures.py --render-site index.html
    python tools/generate_disclosures.py --render-bench-md ../sota-bench/README.md
"""

from __future__ import annotations

import argparse
import html
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SITE_START = "<!-- DISCLOSURES:START"
SITE_END = "<!-- DISCLOSURES:END -->"
BENCH_START = "<!-- PUBLIC-FINDINGS:START"
BENCH_END = "<!-- PUBLIC-FINDINGS:END -->"

_REQUIRED_DISPLAY = ("name", "severity_label", "score", "desc", "id_label", "url")


@dataclass(frozen=True)
class RecordStatus:
    """The result of validating one finding record."""

    name: str
    renderable: bool
    reasons: tuple[str, ...]


def load_findings(path: Path) -> list[dict[str, Any]]:
    """Load and shallow-validate the data file; return the findings list."""
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"{path}: top-level 'findings' must be a list")
    return findings


def validate_record(rec: dict[str, Any]) -> RecordStatus:
    """A record is renderable only if every display field is present AND its
    proof asserts a published state with a url (fail-closed)."""
    name = str(rec.get("name", "<unnamed>"))
    reasons: list[str] = []
    for key in _REQUIRED_DISPLAY:
        if not rec.get(key):
            reasons.append(f"missing display field {key!r}")
    proof = rec.get("proof")
    if not isinstance(proof, dict):
        reasons.append("missing 'proof' object")
    elif proof.get("published") is not True:
        reasons.append("proof.published is not true (fail-closed: not rendered)")
    return RecordStatus(name=name, renderable=not reasons, reasons=tuple(reasons))


def renderable_records(
    findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[RecordStatus]]:
    """Split findings into (renderable records, all statuses)."""
    statuses = [validate_record(r) for r in findings]
    keep = [r for r, s in zip(findings, statuses, strict=True) if s.renderable]
    return keep, statuses


# --- live embargo verification ----------------------------------------------


def _gh_json(args: list[str]) -> tuple[bool, str]:
    """Run ``gh api`` and return (ok, stdout-or-error). ok is the process success."""
    try:
        proc = subprocess.run(
            ["gh", "api", *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except FileNotFoundError:
        return False, "gh not found on PATH"
    except subprocess.TimeoutExpired:
        return False, "gh api timed out"
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout).strip()
    return True, proc.stdout.strip()


def verify_record_live(rec: dict[str, Any]) -> tuple[bool, str]:
    """Re-check a record's proof against the LIVE GitHub state.

    global_db proof  -> the GHSA must be present in the global advisory DB.
    repo_advisory    -> the repo advisory state must be exactly 'published'.
    """
    proof = rec.get("proof") or {}
    ghsa = proof.get("ghsa")
    repo = proof.get("repo")
    if not ghsa:
        return False, "proof has no ghsa to verify"
    if proof.get("in_global_db") is True:
        ok, out = _gh_json([f"advisories/{ghsa}", "--jq", ".ghsa_id"])
        if ok and out == ghsa:
            return True, f"present in global advisory DB ({ghsa})"
        return False, f"claimed in_global_db but global lookup failed: {out!r}"
    if not repo:
        return False, "repo_advisory proof has no repo to verify"
    ok, out = _gh_json([f"repos/{repo}/security-advisories/{ghsa}", "--jq", ".state"])
    if ok and out == "published":
        return True, f"repo advisory state=published ({repo}/{ghsa})"
    return False, f"repo advisory state is {out!r} (need 'published')"


# --- rendering ---------------------------------------------------------------


def _esc(value: Any) -> str:
    """HTML-escape a data field (text content). URLs are passed through _attr."""
    return html.escape(str(value), quote=False)


def render_site_rows(findings: list[dict[str, Any]]) -> list[str]:
    """Render the renderable findings as the site's ``.row`` anchors (exact
    indentation matching the hand-authored block so the first regenerate is a
    no-op diff)."""
    lines: list[str] = []
    for rec in findings:
        url = str(rec["url"])
        lines.append(
            f'      <a class="row" href="{url}" target="_blank" rel="noopener">'
        )
        lines.append(
            f'        <span class="sev">{_esc(rec["severity_label"])} '
            f'<span class="score">{_esc(rec["score"])}</span></span>'
        )
        lines.append(
            f'        <span><span class="name">{_esc(rec["name"])}</span>'
            f'<span class="desc">{_esc(rec["desc"])}</span></span>'
        )
        lines.append(
            f'        <span class="id">{_esc(rec["id_label"])} '
            f'<span class="arrow">&#8599;</span></span>'
        )
        lines.append("      </a>")
    return lines


def render_bench_md(findings: list[dict[str, Any]]) -> list[str]:
    """Render the renderable findings as a markdown table for the bench README."""
    lines = [
        "| finding | severity | identifier | advisory |",
        "|---|---|---|---|",
    ]
    for rec in findings:
        ident = _esc(rec["id_label"])
        link = f"[{ident}]({rec['url']})"
        lines.append(
            f"| {_esc(rec['name'])} | {_esc(rec['severity_label'])} {_esc(rec['score'])} "
            f"| {ident} | {link} |"
        )
    return lines


def inject_block(text: str, start: str, end: str, body: list[str]) -> str:
    """Replace the content strictly between the start- and end-marker lines.

    The marker lines themselves are preserved verbatim. Raises if either marker
    is missing or out of order.
    """
    src = text.splitlines()
    si = next((i for i, ln in enumerate(src) if start in ln), None)
    ei = next((i for i, ln in enumerate(src) if end in ln), None)
    if si is None or ei is None:
        raise ValueError(
            f"markers not found (start={si}, end={ei}); expected {start!r} and {end!r}"
        )
    if ei <= si:
        raise ValueError("end marker precedes start marker")
    new = src[: si + 1] + body + src[ei:]
    trailing = "\n" if text.endswith("\n") else ""
    return "\n".join(new) + trailing


# --- CLI ---------------------------------------------------------------------


def _report(statuses: list[RecordStatus]) -> int:
    rendered = [s for s in statuses if s.renderable]
    skipped = [s for s in statuses if not s.renderable]
    print(
        f"records: {len(statuses)}  renderable: {len(rendered)}  skipped(fail-closed): {len(skipped)}"
    )
    for s in statuses:
        mark = "RENDER" if s.renderable else "SKIP  "
        print(f"  [{mark}] {s.name}")
        for r in s.reasons:
            print(f"           - {r}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve().parent
    parser.add_argument("--data", default=str(here / "public-findings.json"))
    parser.add_argument(
        "--check", action="store_true", help="validate + fail-closed report"
    )
    parser.add_argument(
        "--verify", action="store_true", help="ALSO live-check each proof via gh"
    )
    parser.add_argument(
        "--render-site", metavar="INDEX_HTML", help="rewrite the site disclosures block"
    )
    parser.add_argument(
        "--render-bench-md", metavar="README_MD", help="rewrite the bench README block"
    )
    args = parser.parse_args(argv)

    data_path = Path(args.data)
    findings = load_findings(data_path)
    keep, statuses = renderable_records(findings)

    if args.check or not (args.verify or args.render_site or args.render_bench_md):
        _report(statuses)

    if args.verify:
        print("\n-- live embargo verify --")
        failed = 0
        for rec in keep:
            ok, detail = verify_record_live(rec)
            print(f"  [{'OK ' if ok else 'FAIL'}] {rec['name']}: {detail}")
            if not ok:
                failed += 1
        if failed:
            print(
                f"\nVERIFY FAILED: {failed} record(s) did not match live state; build blocked."
            )
            return 2
        print("verify ok: every rendered record is live-published.")

    if args.render_site:
        p = Path(args.render_site)
        out = inject_block(
            p.read_text(encoding="utf-8"), SITE_START, SITE_END, render_site_rows(keep)
        )
        p.write_text(out, encoding="utf-8")
        print(f"rendered {len(keep)} rows into {p}")

    if args.render_bench_md:
        p = Path(args.render_bench_md)
        out = inject_block(
            p.read_text(encoding="utf-8"), BENCH_START, BENCH_END, render_bench_md(keep)
        )
        p.write_text(out, encoding="utf-8")
        print(f"rendered {len(keep)} rows into {p}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
