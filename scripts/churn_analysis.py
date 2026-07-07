#!/usr/bin/env python3
"""Attribute verdict-cache churn to the EXACT prompt section that changed (JEF-387).

Stop playing whack-a-mole with re-judge churn: over a 24h window, ingest the engine's
compact `ADJ-MISS-DIAG` log lines (one per re-judge / cache MISS) and answer, from fact,
WHAT churns and WHY — with no full-prompt dumps and no fuzzy text-diffing.

Input — the structured diagnostic line the engine emits (`engine/src/engine/churn_diag.rs`),
in tracing's default `key=value` field format (all values space-free):

    <ts>  INFO protector::engine::churn_diag: ADJ-MISS-DIAG entry=<key> fp=<hash> \
      chain=<hash> sec_runtime=<h> sec_cves=<h> sec_secrets=<h> sec_posture=<h> \
      sec_objectives=<h> sec_entry=<h>

Collect it with, e.g.:

    kubectl logs -n protector deploy/protector --since=24h | \
      python3 scripts/churn_analysis.py

Fields the harness uses:
  entry  — the entry key; the per-entry timeline key.
  fp     — the WHOLE-prompt hash (the verdict-cache key). Between two consecutive lines for
           an entry: fp CHANGED ⇒ prompt churn (attributed to the sec_* that moved);
           fp UNCHANGED ⇒ an Uncertain-retry (JEF-234: the MODEL's verdict, not the prompt)
           — counted separately and NEVER conflated with prompt churn.
  chain  — the objective/technique-SET shape hash; entries sharing it are grouped.
  sec_*  — the six per-section fingerprints (runtime, cves, secrets, posture, objectives,
           entry). The section(s) whose hash changed between two consecutive lines ARE the
           attributed cause of that re-judge.

Output:
  1. Fleet-wide ranked attribution — of all prompt-churn re-judges, the % caused by each
     section changing. THE answer to "what churns."
  2. prompt-churn vs Uncertain-retry split — the two are counted separately.
  3. Per-entry timeline — each entry's re-judge sequence + the section(s) that changed each
     time.
  4. Chain grouping — entries clustered by `chain` so "these N entries all churn on runtime"
     is visible.

Usage:
    python3 scripts/churn_analysis.py [LOGFILE ...]   # read files, or stdin if none
    python3 scripts/churn_analysis.py --selftest       # run the built-in fixture test
"""

import re
import sys
from collections import Counter, OrderedDict, defaultdict

# The six labeled prompt sections, in the order the engine assembles + logs them. The one
# whose hash changes between two consecutive lines for an entry IS the attributed cause.
SECTIONS = ["runtime", "cves", "secrets", "posture", "objectives", "entry"]

# The compact-line marker AND its discriminator: a per-section field only the compact line
# carries. Requiring it cleanly ignores the optional heavy `ADJ-MISS-DIAG-FULL` spot-check
# line (which has none of the sec_* fields, only a space-bearing `prompt=` dump).
MARKER = "ADJ-MISS-DIAG"
_FIELD = re.compile(r"(\w+)=(\S+)")


def parse_line(line):
    """Parse one log line into a record dict, or return None if it is not a compact
    ADJ-MISS-DIAG line. Order- and prefix-independent: fields are extracted by `key=value`
    anywhere in the line, so a `kubectl logs --prefix` pod tag or the leading timestamp/level
    never interfere."""
    if MARKER not in line or "sec_runtime=" not in line:
        return None
    # Values are space-free (hex hashes, RFC1123-ish node keys); strip any surrounding quotes
    # defensively so the split is identical whether the formatter quotes string fields or not.
    fields = {k: v.strip('"') for k, v in _FIELD.findall(line)}
    if "entry" not in fields or "fp" not in fields:
        return None
    record = {
        "entry": fields["entry"],
        "fp": fields["fp"],
        "chain": fields.get("chain", ""),
        "sections": {s: fields.get(f"sec_{s}", "") for s in SECTIONS},
    }
    return record


def load_records(lines):
    """Parse an iterable of log lines into records, preserving order (kubectl logs is already
    chronological, so input order IS the per-entry re-judge sequence)."""
    records = []
    for line in lines:
        record = parse_line(line)
        if record is not None:
            records.append(record)
    return records


def changed_sections(prev, cur):
    """The section names whose fingerprint differs between two consecutive records."""
    return [s for s in SECTIONS if prev["sections"][s] != cur["sections"][s]]


def analyze(records):
    """Reduce the ordered records into the churn attribution. A re-judge is a TRANSITION
    between two consecutive lines for the same entry (the first line for an entry is the
    initial judge — no predecessor to attribute against). Each transition is split by `fp`:
    changed ⇒ prompt churn (attributed to every section that moved); unchanged ⇒ an
    Uncertain-retry (JEF-234)."""
    by_entry = OrderedDict()
    for record in records:
        by_entry.setdefault(record["entry"], []).append(record)

    # Per-section attribution over PROMPT-CHURN transitions only. A transition that moves N
    # sections increments all N, so a section's share is "of prompt-churn re-judges, the % in
    # which THIS section changed" (shares can sum past 100% when sections co-move).
    section_hits = Counter()
    prompt_churn = 0
    uncertain_retries = 0
    initial_judges = 0

    timelines = OrderedDict()
    # chain -> {entries, prompt_churn, uncertain, section_hits}
    groups = defaultdict(lambda: {
        "entries": set(),
        "prompt_churn": 0,
        "uncertain": 0,
        "section_hits": Counter(),
    })

    for entry, seq in by_entry.items():
        initial_judges += 1
        steps = []
        for prev, cur in zip(seq, seq[1:]):
            chain = cur["chain"]
            groups[chain]["entries"].add(entry)
            if cur["fp"] != prev["fp"]:
                moved = changed_sections(prev, cur)
                prompt_churn += 1
                section_hits.update(moved)
                groups[chain]["prompt_churn"] += 1
                groups[chain]["section_hits"].update(moved)
                steps.append({"kind": "prompt-churn", "sections": moved})
            else:
                # fp UNCHANGED ⇒ the model was re-run on an identical prompt: an
                # Uncertain-retry, never prompt churn. `fp` is authoritative for the split.
                uncertain_retries += 1
                groups[chain]["uncertain"] += 1
                steps.append({"kind": "uncertain-retry", "sections": []})
        timelines[entry] = steps

    transitions = prompt_churn + uncertain_retries
    return {
        "total_events": len(records),
        "entries": len(by_entry),
        "initial_judges": initial_judges,
        "transitions": transitions,
        "prompt_churn": prompt_churn,
        "uncertain_retries": uncertain_retries,
        "section_hits": section_hits,
        "timelines": timelines,
        "groups": groups,
    }


def _pct(part, whole):
    return (100.0 * part / whole) if whole else 0.0


def format_report(a):
    """Render the analysis as the human churn report."""
    out = []
    out.append("=== churn attribution (JEF-387) ===")
    out.append(
        f"events={a['total_events']}  entries={a['entries']}  "
        f"re-judges(transitions)={a['transitions']}  "
        f"initial-judges={a['initial_judges']}"
    )

    out.append("")
    out.append("--- prompt-churn vs Uncertain-retry (JEF-234) split ---")
    out.append(
        f"prompt-churn      {a['prompt_churn']:>6}  "
        f"({_pct(a['prompt_churn'], a['transitions']):5.1f}% of re-judges)"
    )
    out.append(
        f"uncertain-retry   {a['uncertain_retries']:>6}  "
        f"({_pct(a['uncertain_retries'], a['transitions']):5.1f}% of re-judges)"
    )

    out.append("")
    out.append("--- fleet-wide ranked attribution (of prompt-churn re-judges) ---")
    ranked = sorted(a["section_hits"].items(), key=lambda kv: (-kv[1], kv[0]))
    if not ranked:
        out.append("  (no prompt churn)")
    for section, count in ranked:
        out.append(
            f"  {section:<12}{count:>6}  ({_pct(count, a['prompt_churn']):5.1f}% of prompt churn)"
        )

    out.append("")
    out.append("--- grouping by chain shape ---")
    for chain, g in sorted(a["groups"].items(), key=lambda kv: -kv[1]["prompt_churn"]):
        top = g["section_hits"].most_common(1)
        top_str = f"top={top[0][0]}({top[0][1]})" if top else "top=none"
        out.append(
            f"  chain={chain}  entries={len(g['entries'])}  "
            f"prompt-churn={g['prompt_churn']}  uncertain={g['uncertain']}  {top_str}"
        )

    out.append("")
    out.append("--- per-entry timeline ---")
    for entry, steps in a["timelines"].items():
        out.append(f"  {entry}")
        if not steps:
            out.append("    (no re-judge — single observation)")
        for i, step in enumerate(steps, 1):
            if step["kind"] == "prompt-churn":
                out.append(f"    {i}. prompt-churn  changed={','.join(step['sections'])}")
            else:
                out.append(f"    {i}. uncertain-retry")
    return "\n".join(out)


# --- fixture selftest (no pytest / pip; stdlib asserts only) -------------------------------

_FIXTURE = """\
2026-06-30T00:00:00.000000Z  INFO protector::engine::churn_diag: ADJ-MISS-DIAG entry=workload/app/Pod/web fp=fp1 chain=CH1 sec_runtime=r1 sec_cves=c1 sec_secrets=s0 sec_posture=p0 sec_objectives=o1 sec_entry=e1
2026-06-30T00:05:00.000000Z  INFO protector::engine::churn_diag: ADJ-MISS-DIAG entry=workload/app/Pod/web fp=fp2 chain=CH1 sec_runtime=r2 sec_cves=c1 sec_secrets=s0 sec_posture=p0 sec_objectives=o1 sec_entry=e1
2026-06-30T00:10:00.000000Z  INFO protector::engine::churn_diag: ADJ-MISS-DIAG entry=workload/app/Pod/web fp=fp2 chain=CH1 sec_runtime=r2 sec_cves=c1 sec_secrets=s0 sec_posture=p0 sec_objectives=o1 sec_entry=e1
2026-06-30T00:15:00.000000Z  INFO protector::engine::churn_diag: ADJ-MISS-DIAG entry=workload/app/Pod/web fp=fp3 chain=CH1 sec_runtime=r2 sec_cves=c2 sec_secrets=s0 sec_posture=p0 sec_objectives=o1 sec_entry=e1
2026-06-30T00:00:00.000000Z  INFO protector::engine::churn_diag: ADJ-MISS-DIAG entry=workload/api/Pod/svc fp=g1 chain=CH1 sec_runtime=R1 sec_cves=C0 sec_secrets=S0 sec_posture=P0 sec_objectives=O1 sec_entry=E1
2026-06-30T00:05:00.000000Z  INFO protector::engine::churn_diag: ADJ-MISS-DIAG entry=workload/api/Pod/svc fp=g2 chain=CH1 sec_runtime=R2 sec_cves=C0 sec_secrets=S0 sec_posture=P0 sec_objectives=O1 sec_entry=E1
2026-06-30T00:20:00.000000Z  INFO protector::engine::churn_diag: ADJ-MISS-DIAG-FULL entry=workload/app/Pod/web fp=fp3 prompt="You are a senior security analyst making one call with spaces"
"""


def selftest():
    records = load_records(_FIXTURE.splitlines())
    # The FULL spot-check line (spaces in `prompt=`, no sec_*) must be ignored.
    assert len(records) == 6, f"expected 6 compact records, got {len(records)}"

    a = analyze(records)
    assert a["entries"] == 2, a["entries"]
    # web: fp1->fp2 (runtime churn), fp2->fp2 (uncertain-retry), fp2->fp3 (cves churn).
    # svc: g1->g2 (runtime churn). Total 4 transitions.
    assert a["transitions"] == 4, a["transitions"]
    assert a["prompt_churn"] == 3, a["prompt_churn"]
    assert a["uncertain_retries"] == 1, a["uncertain_retries"]
    # Attribution: runtime moved on 2 prompt-churn transitions, cves on 1.
    assert a["section_hits"]["runtime"] == 2, a["section_hits"]
    assert a["section_hits"]["cves"] == 1, a["section_hits"]
    assert a["section_hits"]["objectives"] == 0
    assert a["section_hits"]["entry"] == 0

    # The web timeline: churn(runtime), uncertain-retry, churn(cves).
    web = a["timelines"]["workload/app/Pod/web"]
    assert [s["kind"] for s in web] == [
        "prompt-churn",
        "uncertain-retry",
        "prompt-churn",
    ], web
    assert web[0]["sections"] == ["runtime"], web[0]
    assert web[2]["sections"] == ["cves"], web[2]

    # Grouping: both entries share chain CH1; runtime is its top churn section.
    grp = a["groups"]["CH1"]
    assert len(grp["entries"]) == 2, grp
    assert grp["section_hits"].most_common(1)[0][0] == "runtime", grp["section_hits"]

    # The report renders without error and names the split.
    report = format_report(a)
    assert "prompt-churn vs Uncertain-retry" in report
    assert "runtime" in report

    print("churn_analysis selftest: OK (6 records, 3 prompt-churn, 1 uncertain-retry)")


def main(argv):
    if "--selftest" in argv:
        selftest()
        return 0
    paths = [a for a in argv if not a.startswith("-")]
    if paths:
        lines = []
        for path in paths:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                lines.extend(handle.readlines())
    else:
        lines = sys.stdin.readlines()
    records = load_records(lines)
    print(format_report(analyze(records)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
