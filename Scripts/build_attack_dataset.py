#!/usr/bin/env python3
"""
Build an Alpaca-style QA file from MITRE ATT&CK “uses” relationships.

• Works with Enterprise / Mobile / ICS (v15+).
• Reads raw JSON – no stix2, no validation surprises.
• Output is ./attack_qa_<domain>.jsonl (add .gz to compress).

Quick start:
    pip install typer rich requests
    python build_attack_dataset.py --domain enterprise
"""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import requests
import typer
from rich.progress import track

PROMPT = "Which MITRE ATT&CK technique and tactic does this activity demonstrate?"
INPUT_PREFIX = "Activity: "

DOMAINS = {
    "enterprise": "enterprise-attack",
    "mobile":     "mobile-attack",
    "ics":        "ics-attack",
}
DEFAULT_VER = "16.0"

URL_TPL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
           "master/{dom}/{dom}-{ver}.json")

# ────────────────────────────────────────────────────────────────────
def download(dom: str, ver: str, dest: Path) -> Path:
    url = URL_TPL.format(dom=dom, ver=ver)
    typer.echo(f"↓ {url}")
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    dest.write_bytes(r.content)
    typer.echo(f"✓ saved → {dest}")
    return dest

def load_objects(path: Path) -> List[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["objects"]

# ────────────────────────────────────────────────────────────────────
def make_maps(objs: List[dict], dom: str) -> Tuple[Dict[str, dict], Dict[str, Tuple[str,str]]]:
    tech_by_id: Dict[str, dict] = {}
    tactic_by_short: Dict[str, Tuple[str,str]] = {}

    for o in objs:
        if o.get("type") == "attack-pattern" and dom in o.get("x_mitre_domains", []):
            tech_by_id[o["id"]] = o
        elif o.get("type") == "x-mitre-tactic" and dom in o.get("x_mitre_domains", []):
            ext_id = next(r["external_id"] for r in o["external_references"]
                          if r["source_name"] == "mitre-attack")
            tactic_by_short[o["x_mitre_shortname"]] = (ext_id, o["name"])
    return tech_by_id, tactic_by_short

def build_rows(objs: List[dict], dom: str) -> List[dict]:
    techs, tactics = make_maps(objs, dom)
    rows: List[dict] = []

    uses = [o for o in objs if o.get("type") == "relationship"
                             and o.get("relationship_type") == "uses"
                             and o.get("description")]

    for rel in track(uses, description="Building examples"):
        sent = rel["description"].replace("\n", " ").strip()
        tech = techs.get(rel["target_ref"])
        if not tech:
            continue

        tech_id = next(r["external_id"] for r in tech["external_references"]
                       if r["source_name"] == "mitre-attack")
        tech_name = tech["name"]

        tac_ids, tac_names = [], []
        for phase in tech.get("kill_chain_phases", []):
            if phase["kill_chain_name"] != "mitre-attack":
                continue
            short = phase["phase_name"]
            if short in tactics:
                tid, tname = tactics[short]
                tac_ids.append(tid)
                tac_names.append(tname)
        if not tac_ids:      # extremely rare
            continue

        rows.append({
            "instruction": PROMPT,
            "input": INPUT_PREFIX + sent,
            "output": f"Technique={tech_id}: {tech_name} | "
                      f"Tactic={' ; '.join(tac_ids)}: {' ; '.join(tac_names)}"
        })
    return rows

# ────────────────────────────────────────────────────────────────────
def main(
    domain: str = typer.Option("enterprise", help="enterprise | mobile | ics"),
    version: str = typer.Option(DEFAULT_VER,   help="ATT&CK version to fetch"),
    out:     Path = typer.Option(None,         help="Output file (.jsonl[.gz])"),
    stix:    Path = typer.Option(None,         help="Use a local bundle JSON"),
):
    if domain not in DOMAINS:
        typer.echo(f"Domain must be one of {list(DOMAINS)}", err=True)
        raise typer.Exit(1)
    dom_str = DOMAINS[domain]

    if stix is None:
        stix = Path(f"{dom_str}-{version}.json")
        if not stix.exists():
            download(dom_str, version, stix)
        else:
            typer.echo(f"✓ using cached {stix}")
    else:
        stix = stix.expanduser().resolve()
        if not stix.exists():
            typer.echo(f"{stix} not found", err=True)
            raise typer.Exit(1)

    objs  = load_objects(stix)
    rows  = build_rows(objs, dom_str)
    typer.echo(f"✓ collected {len(rows):,} examples")

    if out is None:
        out = Path(f"attack_qa_{domain}.jsonl")
    opener = gzip.open if out.suffix == ".gz" else open
    with opener(out, "wt", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    typer.echo(f"✓ written → {out}  ({out.stat().st_size/1024:.1f} KB)")


if __name__ == "__main__":
    try:
        typer.run(main)
    except KeyboardInterrupt:
        sys.exit(1)
