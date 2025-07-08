#!/usr/bin/env python3
"""
evaluate_valid.py – v4.3.1
============================
Evaluate an LLM’s mapping of free-text cyber-threat activity to MITRE ATT&CK
technique **and** tactic IDs, writing a CSV plus metrics to disk and terminal.

Changes vs v4.3.0:
* Print P/R/F1 metrics to terminal in addition to CSV summary.
"""

import argparse, datetime, json, pathlib, re, sys, time
from typing import Dict, Set, Tuple

import pandas as pd, requests
from tqdm import tqdm

# ---------------------------------------------------------------------------- #
# 1. Regex patterns for IDs & gold "ID – Name" pairs
# ---------------------------------------------------------------------------- #
TECH_ID_RE  = re.compile(r"\bT\d{4}(?:\.\d{3})?\b",  re.IGNORECASE)
TACT_ID_RE  = re.compile(r"\bTA\d{4}\b",             re.IGNORECASE)

TECH_PAIR_RE = re.compile(r"(T\d{4}(?:\.\d{3})?)\s*[\u2013:\-]\s*([^|\n]+)")
TACT_PAIR_RE = re.compile(r"(TA\d{4})\s*[\u2013:\-]\s*([^|\n]+)")

TECHNIQUE_NAME2ID: Dict[str, str] = {}
TACTIC_NAME2ID:    Dict[str, str] = {}

# ---------------------------------------------------------------------------- #
# 2. Build name → ID maps from validation file
# ---------------------------------------------------------------------------- #
def discover_name_maps(val_path: pathlib.Path) -> Tuple[Dict[str, str], Dict[str, str]]:
    tech_map, tact_map = {}, {}
    with val_path.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            gold = rec.get("output", "")
            for tid, name in TECH_PAIR_RE.findall(gold):
                tech_map[name.strip().lower()] = tid.upper()
            for taid, name in TACT_PAIR_RE.findall(gold):
                tact_map[name.strip().lower()] = taid.upper()
    return tech_map, tact_map

# ---------------------------------------------------------------------------- #
# 3. Extraction by regex or name
# ---------------------------------------------------------------------------- #
def ids_by_regex(text: str, pat: re.Pattern) -> Set[str]:
    return {m.upper() for m in pat.findall(text)}

def ids_by_name(text: str, name2id: Dict[str, str]) -> Set[str]:
    found = set()
    for name, tid in name2id.items():
        if re.search(rf"\b{re.escape(name)}\b", text, flags=re.IGNORECASE):
            found.add(tid)
    return found

# ---------------------------------------------------------------------------- #
# 4. Unwrap JSON-wrapped output
# ---------------------------------------------------------------------------- #
def safe_extract_output(raw: str) -> str:
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict) and "output" in parsed:
            return parsed["output"]
    except json.JSONDecodeError:
        pass
    return raw

# ---------------------------------------------------------------------------- #
# 5. Strip any echoed prompt / wrappers
# ---------------------------------------------------------------------------- #
def strip_prompt_echo(text: str) -> str:
    # Remove end-of-text markers
    text = text.split("<|endoftext|>")[0]
    # Handle chat-style wrappers
    if "### response" in text.lower():
        text = text.split("### Response:")[-1]
        text = text.split("### response:")[-1]
    # Remove instructions/input echoes
    text = re.split(r"\n\s*instruction:", text, flags=re.IGNORECASE)[0]
    text = re.split(r"\n\s*input:",       text, flags=re.IGNORECASE)[0]
    # Remove leading Output: labels
    text = re.sub(r"^\s*Output\s*[:\-]\s*", "", text, flags=re.IGNORECASE)
    # Trim and fallback
    text = text.strip()
    if text:
        return text
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""

# ---------------------------------------------------------------------------- #
# 6. Prompt constructor
# ---------------------------------------------------------------------------- #
def build_prompt(activity: str) -> str:
    instr = (
        "Which MITRE ATT&CK technique and tactic (including their IDs) "
        "does this activity demonstrate?"
    )
    return (
        f"instruction: {instr}\n\n"
        f"input: Activity: {activity}\n\n"
        "Output:"
    )

# ---------------------------------------------------------------------------- #
# 7. HTTP query with retries
# ---------------------------------------------------------------------------- #
def query(api: str, prompt: str, max_tokens: int, temp: float) -> str:
    payload = {"prompt": prompt, "max_tokens": max_tokens,
               "temperature": temp, "stream": False}
    for _ in range(3):
        try:
            r = requests.post(api, json=payload, timeout=120)
            r.raise_for_status()
            return r.json()["choices"][0]["text"].strip()
        except Exception:
            time.sleep(1)
    return ""

# ---------------------------------------------------------------------------- #
# 8. Micro-average metrics helper
# ---------------------------------------------------------------------------- #
def micro(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f

# ---------------------------------------------------------------------------- #
# 9. Main evaluation loop
# ---------------------------------------------------------------------------- #
def main(args) -> int:
    global TECHNIQUE_NAME2ID, TACTIC_NAME2ID

    # Discover name→ID maps
    val_path = pathlib.Path(args.validation)
    TECHNIQUE_NAME2ID, TACTIC_NAME2ID = discover_name_maps(val_path)
    if args.tech_map:
        TECHNIQUE_NAME2ID.update(
            {k.lower(): v.upper() for k, v in json.load(open(args.tech_map)).items()}
        )

    api_url = f"http://{args.host}:{args.port}/v1/completions"
    out_csv  = pathlib.Path(f"results_{args.name}.csv")

    rows = []
    tech_tp = tech_fp = tech_fn = 0
    tact_tp = tact_fp = tact_fn = 0
    answered = 0

    with val_path.open() as fh:
        it = fh if args.limit is None else (next(fh) for _ in range(args.limit))
        for idx, line in enumerate(tqdm(it, total=args.limit, desc="Evaluating")):
            rec      = json.loads(line)
            prompt   = build_prompt(rec["input"])
            raw_resp = query(api_url, prompt, args.max_tokens, args.temperature)
            unwrapped= safe_extract_output(raw_resp)
            cleaned  = strip_prompt_echo(unwrapped)

            pred_tech = ids_by_regex(cleaned, TECH_ID_RE)
            pred_tact = ids_by_regex(cleaned, TACT_ID_RE)
            if (not pred_tech) and args.names_too:
                pred_tech |= ids_by_name(cleaned, TECHNIQUE_NAME2ID)
            if (not pred_tact) and args.names_too:
                pred_tact |= ids_by_name(cleaned, TACTIC_NAME2ID)

            gold_tech = ids_by_regex(rec["output"], TECH_ID_RE)
            gold_tact = ids_by_regex(rec["output"], TACT_ID_RE)

            tech_ok = bool(pred_tech & gold_tech)
            tact_ok = bool(pred_tact & gold_tact)
            both_ok = tech_ok and tact_ok
            if cleaned:
                answered += 1

            rows.append({
                "ID": idx,
                "model_prompt": prompt,
                "raw_model_output": unwrapped,
                "model_output": cleaned,
                "expected_technique": ",".join(sorted(gold_tech)),
                "expected_tactic": ",".join(sorted(gold_tact)),
                "actual_technique": ",".join(sorted(pred_tech)),
                "actual_tactic": ",".join(sorted(pred_tact)),
                "correct_technique": tech_ok,
                "correct_tactic": tact_ok,
                "both_correct": both_ok,
            })

            tech_tp += len(pred_tech & gold_tech)
            tech_fp += len(pred_tech - gold_tech)
            tech_fn += len(gold_tech - pred_tech)
            tact_tp += len(pred_tact & gold_tact)
            tact_fp += len(pred_tact - gold_tact)
            tact_fn += len(gold_tact - pred_tact)

    # Compute micro metrics
    tprec, trec, tf1 = micro(tech_tp, tech_fp, tech_fn)
    aprec, arec, af1 = micro(tact_tp, tact_fp, tact_fn)
    both_rate   = sum(r["both_correct"] for r in rows) / len(rows)
    answer_rate = answered / len(rows)

    # Print metrics to terminal
    print(f"Technique  P={tprec:.3%}  R={trec:.3%}  F1={tf1:.3%}")
    print(f"Tactic     P={aprec:.3%}  R={arec:.3%}  F1={af1:.3%}")
    print(f"Both correct={both_rate:.3%}  Answer rate={answer_rate:.3%}\n")

    # Write CSV + summary
    pd.DataFrame(rows).to_csv(out_csv, index=False)
    with out_csv.open("a") as fh:
        fh.write("# SUMMARY METRICS\n")
        fh.write(f"# Timestamp,{datetime.datetime.utcnow().isoformat()}Z\n")
        fh.write(f"# Technique_Precision,{tprec:.4f}\n")
        fh.write(f"# Technique_Recall,{trec:.4f}\n")
        fh.write(f"# Technique_F1,{tf1:.4f}\n")
        fh.write(f"# Tactic_Precision,{aprec:.4f}\n")
        fh.write(f"# Tactic_Recall,{arec:.4f}\n")
        fh.write(f"# Tactic_F1,{af1:.4f}\n")
        fh.write(f"# Both_Correct_Rate,{both_rate:.4f}\n")
        fh.write(f"# Answer_Rate,{answer_rate:.4f}\n")

    print(f"Saved results to: {out_csv.resolve()}")
    return 0

# ---------------------------------------------------------------------------- #
# 10. CLI
# ---------------------------------------------------------------------------- #
if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description="Evaluate LLM MITRE mappings and print metrics"
    )
    p.add_argument("--validation", default="valid.jsonl")
    p.add_argument("--name", required=True)
    p.add_argument("--host", default="localhost")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--max_tokens", type=int, default=128)
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--limit", type=int)
    p.add_argument("--tech-map")
    p.add_argument("--names-too", action="store_true",
                   help="Also use name-based lookup if no IDs found")
    sys.exit(main(p.parse_args()))
