import re, json, gzip, pathlib

IN  = pathlib.Path("attack_qa_enterprise.jsonl")
OUT = pathlib.Path("attack_qa_enterprise.clean.jsonl")

link_pat   = re.compile(r"\[([^][]+)]\([^()]+?\)")     # [text](url)
cite_pat   = re.compile(r"\(Citation:[^)]+\)")          # (Citation: ...)
html_pat   = re.compile(r"&[#A-Za-z0-9]+;")             # basic HTML ent.

with IN.open("r", encoding="utf-8") as fin, \
     OUT.open("w", encoding="utf-8") as fout:
    for line in fin:
        obj = json.loads(line)
        text = obj["input"]           # only clean the activity sentence
        text = link_pat.sub(r"\1", text)      # keep visible text
        text = cite_pat.sub("", text)
        text = html_pat.sub("", text)
        obj["input"] = " ".join(text.split()) # normalise whitespace
        fout.write(json.dumps(obj, ensure_ascii=False) + "\n")

print(f"✓ cleaned → {OUT}")
