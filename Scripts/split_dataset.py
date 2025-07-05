#!/usr/bin/env python3
"""
Split a JSONL dataset into training and validation files.

Example
-------
python split_dataset.py data/processed/attack_qa_enterprise.clean.jsonl \
        --train_out data/splits/train.jsonl \
        --valid_out data/splits/valid.jsonl
"""
import argparse
import json
import random
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Split .jsonl dataset into train/valid sets.")
    parser.add_argument("input_file", type=Path, help="Path to source .jsonl file")
    parser.add_argument("--train_out", type=Path, default="train.jsonl",
                        help="Output path for the training split")
    parser.add_argument("--valid_out", type=Path, default="valid.jsonl",
                        help="Output path for the validation split")
    parser.add_argument("--train_ratio", type=float, default=0.8,
                        help="Proportion of records to put in the training split")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    random.seed(args.seed)

    # Load every JSON object in the source file
    with args.input_file.open("r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f]

    # Shuffle once so the split is independent of original ordering
    random.shuffle(records)

    split_idx = int(len(records) * args.train_ratio)
    train_records = records[:split_idx]
    valid_records = records[split_idx:]

    # Ensure output directories exist
    args.train_out.parent.mkdir(parents=True, exist_ok=True)
    args.valid_out.parent.mkdir(parents=True, exist_ok=True)

    # Write the two files
    for path, subset in ((args.train_out, train_records), (args.valid_out, valid_records)):
        with path.open("w", encoding="utf-8") as f:
            for rec in subset:
                json.dump(rec, f)
                f.write("\n")

    print(f"✔  Wrote {len(train_records)} training and {len(valid_records)} validation examples.")


if __name__ == "__main__":
    main()
