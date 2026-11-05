#!/usr/bin/env python3
"""Clean + merge the 8 CICIDS2017 MachineLearningCVE CSV files.

Handles:
  1. leading whitespace in column names
  2. duplicate 'Fwd Header Length' column (drop one)
  3. NaN / infinite values (replace inf with NaN, then drop rows with NaN)
  4. garbled label characters (Web Attack encoding)
  5. merge all 8 days into one combined CSV

Usage: python clean_merge_cicids2017.py
"""
import os
import re
import numpy as np
import pandas as pd

SRC_DIR = "/home/pritam/Desktop/Python/HOMEProject/MachineLearningCVE"
OUT_FILE = "/home/pritam/Desktop/Python/HOMEProject/cicids2017_combined.csv"

FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]


def clean_label(label: str) -> str:
    """Normalize attack labels, fix the Web Attack encoding issue."""
    label = label.strip()
    label = re.sub(r"\s+", " ", label)  # collapse multiple spaces
    # Fix garbled 'Web Attack \ufffd Brute Force' -> 'Web Attack Brute Force'
    label = label.replace("\ufffd", "").replace("  ", " ").strip()
    return label


def process_file(path):
    """Read one CSV, clean it, return a DataFrame."""
    df = pd.read_csv(path, skipinitialspace=True)

    # 1. drop duplicate columns (pandas renames 2nd occurrence to 'name.1')
    #    -> remove any '.1' (and higher) suffixed duplicates, keep first occurrence
    dup_cols = [c for c in df.columns if re.search(r"\.\d+$", c)]
    if dup_cols:
        df = df.drop(columns=dup_cols)
    # safety: drop any remaining true duplicates
    df = df.loc[:, ~df.columns.duplicated()]

    # 2. clean the label column
    df["Label"] = df["Label"].apply(clean_label)

    # 3. replace infinite with NaN, then drop rows with any NaN
    df = df.replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df = df.dropna()
    after = len(df)
    dropped = before - after

    return df, dropped


def main():
    frames = []
    total_raw = 0
    total_dropped = 0
    labels = {}

    print("=" * 70)
    print("CLEAN + MERGE CICIDS2017")
    print("=" * 70)

    for f in FILES:
        path = os.path.join(SRC_DIR, f)
        print(f"\nProcessing: {f}")
        df, dropped = process_file(path)
        total_raw += len(df) + dropped
        total_dropped += dropped
        print(f"  rows kept={len(df):>7d}  dropped (NaN/inf)={dropped}")

        # accumulate label counts
        for lbl, cnt in df["Label"].value_counts().items():
            labels[lbl] = labels.get(lbl, 0) + cnt

        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)

    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Total raw rows:      {total_raw}")
    print(f"Rows dropped:        {total_dropped}")
    print(f"Final combined rows: {len(combined)}")
    print(f"Final columns:       {len(combined.columns)}")

    print("\n--- Label distribution (final) ---")
    for lbl, cnt in sorted(labels.items(), key=lambda x: -x[1]):
        print(f"  {lbl:35s} {cnt:>8d}")

    print(f"\n--- Column count check ---")
    print(f"Expected: 78 unique columns (77 features + Label)")
    print(f"Actual:   {len(combined.columns)}")

    combined.to_csv(OUT_FILE, index=False)
    print(f"\nSaved combined CSV -> {OUT_FILE}")
    print(f"File size: {os.path.getsize(OUT_FILE) / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
