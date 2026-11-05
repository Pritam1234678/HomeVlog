#!/usr/bin/env python3
"""Clean + merge the 8 GeneratedLabelledFlows CSV files (with IP addresses).

This is the version the GNN needs — it includes Source IP / Destination IP /
Timestamp identity columns, unlike MachineLearningCVE (77 features + Label only).

Handles:
  1. leading whitespace in column names
  2. duplicate 'Fwd Header Length' column (drop one)
  3. NaN / infinite values
  4. garbled label characters (Web Attack encoding)
  5. merge all 8 days into one combined CSV with identity columns preserved

Usage: python clean_merge_generated.py
"""
import os
import re
import numpy as np
import pandas as pd

SRC_DIR = "/home/pritam/Desktop/Python/HOMEProject/TrafficLabelling "
OUT_FILE = "/home/pritam/Desktop/Python/HOMEProject/cicids2017_generated_combined.csv"

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


def clean_label(label):
    if not isinstance(label, str):
        return ""
    label = label.strip()
    label = re.sub(r"\s+", " ", label)
    label = label.replace("\ufffd", "").replace("\u0096", "-").replace("  ", " ").strip()
    return label


def process_file(path):
    # latin1 handles non-UTF8 bytes (e.g. 0x96 = en-dash in cp1252) present in WebAttacks
    df = pd.read_csv(path, skipinitialspace=True, low_memory=False, encoding="latin1")

    # drop duplicate columns (pandas renames 2nd occurrence to 'name.1')
    dup_cols = [c for c in df.columns if re.search(r"\.\d+$", c)]
    if dup_cols:
        df = df.drop(columns=dup_cols)
    df = df.loc[:, ~df.columns.duplicated()]

    # clean label
    df["Label"] = df["Label"].apply(clean_label)

    # NaN / inf handling
    df = df.replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df = df.dropna()
    dropped = before - len(df)

    return df, dropped


def main():
    frames = []
    total_raw = 0
    total_dropped = 0
    labels = {}

    print("=" * 70)
    print("CLEAN + MERGE GENERATED LABELLED FLOWS (with IPs)")
    print("=" * 70)

    for f in FILES:
        path = os.path.join(SRC_DIR, f)
        print(f"\nProcessing: {f}")
        df, dropped = process_file(path)
        total_raw += len(df) + dropped
        total_dropped += dropped
        print(f"  rows kept={len(df):>7d}  dropped (NaN/inf)={dropped}")
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

    print("\n--- Identity columns present ---")
    for c in ["Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp"]:
        print(f"  {c}: {'YES' if c in combined.columns else 'MISSING'}")

    print("\n--- Label distribution (final) ---")
    for lbl, cnt in sorted(labels.items(), key=lambda x: -x[1]):
        print(f"  {lbl:35s} {cnt:>8d}")

    combined.to_csv(OUT_FILE, index=False)
    print(f"\nSaved -> {OUT_FILE}")
    print(f"File size: {os.path.getsize(OUT_FILE) / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
