#!/usr/bin/env python3
"""Build a training-ready CICIDS2017 CSV (separate file, original untouched).

Pipeline:
  1. load cicids2017_combined.csv (already clean: no NaN/inf/dupes)
  2. label encode -> 14 integer classes (BENIGN=0, attacks=1..13)
  3. StandardScaler on all 77 numeric features
  4. save to cicids2017_training_ready.csv
  5. save label mapping + scaler to .pkl files for later reuse

Note: SMOTE + train/val/test split are done at TRAINING time (not here),
to avoid data leakage.
"""
import os
import json
import pickle

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder

BASE = "/home/pritam/Desktop/Python/HOMEProject"
SRC = os.path.join(BASE, "cicids2017_combined.csv")
OUT = os.path.join(BASE, "cicids2017_training_ready.csv")
LABEL_MAP_JSON = os.path.join(BASE, "cicids2017_label_map.json")
SCALER_PKL = os.path.join(BASE, "cicids2017_scaler.pkl")


def main():
    print("=" * 70)
    print("BUILD TRAINING-READY DATASET")
    print("=" * 70)

    # 1. load
    print(f"\nLoading {os.path.basename(SRC)} ...")
    df = pd.read_csv(SRC)
    print(f"  shape: {df.shape}")
    print(f"  columns: {len(df.columns)}")

    # 2. label encoding
    print("\nLabel encoding ...")
    label_col = "Label"
    le = LabelEncoder()
    df["label"] = le.fit_transform(df[label_col])

    label_map = {name: int(idx) for idx, name in enumerate(le.classes_)}
    print(f"  classes: {len(label_map)}")
    for name, idx in sorted(label_map.items(), key=lambda x: x[1]):
        print(f"    {idx:>2d} -> {name}")

    # drop original string label, keep numeric label
    df = df.drop(columns=[label_col])

    # 3. separate features (all except 'label')
    feature_cols = [c for c in df.columns if c != "label"]
    X = df[feature_cols].astype(np.float64)
    y = df["label"].astype(np.int64)

    print(f"\nFeature matrix: {X.shape} (rows, features)")
    print(f"Label vector:   {y.shape}")

    # 4. scale features
    print("\nScaling features (StandardScaler) ...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    print("  scaling done")

    # 5. rebuild dataframe
    out_df = pd.DataFrame(X_scaled, columns=feature_cols)
    out_df["label"] = y.values

    print(f"\nFinal training-ready shape: {out_df.shape}")

    # 6. save
    print(f"\nSaving CSV -> {OUT}")
    out_df.to_csv(OUT, index=False)
    print(f"  file size: {os.path.getsize(OUT) / 1e6:.1f} MB")

    # 7. save label map + scaler
    with open(LABEL_MAP_JSON, "w") as f:
        json.dump(label_map, f, indent=2)
    with open(SCALER_PKL, "wb") as f:
        pickle.dump(scaler, f)
    print(f"Saved label map -> {LABEL_MAP_JSON}")
    print(f"Saved scaler    -> {SCALER_PKL}")

    # 8. verification
    print("\n" + "=" * 70)
    print("VERIFICATION")
    print("=" * 70)
    verify = pd.read_csv(OUT, nrows=1000)
    print(f"  columns: {len(verify.columns)}")
    print(f"  any NaN: {verify.isna().sum().sum()}")
    print(f"  label range: {verify['label'].min()}..{verify['label'].max()}")
    print(f"  feature mean (sample): {verify[feature_cols[0]].mean():.6f} (should be ~0)")
    print(f"  feature std  (sample): {verify[feature_cols[0]].std():.6f} (should be ~1)")
    print("\nDONE")


if __name__ == "__main__":
    main()
