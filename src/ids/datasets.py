"""
datasets.py
===========
Load public intrusion-detection datasets and map them onto the project's
canonical 28-feature schema (see preprocess.ALL_CANONICAL_FEATURES).

Supported formats (detected automatically from the column names):

* UNSW-NB15, partitioned train/test CSVs
  (UNSW_NB15_training-set.csv, UNSW_NB15_testing-set.csv)
* UNSW-NB15, original 49-column CSVs
  (UNSW-NB15_1.csv ... _4.csv, which ship without a header row)
* CICIDS2017 "MachineLearningCVE" and "TrafficLabelling" CSVs
  (e.g. Wednesday-workingHours.pcap_ISCX.csv)
* Canonical CSVs that already use this project's column names plus `label`

Features a dataset does not measure (e.g. TTL in CICIDS2017) are returned as
NaN; NetworkPreprocessor imputes them with training medians.

Usage:
    from src.ids.datasets import load_dataset
    df, y, attack_cat = load_dataset("data/raw/UNSW_NB15_training-set.csv", max_rows=200_000)
"""

import glob
import logging
import os
from typing import Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd

from src.ids.preprocess import ALL_CANONICAL_FEATURES, CANONICAL_NUMERICAL_FEATURES

logger = logging.getLogger(__name__)

# Column order of the original UNSW-NB15_1..4.csv files (no header row in those files)
UNSW_RAW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl", "dttl",
    "sloss", "dloss", "service", "sload", "dload", "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb",
    "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "sjit", "djit", "stime", "ltime", "sintpkt",
    "dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
    "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label",
]

PORT_SERVICE = {80: "http", 8080: "http", 443: "ssl", 8443: "ssl", 53: "dns", 22: "ssh",
                21: "ftp", 20: "ftp-data", 25: "smtp", 110: "pop3", 143: "imap", 3389: "rdp"}
IANA_PROTO = {6: "tcp", 17: "udp", 1: "icmp"}


# ------------------------------------------------------------------------------
# Format detection
# ------------------------------------------------------------------------------
def _norm(cols: Iterable[str]) -> List[str]:
    return [str(c).strip().lower() for c in cols]


def detect_format(columns: Iterable[str]) -> str:
    cols = set(_norm(columns))
    if {"flow duration", "total fwd packets"} <= cols:
        return "cicids2017"
    if {"dur", "spkts", "dpkts", "sbytes"} <= cols and ("smean" in cols or "smeansz" in cols):
        return "unsw_nb15"
    if {"duration", "spkts", "sbytes", "proto"} <= cols and "label" in cols:
        return "canonical"
    raise ValueError(
        "Unrecognised dataset columns. Supported: CICIDS2017, UNSW-NB15, or a canonical CSV with "
        f"{ALL_CANONICAL_FEATURES[:4]}... and 'label'. First columns seen: {list(columns)[:8]}")


def _read_csv(path: str, nrows: Optional[int]) -> pd.DataFrame:
    """Read one CSV, adding the UNSW-NB15 header when the file has none."""
    head = pd.read_csv(path, nrows=5, low_memory=False, encoding="utf-8-sig", encoding_errors="replace")
    first = _norm(head.columns)
    looks_headerless = (len(head.columns) == len(UNSW_RAW_COLUMNS)
                        and not ({"dur", "proto", "label"} & set(first)))
    if looks_headerless:
        return pd.read_csv(path, header=None, names=UNSW_RAW_COLUMNS, nrows=nrows,
                           low_memory=False, encoding="utf-8-sig", encoding_errors="replace")
    return pd.read_csv(path, nrows=nrows, low_memory=False, encoding="utf-8-sig", encoding_errors="replace")


# ------------------------------------------------------------------------------
# Mappers
# ------------------------------------------------------------------------------
def _num(s: pd.Series) -> pd.Series:
    return pd.to_numeric(s, errors="coerce").replace([np.inf, -np.inf], np.nan)


def map_unsw_nb15(raw: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    r = raw.copy()
    r.columns = _norm(r.columns)
    r = r.rename(columns={"dur": "duration", "smean": "smeansz", "dmean": "dmeansz",
                          "response_body_len": "res_bdy_len"})
    out = pd.DataFrame(index=r.index)
    for col in CANONICAL_NUMERICAL_FEATURES:
        out[col] = _num(r[col]) if col in r.columns else np.nan
    dur = out["duration"].clip(lower=1e-6)
    out["packet_rate"] = (out["spkts"] + out["dpkts"]) / dur
    out["byte_rate"] = (out["sbytes"] + out["dbytes"]) / dur
    if out["tcprtt"].isna().all():
        out["tcprtt"] = out["synack"] + out["ackdat"]
    out["proto"] = r["proto"].astype(str).str.strip().str.lower()
    out["service"] = r.get("service", pd.Series("none", index=r.index)).astype(str).str.strip().str.lower().replace({"-": "none", "nan": "none"})

    label = _num(r["label"]).fillna(0).astype(int).clip(0, 1)
    cat = r.get("attack_cat", pd.Series("", index=r.index)).astype(str).str.strip()
    cat = cat.where(~cat.isin(["", "nan", "None"]), "Normal")
    cat = cat.where(label == 1, "Normal")
    return out, label, cat


def map_cicids2017(raw: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    r = raw.copy()
    r.columns = _norm(r.columns)
    # Some CICIDS2017 files repeat "fwd header length"; keep the first occurrence
    r = r.loc[:, ~pd.Index(r.columns).duplicated()]

    def col(name, default=np.nan):
        return _num(r[name]) if name in r.columns else pd.Series(default, index=r.index, dtype=float)

    out = pd.DataFrame(index=r.index)
    dur_s = col("flow duration") / 1e6                      # microseconds -> seconds
    out["duration"] = dur_s.clip(lower=1e-6)
    out["spkts"] = col("total fwd packets")
    out["dpkts"] = col("total backward packets")
    out["sbytes"] = col("total length of fwd packets")
    out["dbytes"] = col("total length of bwd packets")
    out["sttl"] = np.nan                                    # not measured by CICFlowMeter
    out["dttl"] = np.nan
    out["sloss"] = np.nan
    out["dloss"] = np.nan
    out["sload"] = out["sbytes"] * 8 / out["duration"]
    out["dload"] = out["dbytes"] * 8 / out["duration"]
    out["smeansz"] = col("fwd packet length mean")
    out["dmeansz"] = col("bwd packet length mean")
    out["trans_depth"] = np.nan
    out["res_bdy_len"] = np.nan
    out["sjit"] = col("fwd iat std") / 1000.0               # microseconds -> ms
    out["djit"] = col("bwd iat std") / 1000.0
    out["synack"] = np.nan
    out["ackdat"] = np.nan
    out["swin"] = col("init_win_bytes_forward")
    out["dwin"] = col("init_win_bytes_backward")
    out["stcpb"] = np.nan
    out["dtcpb"] = np.nan
    out["tcprtt"] = np.nan
    out["packet_rate"] = col("flow packets/s")
    out["byte_rate"] = col("flow bytes/s")

    if "protocol" in r.columns:
        out["proto"] = _num(r["protocol"]).map(IANA_PROTO).fillna("unknown")
    else:
        out["proto"] = "unknown"
    port = col("destination port")
    out["service"] = port.map(PORT_SERVICE).fillna("none")

    lab = r["label"].astype(str).str.strip()
    label = (lab.str.upper() != "BENIGN").astype(int)
    cat = lab.where(label == 1, "Normal")
    return out, label, cat


def map_canonical(raw: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    r = raw.copy()
    r.columns = _norm(r.columns)
    out = pd.DataFrame(index=r.index)
    for c in ALL_CANONICAL_FEATURES:
        out[c] = r[c] if c in r.columns else np.nan
    label = _num(r["label"]).fillna(0).astype(int).clip(0, 1)
    cat = r["attack_cat"].astype(str) if "attack_cat" in r.columns else label.map({0: "Normal", 1: "Attack"})
    return out, label, cat


MAPPERS = {"unsw_nb15": map_unsw_nb15, "cicids2017": map_cicids2017, "canonical": map_canonical}


# ------------------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------------------
def expand_paths(path: str) -> List[str]:
    """A file, a directory (all *.csv inside) or a glob pattern."""
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "*.csv")))
    elif any(ch in path for ch in "*?["):
        files = sorted(glob.glob(path))
    else:
        files = [path]
    files = [f for f in files if os.path.isfile(f)]
    if not files:
        raise FileNotFoundError(f"No CSV files found at {path}")
    return files


def load_dataset(
    path: str,
    fmt: str = "auto",
    max_rows: Optional[int] = None,
    rows_per_file: Optional[int] = None,
    random_state: int = 42,
) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    """
    Load one or more dataset CSVs and return (features, binary label, attack category).

    Args:
        path: CSV file, directory of CSVs, or glob (e.g. "data/raw/CICIDS2017/*.csv").
        fmt: "auto", "unsw_nb15", "cicids2017" or "canonical".
        max_rows: Stratified random sample of this many rows overall (keeps every
            attack category represented). Use it for multi-million-row datasets.
        rows_per_file: Read at most this many rows from each file (faster loading).
    """
    frames, labels, cats = [], [], []
    for f in expand_paths(path):
        raw = _read_csv(f, rows_per_file)
        kind = detect_format(raw.columns) if fmt == "auto" else fmt
        feats, y, cat = MAPPERS[kind](raw)
        logger.info("Loaded %s: %d rows as %s (%d attacks)", os.path.basename(f), len(feats), kind, int(y.sum()))
        frames.append(feats)
        labels.append(y)
        cats.append(cat)

    df = pd.concat(frames, ignore_index=True)
    y = pd.concat(labels, ignore_index=True).rename("label")
    cat = pd.concat(cats, ignore_index=True).rename("attack_cat")

    # Drop rows with no usable flow information at all
    keep = df[["duration", "spkts", "sbytes"]].notna().any(axis=1)
    df, y, cat = df[keep].reset_index(drop=True), y[keep].reset_index(drop=True), cat[keep].reset_index(drop=True)

    if max_rows and len(df) > max_rows:
        df, y, cat = stratified_sample(df, y, cat, max_rows, random_state)
    return df, y, cat


def stratified_sample(df, y, cat, n, random_state=42):
    """Sample n rows, proportional by attack category but at least a few of each."""
    rng = np.random.default_rng(random_state)
    groups = cat.groupby(cat).groups
    total = len(cat)
    chosen = []
    for _, idx in groups.items():
        idx = np.asarray(idx)
        k = max(min(len(idx), 50), int(round(n * len(idx) / total)))
        chosen.append(rng.choice(idx, size=min(k, len(idx)), replace=False))
    sel = np.concatenate(chosen)
    if len(sel) > n:
        sel = rng.choice(sel, size=n, replace=False)
    sel = np.sort(sel)
    return (df.iloc[sel].reset_index(drop=True), y.iloc[sel].reset_index(drop=True),
            cat.iloc[sel].reset_index(drop=True))


def summarize(y: pd.Series, cat: pd.Series) -> pd.DataFrame:
    return (pd.DataFrame({"attack_cat": cat, "label": y})
            .value_counts().rename("rows").reset_index().sort_values("rows", ascending=False))
