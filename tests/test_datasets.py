"""
test_datasets.py
================
Dataset loader: format detection and mapping of UNSW-NB15 (both layouts) and
CICIDS2017 onto the canonical 28-feature schema, using small fixture files with
the real column layouts.
"""

import numpy as np
import pandas as pd

from src.ids.datasets import load_dataset, detect_format, UNSW_RAW_COLUMNS
from src.ids.preprocess import ALL_CANONICAL_FEATURES, NetworkPreprocessor
from src.ids.train_rf import CalibratedRFModel

UNSW_SET_COLUMNS = ("id,dur,proto,service,state,spkts,dpkts,sbytes,dbytes,rate,sttl,dttl,sload,dload,sloss,dloss,"
                    "sinpkt,dinpkt,sjit,djit,swin,stcpb,dtcpb,dwin,tcprtt,synack,ackdat,smean,dmean,trans_depth,"
                    "response_body_len,ct_srv_src,ct_state_ttl,ct_dst_ltm,ct_src_dport_ltm,ct_dst_sport_ltm,"
                    "ct_dst_src_ltm,is_ftp_login,ct_ftp_cmd,ct_flw_http_mthd,ct_src_ltm,ct_srv_dst,"
                    "is_sm_ips_ports,attack_cat,label").split(",")

CIC_COLUMNS = [" Destination Port", " Flow Duration", " Total Fwd Packets", " Total Backward Packets",
               "Total Length of Fwd Packets", " Total Length of Bwd Packets", " Fwd Packet Length Mean",
               " Bwd Packet Length Mean", "Flow Bytes/s", " Flow Packets/s", " Fwd IAT Std", " Bwd IAT Std",
               "Init_Win_bytes_forward", " Init_Win_bytes_backward", " Label"]


def _unsw_set(path, n=120, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        atk = i % 3 == 0
        r = {c: float(rng.uniform(0, 10)) for c in UNSW_SET_COLUMNS}
        r.update(id=i, proto="tcp" if i % 2 else "udp", service="-" if i % 4 else "http", state="FIN",
                 spkts=int(rng.integers(2, 50)) * (20 if atk else 1), dpkts=int(rng.integers(0, 40)),
                 sttl=254 if atk else 31, attack_cat="Exploits" if atk else "Normal", label=int(atk))
        rows.append(r)
    pd.DataFrame(rows, columns=UNSW_SET_COLUMNS).to_csv(path, index=False, encoding="utf-8-sig")


def _cic(path, n=120, seed=1):
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        atk = i % 2 == 0
        rows.append([80, int(rng.integers(1000, 5_000_000)), int(rng.integers(1, 9)) * (30 if atk else 1),
                     int(rng.integers(0, 9)), 1200.0, 3000.0, 60.0, 400.0,
                     "Infinity" if i == 5 else 1e5, 50.0, 1000.0, 2000.0, 8192, 229,
                     "DDoS" if atk else "BENIGN"])
    pd.DataFrame(rows, columns=CIC_COLUMNS).to_csv(path, index=False)


def test_detect_format():
    assert detect_format(UNSW_SET_COLUMNS) == "unsw_nb15"
    assert detect_format(UNSW_RAW_COLUMNS) == "unsw_nb15"
    assert detect_format(CIC_COLUMNS) == "cicids2017"


def test_unsw_partitioned_set_maps_to_schema(tmp_path):
    f = tmp_path / "UNSW_NB15_training-set.csv"
    _unsw_set(f)
    df, y, cat = load_dataset(str(f))
    assert list(df.columns) == ALL_CANONICAL_FEATURES
    assert len(df) == 120 and int(y.sum()) == 40
    assert set(cat) == {"Normal", "Exploits"}
    assert (df["service"] == "none").sum() > 0          # "-" mapped to "none"
    assert df["smeansz"].notna().all()                  # smean -> smeansz


def test_unsw_headerless_original_files(tmp_path):
    f = tmp_path / "UNSW-NB15_1.csv"
    rng = np.random.default_rng(3)
    rows = []
    for i in range(60):
        r = {c: float(rng.uniform(1, 5)) for c in UNSW_RAW_COLUMNS}
        r.update(srcip="10.0.0.1", dstip="10.0.0.2", proto="tcp", state="CON", service="-",
                 attack_cat="" if i % 2 else "DoS", label=0 if i % 2 else 1)
        rows.append(r)
    pd.DataFrame(rows, columns=UNSW_RAW_COLUMNS).to_csv(f, index=False, header=False)
    df, y, cat = load_dataset(str(f))
    assert len(df) == 60 and int(y.sum()) == 30
    assert set(cat) == {"Normal", "DoS"}


def test_cicids2017_mapping_units_and_labels(tmp_path):
    f = tmp_path / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    _cic(f)
    df, y, cat = load_dataset(str(f))
    assert int(y.sum()) == 60
    assert df["duration"].max() <= 5.0                  # microseconds converted to seconds
    assert df["sttl"].isna().all()                      # not measured by CICFlowMeter
    assert not np.isinf(df["byte_rate"].dropna()).any() # "Infinity" handled
    assert (df["service"] == "http").all()              # port 80


def test_directory_and_sampling(tmp_path):
    folder = tmp_path / "multi_file_dataset"
    folder.mkdir(exist_ok=True)
    _unsw_set(folder / "a.csv", seed=1)
    _unsw_set(folder / "b.csv", seed=2)
    df, y, cat = load_dataset(str(folder), max_rows=100)
    assert len(df) == 100
    assert set(cat) == {"Normal", "Exploits"}


def test_trains_on_mapped_cicids_with_missing_features(tmp_path):
    f = tmp_path / "cic.csv"
    _cic(f, n=200)
    df, y, _ = load_dataset(str(f))
    pre = NetworkPreprocessor(apply_smote=False)
    X, yy = pre.fit_transform_resample(df, y)
    assert not np.isnan(X).any()
    model = CalibratedRFModel(n_estimators=20, cv_folds=2).fit(X, yy, preprocessor=pre)
    p = model.predict_confidence(X)
    assert ((p >= 0.5) == yy.astype(bool)).mean() > 0.9
