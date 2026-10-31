"""
preprocess.py
=============
Module for network flow feature extraction, schema harmonization, missing value
imputation, robust scaling, SMOTE-Tomek resampling, and dataset partitioning.

Harmonizes heterogeneous feature sets from CICIDS2017, UNSW-NB15, and real-time
OpenFlow switch PacketIn flow statistics into a canonical 28-feature representation.
"""

from typing import List, Tuple, Dict, Optional, Union
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import RobustScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from imblearn.combine import SMOTETomek
import joblib
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ==============================================================================
# CANONICAL FEATURE SPECIFICATION
# ==============================================================================
CANONICAL_NUMERICAL_FEATURES: List[str] = [
    "duration",         # Flow duration in seconds
    "spkts",            # Source-to-destination packet count
    "dpkts",            # Destination-to-source packet count
    "sbytes",           # Source-to-destination transaction bytes
    "dbytes",           # Destination-to-source transaction bytes
    "sttl",             # Source time to live
    "dttl",             # Destination time to live
    "sloss",            # Source packets retransmitted/dropped
    "dloss",            # Destination packets dropped
    "sload",            # Source bits per second
    "dload",            # Destination bits per second
    "smeansz",          # Mean packet size transmitted by source
    "dmeansz",          # Mean packet size transmitted by destination
    "trans_depth",      # Pipelined HTTP request depth
    "res_bdy_len",      # Content length of HTTP response
    "sjit",             # Source jitter (ms)
    "djit",             # Destination jitter (ms)
    "synack",           # TCP SYN-to-SYN-ACK setup time
    "ackdat",           # TCP SYN-ACK to ACK completion time
    "swin",             # Source TCP window advertisement
    "dwin",             # Destination TCP window advertisement
    "stcpb",            # Source TCP base sequence number
    "dtcpb",            # Destination TCP base sequence number
    "tcprtt",           # Round-trip time (synack + ackdat)
    "packet_rate",      # Total packets per second (spkts + dpkts)/duration
    "byte_rate",        # Total bytes per second (sbytes + dbytes)/duration
]

CANONICAL_CATEGORICAL_FEATURES: List[str] = [
    "proto",            # Protocol (tcp, udp, icmp, etc.)
    "service",          # Application layer service (http, dns, ssh, ssl, none)
]

ALL_CANONICAL_FEATURES = CANONICAL_NUMERICAL_FEATURES + CANONICAL_CATEGORICAL_FEATURES


class NetworkPreprocessor(BaseEstimator, TransformerMixin):
    """
    Standardized Network Feature Transformer.
    Implements fit/transform logic with RobustScaler for power-law traffic distributions,
    categorical encoders with unknown token handling, and serialization helpers.
    """

    def __init__(self, apply_smote: bool = False, random_state: int = 42):
        """
        Initialize Preprocessor.
        
        Args:
            apply_smote: Whether to apply SMOTE-TomekLinks during training fit.
            random_state: Deterministic seed for reproducible resampling.
        """
        self.apply_smote = apply_smote
        self.random_state = random_state
        self.scaler = RobustScaler(quantile_range=(5.0, 95.0))
        self.proto_encoder = LabelEncoder()
        self.service_encoder = LabelEncoder()
        self.fitted = False
        self.known_protos: List[str] = []
        self.known_services: List[str] = []
        self.feature_medians_: Dict[str, float] = {}

    def _impute_and_clean(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean raw DataFrame: handle NaNs, infs, negative rates, and compute derived rates.
        """
        df_clean = df.copy()

        # Replace infinite values with NaN and impute medians
        df_clean = df_clean.replace([np.inf, -np.inf], np.nan)
        
        # Ensure non-negative duration with small epsilon to prevent div-by-zero
        if "duration" in df_clean.columns:
            df_clean["duration"] = np.maximum(df_clean["duration"].fillna(0.001), 0.0001)

        # Compute derived rates if missing
        if "packet_rate" not in df_clean.columns and "spkts" in df_clean.columns and "dpkts" in df_clean.columns:
            df_clean["packet_rate"] = (df_clean["spkts"] + df_clean["dpkts"]) / df_clean["duration"]
            
        if "byte_rate" not in df_clean.columns and "sbytes" in df_clean.columns and "dbytes" in df_clean.columns:
            df_clean["byte_rate"] = (df_clean["sbytes"] + df_clean["dbytes"]) / df_clean["duration"]

        if "tcprtt" not in df_clean.columns and "synack" in df_clean.columns and "ackdat" in df_clean.columns:
            df_clean["tcprtt"] = df_clean["synack"] + df_clean["ackdat"]

        # Fill missing numerical values. Once fitted, unobserved values (NaN) are
        # imputed with the training median so that "not measured" is not confused
        # with "measured as zero" (e.g. a controller that only sees one direction).
        medians = getattr(self, "feature_medians_", None) or {}
        for col in CANONICAL_NUMERICAL_FEATURES:
            fill = float(medians.get(col, 0.0))
            if col in df_clean.columns:
                df_clean[col] = pd.to_numeric(df_clean[col], errors="coerce").fillna(fill)
            else:
                df_clean[col] = fill

        # Fill missing categorical columns
        if "proto" in df_clean.columns:
            df_clean["proto"] = df_clean["proto"].astype(str).str.lower().fillna("unknown")
        else:
            df_clean["proto"] = "unknown"

        if "service" in df_clean.columns:
            df_clean["service"] = df_clean["service"].astype(str).str.lower().fillna("none")
        else:
            df_clean["service"] = "none"

        return df_clean

    def fit(self, X: pd.DataFrame, y: Optional[Union[pd.Series, np.ndarray]] = None) -> "NetworkPreprocessor":
        """
        Fit numerical scaler and categorical encoders on training dataset.
        """
        # Per-feature medians of the observed (non-missing) training values. They
        # fill gaps both here and at inference, so "not measured" (NaN, e.g. TTL in
        # CICIDS2017 or reverse-direction fields seen by the controller) is never
        # confused with a measured zero.
        self.feature_medians_ = {}
        for c in CANONICAL_NUMERICAL_FEATURES:
            if c in X.columns:
                vals = pd.to_numeric(X[c], errors="coerce").replace([np.inf, -np.inf], np.nan)
                med = vals.median()
                self.feature_medians_[c] = float(med) if pd.notna(med) else 0.0
        df_clean = self._impute_and_clean(X)
        for c in CANONICAL_NUMERICAL_FEATURES:
            self.feature_medians_.setdefault(c, float(df_clean[c].median()))

        # Fit RobustScaler on numerical features
        num_data = df_clean[CANONICAL_NUMERICAL_FEATURES].values
        self.scaler.fit(num_data)

        # Fit categorical encoders
        self.known_protos = list(df_clean["proto"].unique()) + ["unknown"]
        self.proto_encoder.fit(self.known_protos)

        self.known_services = list(df_clean["service"].unique()) + ["none", "unknown"]
        self.service_encoder.fit(self.known_services)

        self.fitted = True
        logger.info("NetworkPreprocessor successfully fitted on %d samples across %d features.", len(df_clean), len(ALL_CANONICAL_FEATURES))
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """
        Transform raw network DataFrame into scaled numpy feature matrix.
        """
        if not self.fitted:
            raise RuntimeError("NetworkPreprocessor must be fitted before calling transform().")

        df_clean = self._impute_and_clean(X)

        # Scale numerical features
        num_scaled = self.scaler.transform(df_clean[CANONICAL_NUMERICAL_FEATURES].values)

        # Encode categorical features with out-of-vocabulary fallback
        proto_series = df_clean["proto"].map(
            lambda x: x if x in self.proto_encoder.classes_ else "unknown"
        )
        proto_encoded = self.proto_encoder.transform(proto_series).reshape(-1, 1)

        service_series = df_clean["service"].map(
            lambda x: x if x in self.service_encoder.classes_ else "unknown"
        )
        service_encoded = self.service_encoder.transform(service_series).reshape(-1, 1)

        # Concatenate into final feature matrix
        X_trans = np.hstack([num_scaled, proto_encoded, service_encoded])
        return X_trans

    def fit_transform_resample(
        self, X: pd.DataFrame, y: Union[pd.Series, np.ndarray]
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Fit preprocessor, transform features, and apply SMOTE-Tomek balancing if enabled.
        """
        self.fit(X, y)
        X_trans = self.transform(X)
        y_arr = np.array(y).astype(int)

        if self.apply_smote:
            logger.info("Applying SMOTE-TomekLinks resampling on training set (Original: %d samples)...", len(y_arr))
            smt = SMOTETomek(random_state=self.random_state)
            X_res, y_res = smt.fit_resample(X_trans, y_arr)
            logger.info("Resampling completed. Balanced dataset size: %d samples (Class 0: %d, Class 1: %d)",
                        len(y_res), np.sum(y_res == 0), np.sum(y_res == 1))
            return X_res, y_res

        return X_trans, y_arr

    def save(self, filepath: str) -> None:
        """Serialize preprocessor state to disk."""
        joblib.dump(self, filepath)
        logger.info("Saved fitted NetworkPreprocessor to %s", filepath)

    @classmethod
    def load(cls, filepath: str) -> "NetworkPreprocessor":
        """Deserialize preprocessor from disk."""
        obj = joblib.load(filepath)
        if not isinstance(obj, NetworkPreprocessor):
            raise TypeError(f"Loaded object is not an instance of NetworkPreprocessor: {type(obj)}")
        logger.info("Loaded NetworkPreprocessor from %s", filepath)
        return obj


def generate_synthetic_flow_dataset(
    n_samples: int = 10000, attack_ratio: float = 0.2, random_state: int = 42
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Generate realistic synthetic network flow dataset mirroring CICIDS2017 & UNSW-NB15
    for rapid testing, benchmarking, and demonstration.

    Simulates:
    - Benign traffic (HTTP, DNS, normal payload distributions, low jitter, normal TTL).
    - DoS / DDoS (High packet rate, asymmetric sload vs dload, high loss, uniform packet sizes).
    - Port Scan / Reconnaissance (Short duration, zero payload, high SYN rate, failed handshakes).
    - Infiltration / Web Exploits (High trans_depth, abnormal res_bdy_len, high TCP window variance).
    """
    np.random.seed(random_state)
    n_attacks = int(n_samples * attack_ratio)
    n_benign = n_samples - n_attacks

    data_rows = []
    labels = []

    # 1. Generate Benign Traffic
    for _ in range(n_benign):
        dur = float(np.random.exponential(scale=2.5) + 0.01)
        spkts = int(np.random.poisson(lam=15) + 2)
        dpkts = int(np.random.poisson(lam=20) + 2)
        sbytes = int(spkts * np.random.normal(loc=120, scale=30) + 64)
        dbytes = int(dpkts * np.random.normal(loc=800, scale=200) + 128)
        
        row = {
            "duration": dur,
            "spkts": max(spkts, 1),
            "dpkts": max(dpkts, 1),
            "sbytes": max(sbytes, 64),
            "dbytes": max(dbytes, 64),
            "sttl": int(np.random.choice([64, 128])),
            "dttl": int(np.random.choice([64, 56])),
            "sloss": int(np.random.binomial(n=spkts, p=0.01)),
            "dloss": int(np.random.binomial(n=dpkts, p=0.01)),
            "sload": float((sbytes * 8) / dur),
            "dload": float((dbytes * 8) / dur),
            "smeansz": float(sbytes / max(spkts, 1)),
            "dmeansz": float(dbytes / max(dpkts, 1)),
            "trans_depth": int(np.random.choice([1, 2, 3], p=[0.8, 0.15, 0.05])),
            "res_bdy_len": int(np.random.exponential(scale=1500)),
            "sjit": float(np.random.exponential(scale=5.0)),
            "djit": float(np.random.exponential(scale=6.0)),
            "synack": float(np.random.uniform(0.01, 0.05)),
            "ackdat": float(np.random.uniform(0.01, 0.04)),
            "swin": 65535,
            "dwin": 65535,
            "stcpb": int(np.random.randint(100000, 99999999)),
            "dtcpb": int(np.random.randint(100000, 99999999)),
            "proto": np.random.choice(["tcp", "udp", "icmp"], p=[0.75, 0.20, 0.05]),
            "service": np.random.choice(["http", "dns", "ssl", "ssh", "none"], p=[0.45, 0.25, 0.15, 0.05, 0.10]),
        }
        data_rows.append(row)
        labels.append(0)

    # 2. Generate Attack Traffic
    attack_types = ["dos_ddos", "port_scan", "web_exploit", "infiltration"]
    for _ in range(n_attacks):
        atk = np.random.choice(attack_types, p=[0.5, 0.25, 0.15, 0.10])
        
        if atk == "dos_ddos":
            dur = float(np.random.uniform(0.1, 1.0))
            spkts = int(np.random.randint(500, 3000))
            dpkts = int(np.random.randint(0, 5)) # Server overwhelmed / unresponsive
            sbytes = spkts * int(np.random.choice([64, 128, 1400]))
            dbytes = dpkts * 64
            proto = np.random.choice(["tcp", "udp", "icmp"], p=[0.4, 0.5, 0.1])
            service = "none" if proto != "tcp" else "http"
            synack = 0.0
            ackdat = 0.0
            res_bdy_len = 0
            trans_depth = 0
        elif atk == "port_scan":
            dur = float(np.random.uniform(0.001, 0.05))
            spkts = int(np.random.randint(1, 3))
            dpkts = 0
            sbytes = spkts * 40 # SYN only
            dbytes = 0
            proto = "tcp"
            service = "none"
            synack = 0.0
            ackdat = 0.0
            res_bdy_len = 0
            trans_depth = 0
        else: # web_exploit or infiltration
            dur = float(np.random.uniform(1.0, 5.0))
            spkts = int(np.random.randint(20, 80))
            dpkts = int(np.random.randint(15, 60))
            sbytes = int(np.random.randint(3000, 15000)) # Malicious payload injection
            dbytes = int(np.random.randint(500, 2000))
            proto = "tcp"
            service = np.random.choice(["http", "ssl"])
            synack = float(np.random.uniform(0.02, 0.08))
            ackdat = float(np.random.uniform(0.02, 0.08))
            res_bdy_len = int(np.random.randint(5000, 50000))
            trans_depth = int(np.random.randint(4, 10))

        row = {
            "duration": dur,
            "spkts": max(spkts, 1),
            "dpkts": max(dpkts, 0),
            "sbytes": max(sbytes, 40),
            "dbytes": max(dbytes, 0),
            "sttl": int(np.random.choice([64, 255, 32])),
            "dttl": int(np.random.choice([64, 0])),
            "sloss": int(np.random.binomial(n=max(spkts, 1), p=0.1)),
            "dloss": int(np.random.binomial(n=max(dpkts, 1), p=0.05)),
            "sload": float((sbytes * 8) / dur),
            "dload": float((dbytes * 8) / dur),
            "smeansz": float(sbytes / max(spkts, 1)),
            "dmeansz": float(dbytes / max(dpkts, 1)) if dpkts > 0 else 0.0,
            "trans_depth": trans_depth,
            "res_bdy_len": res_bdy_len,
            "sjit": float(np.random.exponential(scale=15.0)),
            "djit": float(np.random.exponential(scale=20.0)),
            "synack": synack,
            "ackdat": ackdat,
            "swin": int(np.random.choice([0, 1024, 65535])),
            "dwin": int(np.random.choice([0, 65535])),
            "stcpb": int(np.random.randint(100000, 99999999)),
            "dtcpb": int(np.random.randint(100000, 99999999)),
            "proto": proto,
            "service": service,
        }
        data_rows.append(row)
        labels.append(1)

    df = pd.DataFrame(data_rows)
    # Derived canonical features (the 28-feature schema includes these three)
    df["tcprtt"] = df["synack"] + df["ackdat"]
    df["packet_rate"] = (df["spkts"] + df["dpkts"]) / df["duration"]
    df["byte_rate"] = (df["sbytes"] + df["dbytes"]) / df["duration"]
    y = pd.Series(labels, name="label")
    return df, y
