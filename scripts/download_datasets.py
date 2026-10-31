"""
download_datasets.py
====================
Download the public dataset files used in Module 9 into data/raw/.

    python scripts/download_datasets.py            # UNSW-NB15 train + test (~46 MB)
    python scripts/download_datasets.py --cicids   # also CICIDS2017 Friday DDoS day (~92 MB)

The files come from public GitHub mirrors. The official sources are
https://research.unsw.edu.au/projects/unsw-nb15-dataset and
https://www.unb.ca/cic/datasets/ids-2017.html
"""

import argparse
import os
import sys
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RAW = os.path.join(ROOT, "data", "raw")

UNSW = {
    "UNSW_NB15_training-set.csv": "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_training-set.csv",
    "UNSW_NB15_testing-set.csv": "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_testing-set.csv",
}
CICIDS = {
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": "https://raw.githubusercontent.com/SHUBHAMRAWAT-25/DDOS-attack-detection-using-random-forest-algorithm/main/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
}


def fetch(name: str, url: str) -> None:
    dest = os.path.join(RAW, name)
    if os.path.exists(dest) and os.path.getsize(dest) > 1_000_000:
        print(f"  already present: {name}")
        return
    print(f"  downloading {name} ...", end="", flush=True)

    def progress(blocks, block_size, total):
        if total > 0:
            pct = min(100, blocks * block_size * 100 // total)
            print(f"\r  downloading {name} ... {pct:3d}%", end="", flush=True)

    tmp = dest + ".part"
    urllib.request.urlretrieve(url, tmp, reporthook=progress)
    os.replace(tmp, dest)
    print(f"\r  downloaded {name} ({os.path.getsize(dest) / 1e6:.1f} MB)        ")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cicids", action="store_true", help="Also download the CICIDS2017 Friday DDoS file")
    args = ap.parse_args()
    os.makedirs(RAW, exist_ok=True)
    files = dict(UNSW)
    if args.cicids:
        files.update(CICIDS)
    print(f"Saving to {RAW}")
    try:
        for name, url in files.items():
            fetch(name, url)
    except Exception as e:  # network problems: say what to do instead
        print(f"\nDownload failed: {e}\nDownload the files manually from the official pages listed in "
              f"this script and place them in {RAW}")
        sys.exit(1)
    print("Done.")


if __name__ == "__main__":
    main()
