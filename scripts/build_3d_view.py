"""
build_3d_view.py
================
Embed results/simulation_trace.json into the 3D viewer template, producing a
single self-contained page: visualization/sdn_3d_simulation.html

Open that file in any modern browser (it loads three.js from a CDN).

Usage:
    python scripts/run_sdn_simulation.py      # produce the trace
    python scripts/build_3d_view.py           # build the 3D page
"""

import argparse
import json
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


SCALE_TEMPLATE = os.path.join(ROOT, "visualization", "sdn_3d_scale_template.html")


def pick_template(trace: dict, template_path: str) -> str:
    """Large-network traces use the scale viewer unless a template was given explicitly."""
    if trace.get("meta", {}).get("mode") == "scale" and template_path.endswith("sdn_3d_template.html"):
        return SCALE_TEMPLATE
    return template_path


def build(trace_path: str, template_path: str, out_path: str) -> str:
    with open(trace_path) as f:
        trace = json.load(f)
    template_path = pick_template(trace, template_path)
    with open(template_path, encoding="utf-8") as f:
        template = f.read()
    payload = json.dumps(trace, separators=(",", ":")).replace("</", "<\\/")
    html = template.replace("__TRACE_JSON__", payload)
    if not html.lstrip().lower().startswith("<!doctype"):
        html = ("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\n"
                "</head>\n<body>\n" + html + "\n</body>\n</html>\n")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", default=os.path.join(ROOT, "results", "simulation_trace.json"))
    ap.add_argument("--template", default=os.path.join(ROOT, "visualization", "sdn_3d_template.html"))
    ap.add_argument("--out", default=os.path.join(ROOT, "visualization", "sdn_3d_simulation.html"))
    ap.add_argument("--fragment", action="store_true", help="Do not wrap in <html>/<body> (for hosts that add their own)")
    a = ap.parse_args()
    if a.fragment:
        with open(a.trace) as f:
            trace = json.load(f)
        with open(pick_template(trace, a.template), encoding="utf-8") as f:
            html = f.read().replace("__TRACE_JSON__", json.dumps(trace, separators=(",", ":")).replace("</", "<\\/"))
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"Wrote {a.out}")
    else:
        print(f"Wrote {build(a.trace, a.template, a.out)}")
