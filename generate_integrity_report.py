#!/usr/bin/env python3
"""
csv_integrity_check.py

Two-level integrity check for a CSV file:

Level 1 (file-level):
  - SHA-256 hash of the raw file bytes
  - file size (bytes)

Level 2 (data-level, robust to line-ending differences and some harmless text differences):
  - row/column counts
  - header list
  - per-column stats:
      * non-empty count, empty count
      * numeric: min/max/mean (if parseable)
      * date/time: min/max (if parseable as ISO-ish)
      * text: min/max length, distinct count (capped), sample hash of distincts
  - order-independent dataset fingerprint:
      hash over sorted per-row fingerprints (stable across row order changes)

Outputs:
  - A timestamped .txt report file, and a stable "latest.txt" copy.

Usage:
  python csv_integrity_check.py path/to/file.csv
  python csv_integrity_check.py path/to/file.csv --outdir results
  python csv_integrity_check.py path/to/file.csv --delimiter "," --encoding "utf-8"

Notes:
  - The "data-level" fingerprint depends on normalization rules. It ignores leading/trailing
    whitespace and normalizes line endings implicitly by parsing CSV.
  - If you need strict byte-for-byte equality, rely on Level 1 SHA-256.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# ----------------------------
# Helpers
# ----------------------------

def utc_timestamp() -> str:
    # e.g., 20260209T134455Z
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def sha256_file(path: str) -> Tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            total += len(chunk)
            h.update(chunk)
    return h.hexdigest(), total

def normalize_cell(s: str) -> str:
    # Normalization aimed at semantic checks, not byte-identity.
    # - strip whitespace
    # - normalize internal Windows line endings that may appear in quoted cells
    # - keep case as-is (change if you want case-insensitive behavior)
    if s is None:
        return ""
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    return s.strip()

def classify_missing(s: str) -> Optional[str]:
    v = normalize_cell(s)
    if v == "":
        return "EMPTY"
    v_upper = v.upper()
    if v_upper in ("NA", "N/A", "NULL"):
        return v_upper
    return None

def try_parse_float(s: str) -> Optional[float]:
    if s == "":
        return None
    # Remove common thousand separators cautiously (only if it looks safe)
    # If your data uses commas as decimal separators, remove this block.
    s2 = s
    if s2.count(",") > 0 and s2.count(".") == 0:
        # likely commas are decimals or separators; don't guess
        pass
    # Try direct float
    try:
        return float(s2)
    except Exception:
        return None

def try_parse_iso_datetime(s: str) -> Optional[datetime]:
    """
    Attempt to parse common ISO-ish date/datetime forms without external deps.
    Handles:
      YYYY-MM-DD
      YYYY-MM-DD HH:MM[:SS]
      YYYY-MM-DDTHH:MM[:SS]
    Does not handle locale-specific formats.
    """
    if s == "":
        return None
    s = s.replace("T", " ").strip()
    # date only
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    return None

def hash_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def row_fingerprint(row: List[str]) -> bytes:
    """
    Create a stable per-row fingerprint based on normalized cell values.
    Uses a delimiter unlikely to appear; and includes column boundaries.
    """
    normed = [normalize_cell(x) for x in row]
    joined = "\x1f".join(normed)  # Unit Separator
    return hashlib.sha256(joined.encode("utf-8")).digest()

# ----------------------------
# Data-level profiling
# ----------------------------

class ColStats:
    def __init__(self, name: str):
        self.name = name
        self.non_empty = 0
        self.empty = 0
        self.missing_total = 0
        self.missing_types: Dict[str, int] = {}

        # text stats
        self.min_len: Optional[int] = None
        self.max_len: Optional[int] = None

        # numeric stats (if any)
        self.num_count = 0
        self.num_sum = 0.0
        self.num_min: Optional[float] = None
        self.num_max: Optional[float] = None

        # datetime stats (if any)
        self.dt_count = 0
        self.dt_min: Optional[datetime] = None
        self.dt_max: Optional[datetime] = None

        # distinct tracking (capped to avoid huge memory)
        self.distinct_cap = 20000
        self.distinct: Optional[set] = set()

    def add(self, value: str):
        missing_type = classify_missing(value)
        if missing_type is not None:
            self.missing_total += 1
            self.missing_types[missing_type] = self.missing_types.get(missing_type, 0) + 1
            if missing_type == "EMPTY":
                self.empty += 1
            return
        v = normalize_cell(value)
        self.non_empty += 1

        # text lengths
        L = len(v)
        self.min_len = L if self.min_len is None else min(self.min_len, L)
        self.max_len = L if self.max_len is None else max(self.max_len, L)

        # distincts (cap)
        if self.distinct is not None:
            self.distinct.add(v)
            if len(self.distinct) > self.distinct_cap:
                # stop tracking to protect memory
                self.distinct = None

        # numeric?
        f = try_parse_float(v)
        if f is not None:
            self.num_count += 1
            self.num_sum += f
            self.num_min = f if self.num_min is None else min(self.num_min, f)
            self.num_max = f if self.num_max is None else max(self.num_max, f)

        # datetime?
        dt = try_parse_iso_datetime(v)
        if dt is not None:
            self.dt_count += 1
            self.dt_min = dt if self.dt_min is None else min(self.dt_min, dt)
            self.dt_max = dt if self.dt_max is None else max(self.dt_max, dt)

    def distinct_summary_hash(self) -> str:
        """
        If distinct tracking is available, hash the sorted distinct values.
        If capped out, return a sentinel.
        """
        if self.distinct is None:
            return "DISTINCT_CAPPED"
        # order-independent
        h = hashlib.sha256()
        for item in sorted(self.distinct):
            h.update(item.encode("utf-8"))
            h.update(b"\n")
        return h.hexdigest()

    def to_lines(self) -> List[str]:
        lines = []
        lines.append(f"  - {self.name}")
        lines.append(f"      non_empty: {self.non_empty}")
        lines.append(f"      empty: {self.empty}")
        lines.append(f"      missing_total: {self.missing_total}")
        if self.missing_total == 0:
            lines.append("      missing_types: (none)")
        else:
            lines.append("      missing_types:")
            for key in sorted(self.missing_types):
                lines.append(f"        - {key}: {self.missing_types[key]}")
        if self.min_len is not None:
            lines.append(f"      text_len_min: {self.min_len}")
            lines.append(f"      text_len_max: {self.max_len}")
        else:
            lines.append(f"      text_len_min: (n/a)")
            lines.append(f"      text_len_max: (n/a)")

        if self.num_count > 0:
            mean = self.num_sum / self.num_count
            lines.append(f"      numeric_count: {self.num_count}")
            lines.append(f"      numeric_min: {self.num_min}")
            lines.append(f"      numeric_max: {self.num_max}")
            lines.append(f"      numeric_mean: {mean}")
        else:
            lines.append(f"      numeric_count: 0")

        if self.dt_count > 0:
            lines.append(f"      datetime_count: {self.dt_count}")
            lines.append(f"      datetime_min: {self.dt_min}")
            lines.append(f"      datetime_max: {self.dt_max}")
        else:
            lines.append(f"      datetime_count: 0")
        return lines

def profile_csv(
    path: str,
    delimiter: str = ",",
    encoding: str = "utf-8",
    quotechar: str = '"',
) -> Dict[str, object]:
    """
    Returns a dict with schema/stats, order-dependent dataset hash,
    order-independent dataset fingerprint, and per-column hashes.
    """
    # Read with newline="" per csv module recommendation
    with open(path, "r", encoding=encoding, newline="") as f:
        reader = csv.reader(f, delimiter=delimiter, quotechar=quotechar)
        try:
            header = next(reader)
        except StopIteration:
            # Empty file
            return {
                "header": [],
                "n_cols": 0,
                "n_rows": 0,
                "col_stats": [],
                "dataset_hash": hashlib.sha256(b"EMPTY").hexdigest(),
                "dataset_fingerprint": hashlib.sha256(b"EMPTY").hexdigest(),
                "column_hashes": [],
            }

        header = [normalize_cell(h) for h in header]
        n_cols = len(header)
        stats = [ColStats(name=h if h != "" else f"(col_{i+1})") for i, h in enumerate(header)]

        # Build order-dependent dataset hash (normalized, order-sensitive)
        dataset_hash = hashlib.sha256()

        # Build order-independent dataset fingerprint:
        # - compute per-row sha256 digest bytes
        # - store digests, sort, hash concatenation
        # This is robust to row order changes but uses memory proportional to row count.
        row_digests: List[bytes] = []
        n_rows = 0

        # Per-column hashes (order-sensitive)
        col_hashes = [hashlib.sha256() for _ in range(n_cols)]

        for row in reader:
            n_rows += 1
            # Pad/trim row to header width for stability
            if len(row) < n_cols:
                row = row + [""] * (n_cols - len(row))
            elif len(row) > n_cols:
                row = row[:n_cols]

            # Update dataset hash and per-column hashes
            normed = [normalize_cell(x) for x in row]
            dataset_hash.update("\x1f".join(normed).encode("utf-8"))
            dataset_hash.update(b"\n")

            for i in range(n_cols):
                stats[i].add(row[i])
                col_hashes[i].update(normed[i].encode("utf-8"))
                col_hashes[i].update(b"\n")

            row_digests.append(row_fingerprint(row))

        row_digests.sort()
        h = hashlib.sha256()
        for d in row_digests:
            h.update(d)
        dataset_fp = h.hexdigest()
        dataset_hash_hex = dataset_hash.hexdigest()
        column_hashes_hex = [h.hexdigest() for h in col_hashes]

        return {
            "header": header,
            "n_cols": n_cols,
            "n_rows": n_rows,
            "col_stats": stats,
            "dataset_hash": dataset_hash_hex,
            "dataset_fingerprint": dataset_fp,
            "column_hashes": column_hashes_hex,
        }

# ----------------------------
# Reporting
# ----------------------------

def build_report_lines(
    csv_path: str,
    delimiter: str,
    encoding: str,
    quotechar: str,
) -> Tuple[List[str], str, str]:
    ts = utc_timestamp()
    base = os.path.basename(csv_path)
    safe_base = "".join(c if c.isalnum() or c in ("-", "_", ".", " ") else "_" for c in base)

    # Level 1
    file_hash, file_size = sha256_file(csv_path)

    # Level 2
    profile = profile_csv(csv_path, delimiter=delimiter, encoding=encoding, quotechar=quotechar)

    lines: List[str] = []
    lines.append("CSV INTEGRITY REPORT")
    lines.append(f"timestamp_utc: {ts}")
    lines.append(f"file: {os.path.abspath(csv_path)}")
    lines.append("")
    lines.append("HUMAN-READABLE")
    lines.append(f"encoding: {encoding}")
    lines.append(f"delimiter: {repr(delimiter)}")
    lines.append(f"quotechar: {repr(quotechar)}")
    lines.append(f"n_rows: {profile['n_rows']}")
    lines.append(f"n_cols: {profile['n_cols']}")
    lines.append("header:")
    for h in profile["header"]:
        lines.append(f"  - {h}")
    lines.append("")
    lines.append("column_stats:")
    for st in profile["col_stats"]:
        lines.extend(st.to_lines())
    lines.append("")
    lines.append("FINGERPRINT HASHES")
    lines.append(f"file_size_bytes: {file_size}")
    lines.append(f"file_sha256: {file_hash}")
    lines.append(f"order_sensitive_dataset_sha256: {profile['dataset_hash']}")
    lines.append(f"order_independent_sha256: {profile['dataset_fingerprint']}")
    lines.append("column_hashes_sha256:")
    for name, h, st in zip(profile["header"], profile["column_hashes"], profile["col_stats"]):
        lines.append(f"  - {name}")
        lines.append(f"      sha256: {h}")
        lines.append(f"      distinct_sha256: {st.distinct_summary_hash()}")
    lines.append("")

    return lines, safe_base, ts

def write_report(
    csv_path: str,
    logdir: str,
    delimiter: str,
    encoding: str,
    quotechar: str,
) -> List[str]:
    lines, safe_base, ts = build_report_lines(
        csv_path=csv_path,
        delimiter=delimiter,
        encoding=encoding,
        quotechar=quotechar,
    )

    report_paths: List[str] = []

    # 1) Next to the data
    data_dir = os.path.dirname(os.path.abspath(csv_path))
    report_paths.append(os.path.join(data_dir, f"{safe_base}.integrity_{ts}.txt"))

    # 2) Integrity log directory
    os.makedirs(logdir, exist_ok=True)
    report_paths.append(os.path.join(logdir, f"{safe_base}.integrity_{ts}.txt"))

    for report_path in report_paths:
        with open(report_path, "w", encoding="utf-8", newline="\n") as out:
            out.write("\n".join(lines))

    return report_paths

def main():
    ap = argparse.ArgumentParser(description="Two-level CSV integrity checker (hash + data fingerprint).")
    ap.add_argument("csv_path", help="Path to CSV file")
    ap.add_argument("--logdir", default="integrity_check_log", help="Output directory for report copies")
    ap.add_argument("--delimiter", default=",", help="CSV delimiter (default: ,)")
    ap.add_argument("--encoding", default="utf-8", help="File encoding (default: utf-8)")
    ap.add_argument("--quotechar", default='"', help='CSV quote character (default: ")')
    args = ap.parse_args()

    if not os.path.isfile(args.csv_path):
        print(f"ERROR: file not found: {args.csv_path}", file=sys.stderr)
        sys.exit(2)

    report_paths = write_report(
        csv_path=args.csv_path,
        logdir=args.logdir,
        delimiter=args.delimiter,
        encoding=args.encoding,
        quotechar=args.quotechar,
    )
    for report_path in report_paths:
        print(f"Wrote report: {report_path}")

if __name__ == "__main__":
    main()
