#!/usr/bin/env python3
"""
compare_integrity_reports.py

Compares two CSV integrity report outputs and prints:
- APPROVED if they are identical
- CHANGED if any difference is found, with where it differs

Usage:
  python compare_integrity_reports.py report1.txt report2.txt
"""

from __future__ import annotations

import argparse
import sys
from typing import Dict, List, Optional, Tuple


def parse_report(path: str) -> Dict[str, Tuple[str, int]]:
    """
    Parse report into a flat key -> (value, line) mapping.
    Keys are hierarchical and include sections and column names.
    """
    data: Dict[str, Tuple[str, int]] = {}
    section = ""
    subsection = ""
    current_item = ""
    list_index = 0

    with open(path, "r", encoding="utf-8") as f:
        for idx, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\n")
            line_stripped = line.strip()
            if line == "":
                continue

            # Section headers
            if line_stripped in ("HUMAN-READABLE", "HASHES", "FINGERPRINT HASHES", "FINGERPRINT HASHES:"):
                section = line_stripped
                subsection = ""
                current_item = ""
                list_index = 0
                continue

            # Top-level key: value
            if not line.startswith(" ") and ":" in line:
                key, value = line.split(":", 1)
                full_key = f"{section}.{key.strip()}"
                data[full_key] = (value.strip(), idx)
                continue

            # Named blocks
            if line.endswith(":") and not line.startswith(" "):
                subsection = line[:-1].strip()
                current_item = ""
                list_index = 0
                continue

            # List items under a subsection
            if line.startswith("  - "):
                item = line[4:].strip()
                current_item = item
                list_index += 1
                full_key = f"{section}.{subsection}[{list_index}]"
                data[full_key] = (item, idx)
                continue

            # Nested key under current item
            if line.startswith("      ") and ":" in line and current_item:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                full_key = f"{section}.{subsection}.{current_item}.{key}"
                data[full_key] = (value, idx)
                continue

            # Nested list (e.g., missing_types)
            if line.startswith("        - ") and current_item:
                item = line[10:].strip()
                full_key = f"{section}.{subsection}.{current_item}.list[{idx}]"
                data[full_key] = (item, idx)
                continue

    return data


def parse_column_hashes(path: str) -> Dict[str, Dict[str, Tuple[str, int]]]:
    columns: Dict[str, Dict[str, Tuple[str, int]]] = {}
    in_block = False
    current_col = ""

    with open(path, "r", encoding="utf-8") as f:
        for idx, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\n")
            line_stripped = line.strip()

            if line_stripped == "column_hashes_sha256:":
                in_block = True
                current_col = ""
                continue

            if not in_block:
                continue

            if line_stripped == "":
                continue

            if not line.startswith(" ") and line_stripped.endswith(":"):
                # A new top-level block started
                break

            if line.startswith("  - "):
                current_col = line[4:].strip()
                columns.setdefault(current_col, {})
                continue

            if line.startswith("      ") and ":" in line and current_col:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                columns[current_col][key] = (value, idx)

    return columns


def find_by_suffix(data: Dict[str, Tuple[str, int]], suffix: str) -> Optional[Tuple[str, str, int]]:
    for key, (value, line) in data.items():
        if key.endswith(suffix):
            return key, value, line
    return None


def compare_value(
    data_a: Dict[str, Tuple[str, int]],
    data_b: Dict[str, Tuple[str, int]],
    suffix: str,
) -> Tuple[str, Optional[Tuple[str, int]], Optional[Tuple[str, int]]]:
    a = find_by_suffix(data_a, suffix)
    b = find_by_suffix(data_b, suffix)
    a_val = (a[1], a[2]) if a is not None else None
    b_val = (b[1], b[2]) if b is not None else None
    return suffix, a_val, b_val


def emphasize_fail(text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[1;31m{text}\033[0m"
    return text


def compare_reports(path_a: str, path_b: str) -> int:
    data_a = parse_report(path_a)
    data_b = parse_report(path_b)
    columns_a = parse_column_hashes(path_a)
    columns_b = parse_column_hashes(path_b)

    ignored_keys = {
        ".timestamp_utc",
        ".file",
    }

    changes: List[str] = []
    column_changes: List[str] = []

    # File-level and dataset-level hashes
    checks = [
        ("file size", ".file_size_bytes"),
        ("file-level hash", ".file_sha256"),
        ("dataset-level hash (order-sensitive)", ".order_sensitive_dataset_sha256"),
        ("dataset-level hash (order-independent)", ".order_independent_sha256"),
    ]

    # Always report file-level and dataset-level hash status
    _, file_a, file_b = compare_value(data_a, data_b, ".file_sha256")
    if file_a is None or file_b is None:
        file_hash_status = "file-level hash not approved (missing in one report)"
    elif file_a[0] == file_b[0]:
        file_hash_status = "file-level hash approved"
    else:
        file_hash_status = "file-level hash not approved"

    _, ds_a, ds_b = compare_value(data_a, data_b, ".order_sensitive_dataset_sha256")
    if ds_a is None or ds_b is None:
        ds_hash_status = "dataset-level hash (order-sensitive) not approved (missing in one report)"
    elif ds_a[0] == ds_b[0]:
        ds_hash_status = "dataset-level hash (order-sensitive) approved"
    else:
        ds_hash_status = "dataset-level hash (order-sensitive) not approved"

    _, di_a, di_b = compare_value(data_a, data_b, ".order_independent_sha256")
    if di_a is None or di_b is None:
        di_hash_status = "dataset-level hash (order-independent) not approved (missing in one report)"
    elif di_a[0] == di_b[0]:
        di_hash_status = "dataset-level hash (order-independent) approved"
    else:
        di_hash_status = "dataset-level hash (order-independent) not approved"

    for label, suffix in checks:
        _, a_val, b_val = compare_value(data_a, data_b, suffix)
        if a_val is None or b_val is None:
            changes.append(f"- {label} not approved (missing in one report)")
            continue
        if a_val[0] != b_val[0]:
            changes.append(f"- {label} not approved")

    # Column hash changes (only report mismatches)
    all_cols = sorted(set(columns_a.keys()) | set(columns_b.keys()))
    for col in all_cols:
        a_entry = columns_a.get(col, {})
        b_entry = columns_b.get(col, {})
        for kind in ("sha256", "distinct_sha256"):
            a_val = a_entry.get(kind)
            b_val = b_entry.get(kind)
            if a_val is None or b_val is None:
                column_changes.append(f"- column {col} {kind} not approved (missing in one report)")
                continue
            if a_val[0] != b_val[0]:
                column_changes.append(f"- column {col} {kind} not approved")

    # Human-readable differences
    human_diffs = []
    keys = sorted(set(data_a.keys()) | set(data_b.keys()))
    for key in keys:
        if key in ignored_keys:
            continue
        if not key.startswith("HUMAN-READABLE."):
            continue
        if ".sha256" in key or ".distinct_sha256" in key:
            continue
        if key.endswith(".file_size_bytes"):
            continue
        if key.endswith(".file_sha256"):
            continue
        if key.endswith(".order_sensitive_dataset_sha256"):
            continue
        if key.endswith(".order_independent_sha256"):
            continue
        a = data_a.get(key)
        b = data_b.get(key)
        if a is None:
            human_diffs.append((key, "(missing)", "", b[0], b[1]))
            continue
        if b is None:
            human_diffs.append((key, a[0], a[1], "(missing)", ""))
            continue
        if a[0] != b[0]:
            human_diffs.append((key, a[0], a[1], b[0], b[1]))

    if changes or column_changes or human_diffs:
        print(emphasize_fail("INTEGRITY CHECK DID NOT PASS"))
        print(file_hash_status)
        print(ds_hash_status)
        print(di_hash_status)
        if column_changes:
            print("Column hash checks not approved:")
            for line in column_changes:
                print(line)
    else:
        print("INTEGRITY CHECK PASSED")
        print(file_hash_status)
        print(ds_hash_status)
        print(di_hash_status)

    if human_diffs:
        print("Differences in human-readable section:")
        for key, a_val, a_line, b_val, b_line in human_diffs:
            print(f"- {key}")
            if a_val == "(missing)":
                print("  report1: (missing)")
            else:
                print(f"  report1: {a_val} (line {a_line})")
            if b_val == "(missing)":
                print("  report2: (missing)")
            else:
                print(f"  report2: {b_val} (line {b_line})")

    return 1 if (changes or column_changes or human_diffs) else 0


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare two CSV integrity reports")
    ap.add_argument("report_a", help="First report file")
    ap.add_argument("report_b", help="Second report file")
    args = ap.parse_args()

    exit_code = compare_reports(args.report_a, args.report_b)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
