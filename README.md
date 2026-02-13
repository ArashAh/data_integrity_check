# CSV Integrity Checker

Minimal steps to generate integrity reports and compare them.

Replace the sample_dataset.csv with a copy of your .csv file. 

Reports can be generated at the source and destination can be compared.

## Prerequisites
- Python 3.8+ (any recent 3.x should work)
- Git

## Clone
```bash
git clone <REPO_URL>
cd <REPO_FOLDER>
```

## Create an integrity report
```bash
python generate_integrity_report.py sample_data.csv
```
Output:
- A timestamped report next to the CSV
- A copy in `integrity_check_log/`

Optional flags:
```bash
python csv_integrity_check.py sample_data.csv --logdir integrity_check_log --delimiter "," --encoding "utf-8" --quotechar '"'
```

## Compare two reports
```bash
python compare_integrity_reports.py report1.txt report2.txt
```
The comparison prints:
- File-level and dataset-level hash status (approved / not approved)
- Column hash failures only
- Human-readable differences only

## Interpreting a report
The report has two sections:
- HUMAN-READABLE: row/column counts, header, and per-column stats including missing values.
- FINGERPRINT HASHES: file size, file hash, dataset hashes, and per-column hashes.

Hash meanings:
- `file_sha256`: raw file bytes (sensitive to any change, including line endings).
- `order_sensitive_dataset_sha256`: normalized CSV content, row order matters.
- `order_independent_sha256`: normalized CSV content, row order does not matter.
- Column `sha256`: normalized values per column in row order.
- Column `distinct_sha256`: distinct values only, order independent.

## Interpreting a comparison
- If the integrity check passes, all hashes and human-readable fields match.
- If it fails, the output shows which hash checks are not approved, which columns differ, and any human-readable differences.


## Generate sample data (optional)

In case a test of functionality is needed a sample dataset can be generate using the following instruction. 

```bash
python data_gen.py
```
This creates or overwrites `sample_data.csv`. 
