# Secoda PII Scanner

A command-line utility for auditing Secoda catalog columns for potential personally identifiable information (PII). The scanner fetches Secoda table and column metadata, samples table previews, asks Gemini to classify likely PII columns, and writes reviewable reports before optionally updating reviewed PII classifications back in Secoda.

## What it does

- Discovers Secoda catalog tables and columns.
- Filters scans by database, schema, or a single table.
- Uses Gemini to evaluate column metadata and sampled preview rows.
- Exports JSON and CSV review reports.
- Lets you review the CSV manually before applying PII updates to Secoda.
- Can apply PII updates from an already-reviewed CSV without rescanning.

## Requirements

- Python 3.10+
- A Secoda API key or authorization header with permission to read catalog metadata and update column PII status.
- A Gemini API key.

The script uses only Python standard-library modules, so no package installation is required.

## Usage

Run the scanner interactively:

```bash
python3 secoda_data_scanner.py
```

You will be prompted for:

1. Secoda API base URL (defaults to `https://app.secoda.co/api/v1`)
2. Secoda API key or Authorization header
3. Databases to scan (optional comma-separated list)
4. Schemas to scan (optional comma-separated list)
5. Gemini API key
6. Gemini model (defaults to `gemini-2.0-flash`)

### Scan one table

Scan a named table:

```bash
python3 secoda_data_scanner.py --single-table my_table_name
```

Scan the first matching table only:

```bash
python3 secoda_data_scanner.py --single-table
```

### Debug column discovery

Inspect raw column fields and filter matching without running Gemini classification:

```bash
python3 secoda_data_scanner.py --debug-columns
```

### Apply updates from a reviewed CSV

After reviewing an exported CSV and setting `review_pii` values, apply updates without rescanning:

```bash
python3 secoda_data_scanner.py --review-csv pii_review_YYYYMMDD_HHMMSS.csv
```

Append a tag to each newly updated resource while preserving existing tags:

```bash
python3 secoda_data_scanner.py --single-table my_table_name --update-tag "AI Generated"
```

## Review workflow

1. Run the scanner.
2. Open the generated CSV in a spreadsheet editor.
3. Review the `review_pii` column and adjust values as needed.
4. Save the CSV.
5. Either continue when prompted by the scanner or rerun with `--review-csv`.

## Security notes

- Do **not** commit Secoda or Gemini API keys.
- Prefer entering keys interactively when prompted.
- Leave the `HARDCODED_*` constants in `secoda_data_scanner.py` empty unless you are using a private, local-only copy.
- Review generated CSV and JSON reports before sharing them; sampled data and column evidence may contain sensitive information.

## Generated files

The scanner writes timestamped review files in the working directory, including CSV and JSON reports, plus local scan state used to skip unchanged tables. Treat these as local artifacts and review them carefully before committing or sharing.
