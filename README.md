# AnalyticalEngine

Turns security scanner benchmark results from
[OWASP VulnerableApp](https://github.com/SasanLabs/VulnerableApp) into a
standardized dataset, so scanners can be compared, tracked over time and
visualized with any tool.

```
VulnerableApp benchmark results ──▶ AnalyticalEngine ──▶ runs.csv + findings.csv
(benchmarks/<Tool>/*-results.json)   (this repo)          (schema/datapackage.json)
```

The dataset is the contract: its schema is independent of this engine and of
whatever visualizes it.

## What it does

For every benchmark listed in a sources file, the engine:

1. reads the scanner's results file, written by VulnerableApp's
   `/scanner/benchmark` endpoint (the same format for every scanner);
2. keys each detected, missed and unmatched item by its CWE, normalized to
   `CWE-<number>`. DAST items also get the challenge and level of their URL
   (`/JWTVulnerability/LEVEL_3`);
3. computes the metrics (expected, detected, missed, unmatched, coverage);
4. writes the dataset.

## The dataset

Two CSV files, described column by column in
[`schema/datapackage.json`](schema/datapackage.json), a
[Frictionless Data Package](https://specs.frictionlessdata.io/data-package/):

- **`runs.csv`**: one row per benchmark per run date, with the counts and
  coverage. Running again on the same date replaces that date's row, and a new
  date adds rows, so the file is the history.
- **`findings.csv`**: every item of each benchmark's latest result, with its
  status (`detected`, `missed` or `unmatched`), CWE, type, challenge and
  level (DAST only) and location. It is rewritten on every run. A benchmark
  whose results file is missing keeps its previous rows.

CWE is the key for comparisons: how much of a CWE a scanner covers is
detected / (detected + missed) over that CWE's rows, which any query or
visualization layer can compute. Only benchmarks of the same `scanner_type`
are compared, since DAST and SAST ground truths describe different things.

`detected` rows need results that list `detectedItems`
([SasanLabs/VulnerableApp#832](https://github.com/SasanLabs/VulnerableApp/pull/832)).
Older results only carry the detected count.

## Running it

Requires Java 17. From this repository, against a VulnerableApp checkout:

```bash
./gradlew test
./gradlew run --args="--base-dir ../VulnerableApp --out out/benchmark"
```

| Option | Default | Purpose |
|---|---|---|
| `--out` | (required) | Directory the dataset is written to. |
| `--base-dir` | current directory | Directory the results paths in the sources file are relative to. |
| `--sources` | `config/vulnerableapp/benchmark-sources.json` | The benchmarks to read. |
| `--run-date` | today (UTC) | Date recorded for this run, `YYYY-MM-DD`. |

## Adding a scanner

Once VulnerableApp commits a results file for the scanner, add it to
[`config/vulnerableapp/benchmark-sources.json`](config/vulnerableapp/benchmark-sources.json):

```json
{
  "id": "nuclei",
  "scanner": "Nuclei",
  "variant": "default templates",
  "scannerType": "DAST",
  "results": "benchmarks/Nuclei/nuclei-results.json"
}
```

No code change is needed. The `id` joins rows across the two files, so keep it
stable.

## Development

Code is formatted with google-java-format (AOSP style), like VulnerableApp.
`./gradlew spotlessApply` formats it, and CI runs `./gradlew spotlessCheck test`.
