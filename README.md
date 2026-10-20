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
2. maps each detected, missed and unmatched item to its VulnerableApp
   challenge and level: DAST by URL (`/JWTVulnerability/LEVEL_3`), SAST by
   class name, with a mapping file for classes named differently;
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
  status (`detected`, `missed` or `unmatched`), challenge, level, CWE and
  location. It is rewritten on every run. A benchmark whose results file is
  missing keeps its previous rows.

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
| `--mapping` | `config/vulnerableapp/challenge-mapping.json` | Challenge names for SAST classes named differently. |
| `--run-date` | today (UTC) | Date recorded for this run, `YYYY-MM-DD`. |

## Adding a scanner

Once VulnerableApp commits a results file for the scanner, add it to
[`config/vulnerableapp/benchmark-sources.json`](config/vulnerableapp/benchmark-sources.json):

```json
{
  "id": "nuclei",
  "scanner": "Nuclei",
  "variant": "default templates",
  "scanType": "DAST",
  "results": "benchmarks/Nuclei/nuclei-results.json"
}
```

No code change is needed. The `id` joins rows across the two files, so keep it
stable.

## Development

Code is formatted with google-java-format (AOSP style), like VulnerableApp.
`./gradlew spotlessApply` formats it, and CI runs `./gradlew spotlessCheck test`.
