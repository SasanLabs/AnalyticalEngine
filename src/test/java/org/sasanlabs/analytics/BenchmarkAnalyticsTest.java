package org.sasanlabs.analytics;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.sasanlabs.analytics.model.BenchmarkResult;
import org.sasanlabs.analytics.model.BenchmarkSource;
import org.sasanlabs.analytics.model.FindingRow;
import org.sasanlabs.analytics.model.FindingRow.Status;
import org.sasanlabs.analytics.model.RunRow;
import org.sasanlabs.analytics.model.ScannerType;

class BenchmarkAnalyticsTest {

    private static final BenchmarkSource ZAP =
            new BenchmarkSource(
                    "zap-modern", "ZAP", "Modern UI", ScannerType.DAST, "zap-results.json");
    private static final BenchmarkSource SEMGREP =
            new BenchmarkSource(
                    "semgrep", "Semgrep", "p/default", ScannerType.SAST, "semgrep-results.json");

    private static final String DAST_RESULT =
            """
            {
              "tool": "ZAP", "coverage": 25.0, "totalExpected": 4,
              "detected": 1, "missed": 3, "unmatched": 1, "someFutureField": true,
              "detectedItems": [
                {"url": "/XSS/LEVEL_1", "type": "REFLECTED_XSS", "cwe": "CWE-79", "method": "GET"}
              ],
              "missedItems": [
                {"url": "/SQLInjection/LEVEL_1", "type": "ERROR_BASED_SQL_INJECTION", "cwe": "89"},
                {"url": "/XSS/LEVEL_10", "type": "REFLECTED_XSS", "cwe": "CWE-79"},
                {"url": "/XSS/LEVEL_2", "type": "REFLECTED_XSS", "cwe": "CWE-79"}
              ],
              "unmatchedItems": [{"url": "/", "cwe": "cwe-0693", "wascId": "15"}]
            }
            """;

    @Test
    void toRun_recomputesCoverageAndTakesCountsFromTheResult() throws Exception {
        RunRow run =
                BenchmarkAnalytics.toRun(
                        ZAP, BenchmarkAnalytics.parseResult(DAST_RESULT), "2026-10-13");

        assertThat(run.toCells())
                .containsExactly(
                        "2026-10-13",
                        "zap-modern",
                        "ZAP",
                        "Modern UI",
                        "DAST",
                        "",
                        "4",
                        "1",
                        "3",
                        "1",
                        "25.00");
    }

    @Test
    void coverage_isZeroWithoutGroundTruth() {
        assertThat(BenchmarkAnalytics.coverage(0, 0)).isEqualTo("0.00");
        assertThat(BenchmarkAnalytics.coverage(13, 168)).isEqualTo("7.74");
    }

    @Test
    void toFindings_keysEveryItemByCwe_inStableOrder() throws Exception {
        List<FindingRow> rows =
                BenchmarkAnalytics.toFindings(
                        ZAP, BenchmarkAnalytics.parseResult(DAST_RESULT), "2026-10-13");

        assertThat(rows)
                .extracting(
                        FindingRow::status,
                        FindingRow::cwe,
                        FindingRow::challenge,
                        FindingRow::level)
                .containsExactly(
                        tuple(Status.DETECTED, "CWE-79", "XSS", "LEVEL_1"),
                        tuple(Status.MISSED, "CWE-79", "XSS", "LEVEL_2"),
                        tuple(Status.MISSED, "CWE-79", "XSS", "LEVEL_10"),
                        tuple(Status.MISSED, "CWE-89", "SQLInjection", "LEVEL_1"),
                        tuple(Status.UNMATCHED, "CWE-693", "", ""));
        assertThat(rows.get(4).toCells())
                .containsExactly(
                        "2026-10-13",
                        "zap-modern",
                        "ZAP",
                        "Modern UI",
                        "DAST",
                        "unmatched",
                        "CWE-693",
                        "",
                        "",
                        "",
                        "/");
    }

    @Test
    void toFindings_forSast_hasNoChallenge_andListsMissedAndUnmatchedWithoutDetectedItems()
            throws Exception {
        BenchmarkResult result =
                BenchmarkAnalytics.parseResult(
                        """
                        {"tool": "Semgrep", "totalExpected": 2, "detected": 1, "missed": 1,
                         "unmatched": 0,
                         "missedItems": [{"type": "SQL Injection", "cwe": "CWE-89",
                           "filePath": "src/main/java/a/Sqli.java", "line": 12}],
                         "unmatchedItems": []}
                        """);

        assertThat(BenchmarkAnalytics.toFindings(SEMGREP, result, "2026-10-13"))
                .extracting(
                        FindingRow::status,
                        FindingRow::scannerType,
                        FindingRow::cwe,
                        FindingRow::challenge,
                        FindingRow::location)
                .containsExactly(
                        tuple(
                                Status.MISSED,
                                ScannerType.SAST,
                                "CWE-89",
                                "",
                                "src/main/java/a/Sqli.java:12"));
    }

    @Test
    void normalizeCwe_givesOneFormForEveryVariant() {
        assertThat(BenchmarkAnalytics.normalizeCwe("CWE-89")).isEqualTo("CWE-89");
        assertThat(BenchmarkAnalytics.normalizeCwe("89")).isEqualTo("CWE-89");
        assertThat(BenchmarkAnalytics.normalizeCwe(" cwe-089 ")).isEqualTo("CWE-89");
        assertThat(BenchmarkAnalytics.normalizeCwe(null)).isEmpty();
        assertThat(BenchmarkAnalytics.normalizeCwe("none")).isEmpty();
    }

    @Test
    void scannerType_isReadCaseInsensitively() {
        assertThat(ScannerType.fromString(" dast ")).isEqualTo(ScannerType.DAST);
        assertThat(ScannerType.fromString("SAST")).isEqualTo(ScannerType.SAST);
    }

    @Test
    void mergeRuns_keepsOneRowPerBenchmarkAndDay_updatesWinning() {
        RunRow old = run("2026-10-12", "zap-modern", 10);
        RunRow sameDayStale = run("2026-10-13", "zap-modern", 11);
        RunRow other = run("2026-10-13", "semgrep", 18);
        RunRow sameDayFresh = run("2026-10-13", "zap-modern", 13);

        List<RunRow> merged =
                BenchmarkAnalytics.mergeRuns(
                        List.of(sameDayStale, old, other), List.of(sameDayFresh));

        assertThat(merged)
                .extracting(RunRow::runDate, RunRow::benchmark, RunRow::detected)
                .containsExactly(
                        tuple("2026-10-12", "zap-modern", 10),
                        tuple("2026-10-13", "semgrep", 18),
                        tuple("2026-10-13", "zap-modern", 13));
    }

    @Test
    void previousFindings_keepsOnlyThatBenchmarksRows_andSurvivesACsvRoundTrip() throws Exception {
        List<FindingRow> written =
                BenchmarkAnalytics.toFindings(
                        ZAP, BenchmarkAnalytics.parseResult(DAST_RESULT), "2026-10-13");
        List<FindingRow> existing =
                new ArrayList<>(
                        written.stream().map(r -> FindingRow.fromCells(r.toCells())).toList());
        existing.add(
                new FindingRow(
                        "2026-10-13",
                        "semgrep",
                        "Semgrep",
                        "p/default",
                        ScannerType.SAST,
                        Status.MISSED,
                        "CWE-89",
                        "SQL Injection",
                        "",
                        "",
                        "src/Sqli.java:1"));

        assertThat(BenchmarkAnalytics.previousFindings(existing, "zap-modern")).isEqualTo(written);
        assertThat(BenchmarkAnalytics.previousFindings(existing, "nuclei")).isEmpty();
    }

    private static RunRow run(String date, String benchmark, int detected) {
        return new RunRow(
                date,
                benchmark,
                "S",
                "v",
                ScannerType.DAST,
                "",
                100,
                detected,
                100 - detected,
                0,
                "");
    }
}
