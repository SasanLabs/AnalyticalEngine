package org.sasanlabs.analytics;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.sasanlabs.analytics.io.Csv;
import org.sasanlabs.analytics.model.BenchmarkResult;
import org.sasanlabs.analytics.model.BenchmarkSource;
import org.sasanlabs.analytics.model.FindingRow;
import org.sasanlabs.analytics.model.RunRow;

/**
 * Builds the benchmark dataset from the scanner results files listed in the sources file.
 *
 * <ul>
 *   <li>{@code runs.csv} gains (or updates) one row per benchmark for the run date, so it
 *       accumulates history across runs.
 *   <li>{@code findings.csv} is rewritten with every item of each benchmark's latest result. A
 *       benchmark whose results file is missing keeps its previous rows.
 * </ul>
 */
public final class AnalyticsCli {

    private static final String USAGE =
            "Usage: AnalyticsCli --out <dir> [--base-dir <dir>] [--sources <file>]"
                    + " [--mapping <file>] [--run-date <YYYY-MM-DD>]\n"
                    + "  --out       directory the dataset is written to\n"
                    + "  --base-dir  directory the results paths in the sources file are relative"
                    + " to (default: current directory)\n"
                    + "  --sources   benchmark sources file (default:"
                    + " config/vulnerableapp/benchmark-sources.json)\n"
                    + "  --mapping   challenge mapping file (default:"
                    + " config/vulnerableapp/challenge-mapping.json)\n"
                    + "  --run-date  date recorded for this run (default: today, UTC)";

    private AnalyticsCli() {}

    public static void main(String[] args) throws IOException {
        Path outDir = null;
        Path baseDir = Path.of("");
        Path sourcesFile = Path.of("config/vulnerableapp/benchmark-sources.json");
        Path mappingFile = Path.of("config/vulnerableapp/challenge-mapping.json");
        String runDate = LocalDate.now(ZoneOffset.UTC).toString();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--out" -> outDir = Path.of(requireValue(args, ++i));
                case "--base-dir" -> baseDir = Path.of(requireValue(args, ++i));
                case "--sources" -> sourcesFile = Path.of(requireValue(args, ++i));
                case "--mapping" -> mappingFile = Path.of(requireValue(args, ++i));
                case "--run-date" -> runDate = parseDate(requireValue(args, ++i));
                default -> fail();
            }
        }
        if (outDir == null) {
            fail();
        }

        List<BenchmarkSource> sources = readSources(sourcesFile);
        Map<String, String> sastClassToChallenge = readSastClassToChallenge(mappingFile);

        Path runsFile = outDir.resolve("runs.csv");
        Path findingsFile = outDir.resolve("findings.csv");
        List<FindingRow> existingFindings = new ArrayList<>();
        for (List<String> cells : Csv.readRows(findingsFile)) {
            existingFindings.add(FindingRow.fromCells(cells));
        }

        List<RunRow> runUpdates = new ArrayList<>();
        List<FindingRow> findings = new ArrayList<>();
        for (BenchmarkSource source : sources) {
            Path resultsFile = baseDir.resolve(source.results());
            if (!Files.exists(resultsFile)) {
                System.err.println(
                        "WARN: missing "
                                + resultsFile
                                + ", keeping the last findings of "
                                + source.id());
                findings.addAll(BenchmarkAnalytics.previousFindings(existingFindings, source.id()));
                continue;
            }
            BenchmarkResult result =
                    BenchmarkAnalytics.parseResult(
                            Files.readString(resultsFile, StandardCharsets.UTF_8));
            runUpdates.add(BenchmarkAnalytics.toRun(source, result, runDate));
            findings.addAll(
                    BenchmarkAnalytics.toFindings(source, result, runDate, sastClassToChallenge));
        }

        List<RunRow> existing = new ArrayList<>();
        for (List<String> cells : Csv.readRows(runsFile)) {
            existing.add(RunRow.fromCells(cells));
        }
        List<RunRow> runs = BenchmarkAnalytics.mergeRuns(existing, runUpdates);
        Csv.write(runsFile, RunRow.HEADER, runs.stream().map(RunRow::toCells).toList());
        Csv.write(
                findingsFile,
                FindingRow.HEADER,
                findings.stream().map(FindingRow::toCells).toList());

        System.out.printf(
                "Wrote %d run rows to %s and %d finding rows to %s%n",
                runs.size(), runsFile, findings.size(), findingsFile);
    }

    static List<BenchmarkSource> readSources(Path file) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(file.toFile());
        return mapper.convertValue(
                root.path("benchmarks"), new TypeReference<List<BenchmarkSource>>() {});
    }

    static Map<String, String> readSastClassToChallenge(Path file) throws IOException {
        if (!Files.exists(file)) {
            return Map.of();
        }
        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(file.toFile());
        return mapper.convertValue(
                root.path("sastClassToChallenge"), new TypeReference<Map<String, String>>() {});
    }

    private static String parseDate(String value) {
        try {
            return LocalDate.parse(value).toString();
        } catch (DateTimeParseException e) {
            System.err.println("Invalid --run-date '" + value + "', expected YYYY-MM-DD");
            System.exit(2);
            return null;
        }
    }

    private static String requireValue(String[] args, int index) {
        if (index >= args.length) {
            fail();
        }
        return args[index];
    }

    private static void fail() {
        System.err.println(USAGE);
        System.exit(2);
    }
}
