package org.sasanlabs.analytics.model;

/**
 * One entry of the benchmark sources file: a scanner configuration whose results file the engine
 * reads.
 *
 * @param id stable key that joins runs and findings rows, e.g. {@code zap-modern}
 * @param scanner scanner name, e.g. {@code ZAP}
 * @param variant what distinguishes this configuration from others of the same scanner
 * @param scannerType whether the scanner is DAST or SAST
 * @param results results file path, relative to the {@code --base-dir} given to the engine
 */
public record BenchmarkSource(
        String id, String scanner, String variant, ScannerType scannerType, String results) {}
