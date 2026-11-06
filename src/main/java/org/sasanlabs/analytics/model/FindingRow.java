package org.sasanlabs.analytics.model;

import java.util.List;
import java.util.Locale;

/** One row of {@code findings.csv}: one item of a benchmark's latest result. */
public record FindingRow(
        String runDate,
        String benchmark,
        String scanner,
        String variant,
        ScannerType scannerType,
        Status status,
        String cwe,
        String vulnerabilityType,
        String challenge,
        String level,
        String location) {

    /** Whether an expected item was found or missed, or a reported item matched nothing. */
    public enum Status {
        DETECTED,
        MISSED,
        UNMATCHED;

        public String label() {
            return name().toLowerCase(Locale.ROOT);
        }

        public static Status fromLabel(String label) {
            return valueOf(label.toUpperCase(Locale.ROOT));
        }
    }

    public static final List<String> HEADER =
            List.of(
                    "run_date",
                    "benchmark",
                    "scanner",
                    "variant",
                    "scanner_type",
                    "status",
                    "cwe",
                    "vulnerability_type",
                    "challenge",
                    "level",
                    "location");

    public static FindingRow fromCells(List<String> c) {
        return new FindingRow(
                c.get(0),
                c.get(1),
                c.get(2),
                c.get(3),
                ScannerType.fromString(c.get(4)),
                Status.fromLabel(c.get(5)),
                c.get(6),
                c.get(7),
                c.get(8),
                c.get(9),
                c.get(10));
    }

    public List<String> toCells() {
        return List.of(
                runDate,
                benchmark,
                scanner,
                variant,
                scannerType.name(),
                status.label(),
                cwe,
                vulnerabilityType,
                challenge,
                level,
                location);
    }
}
