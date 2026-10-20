package org.sasanlabs.analytics.io;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;

/**
 * Reads and writes the dataset's CSV files with Apache Commons CSV. Rows end with {@code \n} so the
 * files diff cleanly in git on every platform.
 */
public final class Csv {

    private static final CSVFormat FORMAT =
            CSVFormat.RFC4180.builder().setRecordSeparator('\n').build();

    private Csv() {}

    public static void write(Path file, List<String> header, List<List<String>> rows)
            throws IOException {
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        try (BufferedWriter writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8);
                CSVPrinter printer = new CSVPrinter(writer, FORMAT)) {
            printer.printRecord(header);
            printer.printRecords(rows);
        }
    }

    /** Reads every data row, skipping the header. Returns an empty list if the file is absent. */
    public static List<List<String>> readRows(Path file) throws IOException {
        List<List<String>> rows = new ArrayList<>();
        if (!Files.exists(file)) {
            return rows;
        }
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8);
                CSVParser parser = FORMAT.parse(reader)) {
            boolean header = true;
            for (CSVRecord record : parser) {
                if (header) {
                    header = false;
                    continue;
                }
                rows.add(record.toList());
            }
        }
        return rows;
    }
}
