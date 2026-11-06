package org.sasanlabs.analytics.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import java.util.Locale;

/**
 * How a scanner finds vulnerabilities. Results are only compared between scanners of the same type,
 * since DAST and SAST ground truths describe different things (URLs vs. source lines).
 */
public enum ScannerType {
    DAST,
    SAST;

    @JsonCreator
    public static ScannerType fromString(String value) {
        return valueOf(value.trim().toUpperCase(Locale.ROOT));
    }
}
