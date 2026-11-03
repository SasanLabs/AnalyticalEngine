package org.sasanlabs.analytics.mapping;

import org.sasanlabs.analytics.model.Finding;
import org.sasanlabs.analytics.model.ScannerType;

/** Resolves a benchmark finding to the VulnerableApp challenge it belongs to, where it has one. */
public interface ChallengeMapper {

    ChallengeRef map(Finding finding);

    /** Text identifying where the finding is: a URL path for DAST, {@code path:line} for SAST. */
    String location(Finding finding);

    static ChallengeMapper forScannerType(ScannerType scannerType) {
        return scannerType == ScannerType.SAST
                ? new SastChallengeMapper()
                : new DastChallengeMapper();
    }
}
