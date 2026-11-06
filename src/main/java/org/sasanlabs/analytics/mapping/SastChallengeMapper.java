package org.sasanlabs.analytics.mapping;

import org.sasanlabs.analytics.model.Finding;

/**
 * SAST findings are compared by CWE, so they carry no challenge: the SAST ground truth records a
 * source line, not a challenge or level. Only the location is resolved.
 */
public class SastChallengeMapper implements ChallengeMapper {

    @Override
    public ChallengeRef map(Finding finding) {
        return ChallengeRef.NONE;
    }

    @Override
    public String location(Finding finding) {
        if (finding.filePath() == null) {
            return "";
        }
        return finding.line() != null
                ? finding.filePath() + ":" + finding.line()
                : finding.filePath();
    }
}
