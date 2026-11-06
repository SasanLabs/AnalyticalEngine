package org.sasanlabs.analytics.mapping;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.sasanlabs.analytics.model.Finding;

class SastChallengeMapperTest {

    private final SastChallengeMapper mapper = new SastChallengeMapper();

    @Test
    void sastFindings_carryNoChallenge() {
        assertThat(
                        mapper.map(
                                sast(
                                        "src/main/java/org/sasanlabs/service/vulnerability/jwt/JWTVulnerability.java",
                                        42)))
                .isEqualTo(ChallengeRef.NONE);
    }

    @Test
    void location_isPathAndLine() {
        assertThat(mapper.location(sast("src/Foo.java", 7))).isEqualTo("src/Foo.java:7");
        assertThat(mapper.location(sast("src/Foo.java", null))).isEqualTo("src/Foo.java");
        assertThat(mapper.location(sast(null, 1))).isEmpty();
    }

    private static Finding sast(String path, Integer line) {
        return new Finding(null, null, path, line, null, null, null);
    }
}
