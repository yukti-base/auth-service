package org.yuktisetu.authservice;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Smoke test: the whole auth-service context starts.
 *
 * @ActiveProfiles("test") is required, not decorative. Without it the test runs
 * with no profile and therefore no datasource URL, and fails with "Failed to
 * determine a suitable driver class" -- which is what it was doing. The other
 * five services all carry this annotation; auth-service was the one that had no
 * test resources at all.
 *
 * It is worth more than it looks: it is the only check that auth-service's
 * entity mappings still match the schema the entities generate, and that every
 * bean in the service can actually be constructed.
 */
@SpringBootTest
@ActiveProfiles("test")
class AuthServiceApplicationTests {

    @Test
    void contextLoads() {
    }

}
