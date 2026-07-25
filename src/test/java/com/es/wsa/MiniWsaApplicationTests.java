package com.es.wsa;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Smoke test that the full application context loads. Runs under the {@code standalone}
 * profile so it is self-contained — no Elasticsearch or Redis required — which keeps the
 * default build green on any machine.
 */
@SpringBootTest
@ActiveProfiles("standalone")
class MiniWsaApplicationTests {

	@Test
	void contextLoads() {
	}

}
