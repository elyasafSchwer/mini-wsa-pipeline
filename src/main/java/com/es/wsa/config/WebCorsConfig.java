package com.es.wsa.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Cross-Origin Resource Sharing (CORS) configuration for the browser-based UI.
 *
 * <p>The analytics UI is a separate single-page app served from a different origin (the
 * deployed Vercel site, and {@code http://localhost:5173} during local development), so it
 * needs explicit CORS permission to call the JSON APIs under {@code /v1/**} and
 * {@code /api/**} from the browser.
 *
 * <p>Allowed origins are configurable via {@code wsa.cors.allowed-origins} (comma-separated);
 * the defaults cover the hosted UI and the local Vite dev server.
 */
@Configuration
public class WebCorsConfig implements WebMvcConfigurer {

    private final String[] allowedOrigins;

    public WebCorsConfig(
            @Value("${wsa.cors.allowed-origins:https://mini-wsa-ui.vercel.app,http://localhost:5173}")
            String[] allowedOrigins) {
        this.allowedOrigins = allowedOrigins;
    }

    @Override
    public void addCorsMappings(@NonNull CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins(allowedOrigins)
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .maxAge(3600);
    }
}
