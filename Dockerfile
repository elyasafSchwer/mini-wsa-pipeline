# syntax=docker/dockerfile:1

# ---- Stage 1: build ----------------------------------------------------------
# Build the Spring Boot fat jar with Maven on a JDK 21 image. This stage is thrown
# away in the final image, so none of the build tooling ships to production.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build

# Resolve dependencies first (cached layer) so source-only changes don't re-download
# the whole dependency tree on every build.
COPY pom.xml .
RUN mvn -q -B dependency:go-offline

# Now copy sources and package. Skip tests here — tests need Redis/Elasticsearch and
# are run separately in CI, not during the image build.
COPY src ./src
RUN mvn -q -B clean package -DskipTests

# ---- Stage 2: runtime --------------------------------------------------------
# Lightweight JRE-only Alpine base — no JDK, no Maven, just what's needed to run.
FROM eclipse-temurin:21-jre-alpine AS runtime
WORKDIR /app

# Run as a non-root user (defence in depth; the JVM needs no root privileges).
RUN addgroup -S wsa && adduser -S wsa -G wsa
USER wsa

# Copy only the built jar from the build stage.
COPY --from=build /build/target/mini-wsa-*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
