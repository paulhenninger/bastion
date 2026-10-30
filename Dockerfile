# The API server. Built with the project's own Gradle wrapper (version- and
# checksum-exact), run on a slim Alpine JRE as an unprivileged user.
#
# Every base image is pinned to a version AND a digest: a re-pushed tag can't
# change what is built on. Dependabot (.github/dependabot.yml) proposes new pins;
# CI scans each image (Trivy) and smoke-tests the hardened stack before merge.
# Java stays on its LTS line (25; the next is 29): CI fails if this file,
# build.gradle and ci.yml disagree.
#
# Run it as docker-compose.yml does — read-only root filesystem, every Linux
# capability dropped, no privilege escalation:
#   docker run --read-only --tmpfs /tmp --cap-drop ALL \
#     --security-opt no-new-privileges --env-file .env bastion-app

FROM eclipse-temurin:25.0.5_8-jdk@sha256:83f4a7fc27df94dcc7b8de04d14cbbba8da14406f921e966969c3b09000aa507 AS build
WORKDIR /workspace
COPY gradlew ./
COPY gradle ./gradle
COPY build.gradle settings.gradle ./
# Strip CRs in case of a Windows checkout (see .gitattributes); resolve
# dependencies in their own layer so a code-only change doesn't re-download them.
RUN sed -i 's/\r$//' gradlew && chmod +x gradlew && ./gradlew --no-daemon -q dependencies > /dev/null
COPY config ./config
COPY src ./src
RUN ./gradlew --no-daemon -q bootJar
# Unpack into Spring Boot's layers: a code-only release ships a ~1 MB layer, not the whole jar.
RUN java -Djarmode=tools -jar build/libs/bastion-*.jar extract --layers --launcher --destination /extracted

FROM eclipse-temurin:25.0.5_8-jre-alpine@sha256:56f273059de6b13a6b49fe0ded691ed2d0399bbee76156a8f2d385f7524a3d43
# Alpine security fixes published since the base image was built, then a
# system user with no shell and no home. Nothing else is installed: the
# healthcheck uses busybox wget, which Alpine has built in.
RUN apk upgrade --no-cache \
 && addgroup -S -g 10001 bastion \
 && adduser -S -u 10001 -G bastion -H -s /sbin/nologin bastion
WORKDIR /app
# Root-owned and read-only to the app: it needs to read its code, never write it.
COPY --from=build /extracted/dependencies/ ./
COPY --from=build /extracted/spring-boot-loader/ ./
COPY --from=build /extracted/snapshot-dependencies/ ./
COPY --from=build /extracted/application/ ./
USER 10001:10001
# 8080 = API (reached only through the web container). 9091 = management
# (health, Prometheus): keep it on a private network.
EXPOSE 8080 9091
HEALTHCHECK --interval=15s --timeout=3s --start-period=60s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:9091/actuator/health/liveness || exit 1
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-XX:+ExitOnOutOfMemoryError", "-Djava.io.tmpdir=/tmp", \
            "org.springframework.boot.loader.launch.JarLauncher"]
