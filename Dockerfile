# Multi-stage: build with the project's own Gradle wrapper (version-exact),
# run on a slim JRE as an unprivileged user.
FROM eclipse-temurin:25-jdk AS build
WORKDIR /workspace
COPY gradlew ./
COPY gradle ./gradle
COPY build.gradle settings.gradle ./
COPY config ./config
COPY src ./src
# Strip CRs in case of a Windows checkout (see .gitattributes), then build.
RUN sed -i 's/\r$//' gradlew && chmod +x gradlew && ./gradlew bootJar --no-daemon -q

FROM eclipse-temurin:25-jre
# No root process: a compromise of the app is not a compromise of the container.
RUN groupadd --system bastion && useradd --system --gid bastion --no-create-home bastion
WORKDIR /app
COPY --from=build --chown=bastion:bastion /workspace/build/libs/*.jar app.jar
USER bastion
# 8080 = API (behind the reverse proxy). 9091 = management (health, metrics) —
# keep it on the private network only.
EXPOSE 8080 9091
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-XX:+ExitOnOutOfMemoryError", "-jar", "app.jar"]
