FROM eclipse-temurin:17-jdk-jammy AS build

WORKDIR /src
COPY gradle gradle
COPY gradlew settings.gradle build.gradle ./
COPY core core
COPY cli cli
COPY src/main/resources src/main/resources
RUN chmod +x gradlew && ./gradlew :cli:shadowJar --no-daemon

FROM eclipse-temurin:17-jre-jammy

RUN groupadd --gid 10001 bypassfuzzer \
    && useradd --uid 10001 --gid bypassfuzzer --create-home --shell /usr/sbin/nologin bypassfuzzer \
    && install -d -o bypassfuzzer -g bypassfuzzer -m 0700 /work
COPY --from=build --chown=bypassfuzzer:bypassfuzzer /src/cli/build/libs/bypassfuzzer-cli.jar /opt/bypassfuzzer/bypassfuzzer-cli.jar

USER bypassfuzzer
WORKDIR /work
ENTRYPOINT ["java", "-jar", "/opt/bypassfuzzer/bypassfuzzer-cli.jar"]
