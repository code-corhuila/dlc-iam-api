FROM maven:3.9.13-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml ./
COPY iam-core/pom.xml iam-core/pom.xml
COPY iam-adapters/pom.xml iam-adapters/pom.xml
COPY iam-app/pom.xml iam-app/pom.xml
COPY iam-core/src/main iam-core/src/main
COPY iam-adapters/src/main iam-adapters/src/main
COPY iam-app/src/main iam-app/src/main
RUN mvn -B -q -pl iam-app -am -Dmaven.test.skip=true package

FROM eclipse-temurin:21.0.12_8-jre
WORKDIR /app
COPY --from=build --chown=10001:10001 /workspace/iam-app/target/iam-app-0.1.0-SNAPSHOT.jar /app/iam.jar
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/iam.jar"]
