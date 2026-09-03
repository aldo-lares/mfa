FROM maven:3.9.11-eclipse-temurin-25 AS build

WORKDIR /app
COPY pom.xml .
RUN mvn -B dependency:go-offline

COPY src ./src
RUN mvn -B package -DskipTests \
    && mvn -B dependency:copy-dependencies -DoutputDirectory=target/dependency

FROM eclipse-temurin:25-jre

WORKDIR /app
COPY --from=build /app/target/classes ./target/classes
COPY --from=build /app/target/dependency ./target/dependency

EXPOSE 8080
CMD ["java", "-cp", "target/classes:target/dependency/*", "com.github.aldolares.mfa.AuthenticationServiceApplication"]