FROM maven:3.9.9-eclipse-temurin-25 AS build

WORKDIR /app
COPY pom.xml .
RUN mvn -B dependency:go-offline

COPY src ./src
RUN mvn -B package -DskipTests \
    && mvn -B dependency:build-classpath -Dmdep.outputFile=classpath.txt -Dmdep.path

FROM eclipse-temurin:25-jre

WORKDIR /app
COPY --from=build /app/target/classes ./target/classes
COPY --from=build /app/classpath.txt .

EXPOSE 8080
CMD ["sh", "-c", "exec java -cp target/classes:$(cat classpath.txt) com.github.aldolares.mfa.AuthenticationServiceApplication"]