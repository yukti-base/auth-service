FROM eclipse-temurin:21-jdk AS build

WORKDIR /workspace

COPY . .

RUN chmod +x /workspace/framework/gradlew /workspace/auth-service/gradlew

RUN /workspace/framework/gradlew -p /workspace/framework :user-dal:publishToMavenLocal --no-daemon
RUN /workspace/auth-service/gradlew -p /workspace/auth-service bootJar -x test --no-daemon

FROM eclipse-temurin:21-jre

WORKDIR /app
COPY --from=build /workspace/auth-service/build/libs/auth-service-0.0.1-SNAPSHOT.jar /app/app.jar

EXPOSE 8081
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
