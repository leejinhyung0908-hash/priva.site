# 1단계: 빌드
FROM eclipse-temurin:21-jdk AS builder
WORKDIR /app
COPY . .
RUN chmod +x gradlew && ./gradlew :gateway:build -x test

# 2단계: 실행
FROM eclipse-temurin:21-jre
WORKDIR /app
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/gateway/build/libs/*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]