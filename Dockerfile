# === Stage 1: Build WAR-файл ===
FROM maven:3.9.6-eclipse-temurin-17 AS builder

WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests -Dlicense.skip=true

# === Stage 2: Запуск у Tomcat ===
FROM tomcat:9.0.70-jdk17

# Прибираємо стандартні апки
RUN rm -rf /usr/local/tomcat/webapps/*

# Копіюємо наш WAR-файл і перейменовуємо його у ROOT.war
COPY --from=builder /app/target/*.war /usr/local/tomcat/webapps/ROOT.war

EXPOSE 8080

CMD ["catalina.sh", "run"]
