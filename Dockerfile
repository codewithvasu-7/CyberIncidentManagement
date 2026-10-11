# Stage 1: Build Java project with Maven
FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Run Tomcat and deploy WAR
FROM tomcat:10.1-jdk21-temurin
WORKDIR /usr/local/tomcat

# Remove default ROOT application
RUN rm -rf webapps/*

# Copy built WAR as ROOT.war so it serves directly from the root domain
COPY --from=build /app/target/*.war webapps/ROOT.war

EXPOSE 8080
CMD ["catalina.sh", "run"]
