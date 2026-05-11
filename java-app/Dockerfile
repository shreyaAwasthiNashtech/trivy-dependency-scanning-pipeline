FROM maven:3.6-jdk-8

WORKDIR /app

COPY pom.xml .

RUN mvn dependency:resolve

COPY src ./src

RUN mvn package

CMD ["java", "-cp", "target/vulnerable-java-app-1.0.jar", "App"]