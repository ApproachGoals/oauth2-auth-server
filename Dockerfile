FROM openjdk:17-jdk-alpine
LABEL maintainer="cs.yuan.shi@gmail.com"

WORKDIR /app

COPY ./oauth2-auth-server-0.0.1-SNAPSHOT.jar auth-service.jar

EXPOSE 9100

ENTRYPOINT ["java", "-jar", "/app/auth-service.jar"]