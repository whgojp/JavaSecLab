FROM openjdk:8

WORKDIR /work

LABEL maintainer="whgojp@foxmail.com"
LABEL version="1.0"
LABEL description="I think therefore I am."

COPY target/JavaSecLab.jar /work/JavaSecLab.jar

EXPOSE 8080
EXPOSE 9090

ENV IMAGE_NAME=JavaSecLab

ENTRYPOINT ["java", "-jar", "JavaSecLab.jar"]
