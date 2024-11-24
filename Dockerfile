FROM openjdk:8

WORKDIR /work

LABEL maintainer="whgojp@foxmail.com"
LABEL version="1.3"
LABEL description="I think therefore I am."

COPY target/JavaSecLab.jar /work/JavaSecLab.jar

RUN mkdir -p /tmp/upload && chmod -R 777 /tmp/upload \
    && echo "vul test.jsp" > /tmp/upload/test.jsp \
    && echo "vul test.txt" > /tmp/upload/test.txt

EXPOSE 80

ENV IMAGE_NAME=JavaSecLab

ENTRYPOINT ["java", "-jar", "JavaSecLab.jar"]
