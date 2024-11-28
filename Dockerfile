FROM openjdk:8

WORKDIR /work

LABEL maintainer="whgojp@foxmail.com"
LABEL version="1.3"
LABEL description="I think therefore I am."

COPY target/JavaSecLab.jar /work/JavaSecLab.jar

RUN mkdir -p /tmp/upload && mkdir -p /tmp/static \
    && mkdir -p /tmp/static/api /tmp/static/css /tmp/static/images /tmp/static/js /tmp/static/lib /tmp/static/other /tmp/static/upload \
    && chmod -R 777 /tmp/upload /tmp/static \
    && echo "vul test.jsp" > /tmp/upload/test.jsp \
    && echo "vul test.txt" > /tmp/upload/test.txt \
    && echo "test readme.md" > /tmp/static/api/readme.md \
    && echo "test styles.css" > /tmp/static/css/styles.css \
    && echo "test script.js" > /tmp/static/js/script.js \
    && echo "test resource.txt" > /tmp/static/other/resource.txt \
    && echo "test file.txt" > /tmp/static/upload/file.txt

EXPOSE 80

ENV IMAGE_NAME=JavaSecLab

ENTRYPOINT ["java", "-jar", "JavaSecLab.jar"]
