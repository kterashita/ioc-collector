FROM python:3.8.12-alpine3.15
LABEL maintainer "Kenichi Terashita"
LABEL version "0.0.1"
RUN echo "http://dl-4.alpinelinux.org/alpine/v3.8/main" >> /etc/apk/repositories && \
    echo "http://dl-4.alpinelinux.org/alpine/v3.8/community" >> /etc/apk/repositories
RUN set -x &&\
    apk update &&\
    apk add py3-lxml &&\
    apk add gcc build-base libffi-dev &&\
    apk add chromium chromium-chromedriver
ADD ./ioc-collector.py /home/
ADD ./config.yaml /home/
ADD ./requirements.txt /home/
RUN set -x &&\
    pip3 install -r /home/requirements.txt
RUN chmod +x /home/ioc-collector.py
