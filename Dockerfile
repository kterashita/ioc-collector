FROM python:3.8.12-alpine3.15
LABEL maintainer "Kenichi Terashita"
LABEL version "0.0.1"
RUN set -x &&\
    apk update &&\
    apk add py3-lxml &&\
    apk add gcc build-base libffi-dev
ADD ./ioc-collector.py /home/
ADD ./config.yaml /home/
ADD ./requirements.txt /home/
RUN set -x &&\
    pip3 install -r /home/requirements.txt
RUN chmod +x /home/ioc-collector.py
