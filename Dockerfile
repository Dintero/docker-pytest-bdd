FROM python:3.10.8-alpine3.16

RUN apk --no-cache --update add openssl libffi patch
COPY requirements.txt .
RUN apk --no-cache --update add --virtual build-dependencies build-base libffi-dev openssl-dev \
  && pty=False python3 -m pip install --disable-pip-version-check -r requirements.txt \
  && apk del build-dependencies
