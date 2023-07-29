FROM python:3.10.12-alpine3.18 as builder
RUN apk --no-cache add build-base openssl-dev libffi-dev
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN --mount=type=cache,target=/root/.cache pip install wheel
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache python3 -m pip install -r requirements.txt

FROM python:3.10.12-alpine3.18
RUN apk --no-cache --update add openssl libffi patch
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
