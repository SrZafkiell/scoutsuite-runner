FROM python:3.11-slim

ARG SCOUTSUITE_VERSION=5.14.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir ScoutSuite==${SCOUTSUITE_VERSION}

WORKDIR /work

ENTRYPOINT ["scout"]
