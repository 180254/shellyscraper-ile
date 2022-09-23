# https://github.com/GoogleContainerTools/distroless/blob/main/examples/python3-requirements/Dockerfile
FROM debian:11-slim AS build
RUN apt-get update && \
    apt-get install --no-install-suggests --no-install-recommends --yes python3-venv gcc libpython3-dev && \
    python3 -m venv /venv && \
    /venv/bin/pip install --upgrade pip setuptools wheel

FROM build AS build-venv
COPY requirements.txt /requirements.txt
RUN /venv/bin/pip install --disable-pip-version-check -r /requirements.txt

FROM gcr.io/distroless/python3-debian11:latest
USER nonroot
WORKDIR /app
COPY --from=build-venv /venv /venv
COPY shellyscraper.py /app
ENTRYPOINT ["/venv/bin/python3", "-u", "/app/shellyscraper.py"]
