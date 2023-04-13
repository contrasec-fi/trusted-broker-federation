FROM debian:buster-slim AS build
RUN apt-get update && \
    apt-get install --no-install-suggests --no-install-recommends --yes python3-venv gcc libpython3-dev && \
    python3 -m venv /venv && \
    /venv/bin/pip install --upgrade pip

FROM build AS build-venv
COPY requirements.txt /requirements.txt
RUN /venv/bin/pip install --disable-pip-version-check -r /requirements.txt

ENV PROVIDER_CLIENT_ID=EU.EORI.PROVIDER
ENV CONSUMER_CLIENT_ID=EU.EORI.CONSUMER
ENV KEYROCK_URL=http://127.0.0.1:3000
ENV KEYROCK_AUTHZ_URL=http://127.0.0.1:3000/oauth2/authorize?
ENV KEYROCK_TOKEN_URL=http://127.0.0.1:3000/oauth2/token
ENV SCORPIO_URL=http://127.0.0.1:9090
ENV PRIVATE_KEY_FILE=private_key
ENV X5C_VALUE_FILE=x5c_value
ENV CONSUMER_EMAIL=johndoe@example.com
ENV APP_URL=http://127.0.0.1:5000
ENV PYTHONUNBUFFERED=1

FROM gcr.io/distroless/python3-debian10:nonroot
COPY --from=build-venv /venv /venv
COPY . /app
WORKDIR /app
EXPOSE 5000
ENTRYPOINT [ "/venv/bin/waitress-serve", "--call", "wsgi:serve" ]
