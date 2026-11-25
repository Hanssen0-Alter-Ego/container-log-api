FROM docker:29-cli AS docker-cli
FROM python:3.12-alpine
LABEL org.opencontainers.image.source="https://github.com/Hanssen0-Alter-Ego/container-log-api"
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY server.py .
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python3", "/app/server.py"]
