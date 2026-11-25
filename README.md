# Container Log API

Private-network, read-only HTTP access to an explicit list of Docker container logs and regular files, plus authenticated Docker inventory. The API does not collect logs. A token is required for every request.

## Deploy with Docker Compose

Copy [compose.yaml](compose.yaml) and [config.example.json](config.example.json) into your deployment directory. Before starting:

```sh
mkdir -p config host-logs
cp config.example.json config/config.json
printf 'DOCKER_SOCKET_GID=%s\n' "$(stat -c '%g' /var/run/docker.sock)" > .env
(umask 077; openssl rand -hex 32 > config/token)
sudo chown 65532:65532 config/token
# Edit config/config.json and the file-log bind mount in compose.yaml.
docker compose pull
docker compose up -d
```

The image is `ghcr.io/hanssen0-alter-ego/container-log-api:latest` (Linux amd64). CI also publishes immutable-by-convention tags `sha-<full-commit>`. Set each Docker source's `container` to its real Docker container name. Replace `./host-logs` with the **specific existing host log directory** (e.g. a CKBadger `run/logs` directory). The application runs as UID/GID 65532; ensure this user can traverse the bound log directory and read the configured files. If you only need file sources, remove the socket mount and `group_add`. If you only need Docker, remove the file source and corresponding mount. Changes to configuration require a container restart.

It listens on host loopback port 8085 by default. For remote access, use an authenticated private network or VPN and TLS via your existing Caddy; do not expose the service or forward these logs to an untrusted location. Docker socket access is effectively host root on standard rootful Docker, even with a `:ro` bind flag. Only run the socket-enabled variant on a trusted host; the allowlist narrows what clients can ask this app for, not what a compromised process can do. The API returns raw logs, which may contain secrets: configure only sources appropriate for the reader. Do not configure a file directory writable by an untrusted user or container if it can replace the selected files. Symlinks and special files are rejected.

## HTTP API

Prefer `Authorization: Bearer <token>` when the client can set it. For clients that cannot, prefix any endpoint with `/t/<token>`:

- List: `GET /t/<token>/v1/sources`
- Read: `GET /t/<token>/v1/sources/<id>/lines?mode=tail&limit=1000`
- Docker inventory: `GET /t/<token>/v1/containers` (add `?all=1` to include stopped containers)

The path token uses the same token file and must be URL-safe; the recommended 64-character hex token works unchanged. Query-string tokens are not accepted. This is a REST API, not an MCP server. The app does not log request URLs, but reverse proxies, tracing, browser history, and clients can record paths. Use HTTPS for remote access and disable or redact raw URL logging and tracing on this route. If an unredacted URL is captured or shared, rotate the token.

```sh
# Put the bearer token in a private curl config file, not in shell history.
base=http://127.0.0.1:8085/v1/sources
curl -fsS --config ~/.config/container-log-api.curl "$base"
curl -fsS --config ~/.config/container-log-api.curl "$base/blockbook-mainnet/lines?mode=head&limit=1000"
curl -fsS --config ~/.config/container-log-api.curl "$base/blockbook-mainnet/lines?mode=tail&limit=1000"
curl -fsS --config ~/.config/container-log-api.curl "$base/ckbadger-indexer/lines?offset=1000&limit=1000"
```

The private curl config is a mode-0600 file with a line of the form `header = "Authorization: Bearer <token>"`. If it is on the same server, a user with access to the token file can pipe a curl config via stdin instead.

- `GET /v1/sources` lists configured IDs and kinds, **not** absolute paths or Docker container names.
- `GET /v1/containers` returns `{containers: [{id, name, image, state, status, ports}]}` for the host's running containers, including those without configured log sources. Add `?all=1` to include stopped containers. The `ports` string is the Docker CLI `PORTS` column, including published host mappings and exposed ports when available; it does not enumerate host-network listeners. Anyone with the token can see these fields. It does not grant access to unconfigured logs or expose container environment variables, mounts, labels or commands. This endpoint requires the Docker socket.
- `GET /v1/sources/{id}/lines` returns `{id,mode,offset,lines}` as JSON. The default `head` mode accepts a zero-based `offset` (default 0); `tail` reads the last lines in source order and does not accept an offset. Both take `limit` (1 to 1000, default 1000). An offset past EOF returns an empty array.
- Docker lines include daemon timestamps and combine stdout and stderr. The source must have a logging driver compatible with `docker logs`; results reflect the history Docker retains for the named container. File mode reads only the configured current file, not rotated siblings. Files that rotate between requests and recreated containers are not stable snapshots.
- Reads are bounded to a 64 MiB scan, a 2 MiB log-response budget, a 12-second read budget, and offsets through 1,000,000 lines. File tails seek backward and Docker tails pass `--tail` to the daemon. Large offsets scan from the beginning; requests exceeding a budget return an explicit error instead of silently clipping. A page at EOF may have fewer than `limit` lines. Oversized reads return 413; unavailable sources return 502; timeouts return 504.

## Test

`python3 -m unittest -v` exercises both source types through real HTTP using a fixture for the Docker CLI. GitHub Actions builds the image and tests reading logs with a real Docker daemon before publishing the tested image.
