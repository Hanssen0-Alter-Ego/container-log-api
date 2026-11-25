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

## Read-only MCP

The same image serves stateless Streamable HTTP at `/mcp` (Bearer header) or
`/t/<token>/mcp` (URL-safe local path token). It exposes only
`list_containers`, `list_log_sources` and `read_logs`. Tool discovery requires
authentication. `read_logs` accepts configured IDs only and at most 200 lines
per call (default 40); ask for fewer lines if the response is too large. Treat
log contents as untrusted data. The existing REST endpoints are unchanged.

For a private ChatGPT connection, keep Compose on `127.0.0.1:8085` and run
OpenAI's [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
on the same host. Create the tunnel, associate the intended ChatGPT workspace,
and use a runtime key, not an admin key. With the official
[`tunnel-client`](https://github.com/openai/tunnel-client/releases/latest)
installed, run from the Compose directory in Bash:

```bash
export CONTROL_PLANE_TUNNEL_ID='<your tunnel ID>'
read -rsp 'Tunnel runtime key: ' CONTROL_PLANE_API_KEY; echo
export CONTROL_PLANE_API_KEY
export MCP_SERVER_URL="http://127.0.0.1:8085/t/$(sudo cat config/token)/mcp"
tunnel-client doctor --explain
tunnel-client run
```

In ChatGPT, select **Plugins → Add custom MCP server → Tunnel**, select that
tunnel, and install the private plugin. Select **No authentication** for this
tunnel-only configuration: the local upstream URL already authenticates to
the app. Do not paste the upstream URL or either secret into ChatGPT, use a
public reverse proxy, or enable raw URL logging on this route. Keep the
tunnel process running for discovery and tool calls.

### Optional: host CPU, RAM, mounted capacity and journal (Linux/systemd)

The API container does not enter the host PID/mount namespaces and does not mount
the host root or raw journal. A small host-side systemd timer publishes snapshots
to a dedicated directory. Leave this section unconfigured to preserve the original
tool list and behavior. This is on-demand inspection, not a time-series database
or alert engine.

On the **host**, from a checkout of this repository:

```sh
sudo install -d -m 0755 /usr/local/lib/container-log-api
sudo install -d -o root -g 65532 -m 0750 /var/lib/container-log-observer
sudo install -m 0644 host-observer/collect.py /usr/local/lib/container-log-api/
sudo install -m 0644 host-observer/container-log-observer@.service host-observer/container-log-observer@.timer /etc/systemd/system/
sudo install -D -m 0644 host-observer/journal-allowlist.conf \
  /etc/systemd/system/container-log-observer@journal.service.d/allowlist.conf
sudo systemctl daemon-reload
sudo systemctl start container-log-observer@metrics.service container-log-observer@journal.service
sudo systemctl enable --now container-log-observer@metrics.timer container-log-observer@journal.timer
```

The journal example exports only kernel messages and `docker.service`. Review
your logs before enabling either source, especially if forwarding to a remote
MCP client. To change the whitelist, edit the installed `allowlist.conf`, remove
the unwanted sources from the API config, reload systemd, and restart the journal
snapshot service. Old exports of removed sources can be deleted on the host.
Never export sensitive units unless you intend to share that output with all
users of this API token. No caller can supply journalctl flags or unit names.

Merge the mount from `host-observer/compose.host-observer.yaml` into your Compose
file under `services.log-api.volumes` (or include it as a second Compose file).
In `config/config.json`, add the top-level field
`"host_snapshot_dir": "/host-observer"` and append the desired entries to your
existing `sources` array:

```json
[
  {"id":"host-kernel","kind":"journal","path":"/host-observer/journal-kernel.log"},
  {"id":"host-docker","kind":"journal","path":"/host-observer/journal-docker.service.log"}
]
```

Recreate the API container with the new image and mount. The MCP tools
`get_host_metrics` (one-second aggregate CPU sample, I/O wait, load, RAM and
swap) and `list_filesystems` (root and storage mount points, including bind,
network and read-only mounts where visible, excluding pseudo/container-overlay
mounts) include `sampled_at`. Check its age before relying on a snapshot.
Capacity is per mounted host filesystem, not per Docker named volume or
unmounted disk; separate mount points can share the same backing capacity.
`list_filesystems` uses `offset` and `limit`; follow `next_offset` if present.
Journal exports hold up to 250 recent entries per configured source, as retained
by the host journal. Use `list_log_sources` and `read_logs` as for file sources.
This does not run journalctl on demand or search the host's entire backlog.
If ChatGPT has cached the MCP tool list, refresh tools in the app after deployment.
