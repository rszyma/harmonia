# harmonia

Harmonia is a binary cache for nix that serves your /nix/store as a binary cache over http.
It's written in Rust for speed.

## Features

- http-ranges support for nar file streaming
- streaming build logs
- .ls file streaming
  - Note: doesn't contain `narOffset` in json response but isn't needed for
    `nix-index`
- Add `/serve/<narhash>/` endpoint to allow serving the content of package. 
  Also discovers index.html to allow serving websites directly from the nix store.
- Content is compressed transparently with [zstd](https://en.wikipedia.org/wiki/Zstd).
- Builtin TLS: when no frontend webserver is used, Harmonia can also provide TLS encryption
- Optional pull-through from upstream binary caches into the local `/nix/store`

## Configuration for public binary cache on NixOS

### Using NixOS stable (from nixpkgs)

There is a module for harmonia in nixpkgs.
The following example set's up harmonia as a public binary cache using
nginx as a frontend webserver with https encryption:

```nix
{ config, pkgs, ... }: {
  services.harmonia.cache.enable = true;
  # FIXME: generate a public/private key pair like this:
  # $ nix-store --generate-binary-cache-key cache.yourdomain.tld-1 /var/lib/secrets/harmonia.secret /var/lib/secrets/harmonia.pub
  services.harmonia.cache.signKeyPaths = [ "/var/lib/secrets/harmonia.secret" ];
  # Example using sops-nix to store the signing key
  #services.harmonia.signKeyPaths = [ config.sops.secrets.harmonia-key.path ];
  #sops.secrets.harmonia-key = { };

  # optional if you use allowed-users in other places
  #nix.settings.allowed-users = [ "harmonia" ];

  networking.firewall.allowedTCPPorts = [ 443 80 ];

  # FIXME: replace this with your own email
  security.acme.defaults.email = "yourname@youremail.com";
  security.acme.acceptTerms = true;

  services.nginx = {
    enable = true;
    recommendedTlsSettings = true;
    # FIXME: replace "cache.yourdomain.tld" with your own domain.
    virtualHosts."cache.yourdomain.tld" = {
      enableACME = true;
      forceSSL = true;

      locations."/".extraConfig = ''
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_redirect http:// https://;
        proxy_http_version 1.1;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
      '';
    };
  };
}
```

### Using the flake version (latest features)

To use the latest version with all features, import the harmonia flake:

```nix
# flake.nix
{
  inputs.harmonia.url = "github:nix-community/harmonia";
  # ... other inputs
}

# configuration.nix
{ inputs, config, pkgs, ... }: {
  imports = [ inputs.harmonia.nixosModules.harmonia ];

  services.harmonia-dev.cache.enable = true;
  # FIXME: generate a public/private key pair like this:
  # $ nix-store --generate-binary-cache-key cache.yourdomain.tld-1 /var/lib/secrets/harmonia.secret /var/lib/secrets/harmonia.pub
  services.harmonia-dev.cache.signKeyPaths = [ "/var/lib/secrets/harmonia.secret" ];

  # All other nginx configuration remains the same as above
  networking.firewall.allowedTCPPorts = [ 443 80 ];

  services.nginx = {
    enable = true;
    recommendedTlsSettings = true;
    virtualHosts."cache.yourdomain.tld" = {
      enableACME = true;
      forceSSL = true;
      locations."/".extraConfig = ''
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_redirect http:// https://;
        proxy_http_version 1.1;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
      '';
    };
  };
}
```

You can use the binary cache on a different machine using the following NixOS configuration:

```nix
{
  nix.settings = {
    substituters = [ "https://cache.yourdomain.tld" ];
    # FIXME replace the key with the content of /var/lib/secrets/harmonia.pub
    trusted-public-keys = [ "cache.yourdomain.tld-1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ];
  };
}
```

## Configuration format

Configuration is done via a `toml` file.
**Hint:** You don't need to interface with the configuration directly in case you are using the NixOS module.
The location of the configuration file should be passed as env var `CONFIG_FILE`. If no config file is passed the
following default values will be used:

```toml
# default ip:hostname to bind to
bind = "[::]:5000"
# unix socket are also supported
# bind = "unix:/run/harmonia/socket"
# Sets number of workers to start in the webserver
workers = 4
# Sets the per-worker maximum number of concurrent connections.
max_connection_rate = 256
# binary cache priority that is advertised in /nix-cache-info
priority = 30
# Whether to enable transparent compression with zstd.
# Default: true
enable_compression = true

# Allow to override the store path advertised in /nix-cache-info
# virtual_nix_store = "/nix/store"
# Allow to serve the nix store from a different physical location
# Default: empty
# Example: if you use `nix copy --store /guest` to populate a store than configure:
# real_nix_store = "/guest/nix/store"

# Path to the nix SQLite database. Harmonia reads store metadata directly from
# this file (only pull-through imports use the nix-daemon). Derived from the store layout
# by default; override only for non-standard state directories.
# nix_db_path = "/nix/var/nix/db/db.sqlite"
```

Per default we wont sign any narinfo because we don't have a secret key, to
enable this feature enable it by providing a path to a private key generated by
`nix-store --generate-binary-cache-key cache.example.com-1 /etc/nix/cache.secret /etc/nix/cache.pub`

```toml
# nix binary cache signing key
sign_key_paths = [ "/run/secrets/cache.secret" ]
```

Harmonia also reads the `SIGN_KEY_PATHS` environment variable which holds paths to secret keys separated by spaces.
All paths provided by `sign_key_paths` config option and `SIGN_KEY_PATHS` environment variable will be used for signing.

### Pull-through from upstream caches

With `upstream_caches` set,
Harmonia serves store paths that are missing locally from upstream binary caches,
and imports them into the local store as a side effect.
The cache host then has everything it served in its own `/nix/store`,
usable like any other store path.

```toml
# Tried in the listed order; the first upstream that has a path wins.
# Unlike Nix substituters, there is no priority weighting.
upstream_caches = [ "https://cache.nixos.org" ]
# Imports go through this daemon (the default).
# nix_daemon_socket = "/nix/var/nix/daemon-socket/socket"
# Stop an upstream download when all clients that stream it disconnected
# for 10 seconds. By default it continues and the path is imported anyway.
# upstream_cancel_on_disconnect = false
```

How a miss is handled:

- A narinfo request returns the upstream path info in Harmonia's own format
  (`Compression: none`, a NAR URL on this cache),
  with the upstream signatures only.
  Harmonia does not add its own signatures to paths that it did not verify yet,
  so a client that trusts only Harmonia's key rejects a path until it is imported,
  and falls back to its next substituter.
  Nothing is downloaded for a narinfo request.
- A NAR request starts one download for the path.
  Concurrent requests for the same path join it.
  The download decompresses the upstream NAR (xz, zstd, bzip2 or none),
  checks it against `NarHash` and `NarSize`,
  and writes it to a temp file that all clients stream from at their own pace.
  A client never receives the last byte of a NAR that failed the check.
- When the download is complete,
  Harmonia adds the path to the local store with the Nix daemon (`AddToStoreNar`),
  from the temp file, so every NAR is downloaded only once.
  References that are not valid locally are pulled first in the same way,
  because the store only accepts paths whose references are valid.

HTTPS upstreams are verified against the system CA store
(on NixOS: `security.pki`).
`SSL_CERT_FILE` and `SSL_CERT_DIR` replace the system locations.
Harmonia refuses to start if an HTTPS upstream is configured and no CA certificate is found.

The daemon checks the upstream signatures against its `trusted-public-keys`,
like for a substituter.
A path without a trusted signature is still served
(the client checks signatures itself),
but it is not imported.
After the import, the same path is served from the local store
with the same narinfo apart from local signatures,
so narinfos that clients cached during the pull stay valid.

Downloads are buffered in `$TMPDIR`.
A temp file lives until its import ended and its last client finished.

With the NixOS module, use `services.harmonia-dev.cache.pullThrough`.
It also allows outbound network access for the service:

```nix
services.harmonia-dev.cache.pullThrough = {
  enable = true;
  upstreamCaches = [ "https://cache.nixos.org" ];
};
```

### TLS Configuration

Harmonia can serve content over HTTPS without requiring a reverse proxy. To enable TLS, specify the paths to your certificate and private key files in the configuration:

```toml
# Path to TLS certificate (PEM format)
tls_cert_path = "/path/to/cert.pem"
# Path to TLS private key (PEM format)
tls_key_path = "/path/to/key.pem"
```

Requirements for TLS certificates:
- Certificate must be in PEM format
- Certificate must be X.509 v3 (rustls does not support older versions)
- Private key can be in either PKCS#8 or RSA format
- Both files must be readable by the harmonia process

Example generating a self-signed certificate for testing:
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/C=US/ST=State/O=Organization/CN=cache.example.com"
```

Note: When TLS is enabled, harmonia will only accept HTTPS connections on the configured port.

### Logging Configuration

Logging is handled by [tracing](https://docs.rs/tracing) and configured via the
`RUST_LOG` environment variable using
[EnvFilter](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html)
syntax (compatible with the familiar `env_logger` directives). The default
filter is `info`. To only log errors use `RUST_LOG=error`, and to keep info
messages while disabling actix access logging use
`RUST_LOG=info,actix_web::middleware=error`.

## Build

### Whole application

```bash
nix build -L
```

### Get a development environment:

``` bash
nix develop
```

## Run tests

```bash
nix flake check -L
```


## Prometheus Monitoring

Harmonia exposes Prometheus metrics at the `/metrics` endpoint for monitoring and observability.

### Available Metrics

**HTTP Request Metrics:**
- `harmonia_http_requests_total` - Total number of HTTP requests (labeled by method, path, and status code)
- `harmonia_http_request_duration_seconds` - Request latency histogram with buckets ranging from 0.0001s to 1.0s

### Grafana Dashboard

A pre-configured Grafana dashboard is available in the repository at `harmonia-cache/harmonia-grafana-dashboard.json`. This dashboard visualizes:
- Request rate and latency patterns
- HTTP status code distribution
- Error rates and performance trends

You can import this dashboard into your Grafana instance to monitor your Harmonia deployment.

### Example Prometheus Configuration

To scrape metrics from Harmonia, add the following to your Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'harmonia'
    static_configs:
      - targets: ['your-harmonia-host:5000']
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and code style guidelines. For architecture details, see [docs/architecture](docs/architecture/).

## Inspiration

- [eris](https://github.com/thoughtpolice/eris)
