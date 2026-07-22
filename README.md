# ACME certificate service

This service obtains TLS certificates through an ACME HTTP-01 challenge and
stores autocert's opaque certificate and ACME-account cache entries in Scaleway
Secret Manager. Secret Manager encrypts every version at rest. Set
`scaleway.key_id` to use a customer-managed Scaleway Key Manager key.

## Run

The service must be reachable by every requested domain on TCP port 80. Point
each domain's DNS record to the service before starting it.

Create a private `config.yaml` from the structure in `config.example.yaml`. The
example uses `${SCW_ACCESS_KEY}` and `${SCW_SECRET_KEY}`, which are expanded
from the process environment. Define those values in the ignored `.env` file
using `.env.example` as its field reference, then run:

```sh
set -a
. ./.env
set +a
go run ./cmd/autocert --config config.yaml
```

The required API key permissions are sufficient to list, create, access, and
disable Secret Manager secrets and versions in `scaleway.project_id`.

## Test with Let's Encrypt staging

Use the staging ACME directory before requesting production certificates. It
performs the same ACME HTTP-01 flow but issues untrusted test certificates and
does not consume Let's Encrypt production issuance limits.

```yaml
acme:
  directory_url: https://acme-staging-v02.api.letsencrypt.org/directory
scaleway:
  secret_prefix: autocert-staging
```

Use a distinct `scaleway.secret_prefix` for staging and production. Autocert caches
certificates by domain, so sharing a prefix would let a valid-but-untrusted
staging certificate be reused in the production run. For production, omit
`acme.directory_url` and use a separate prefix such as `autocert-production`.

For fully local protocol tests, run an ACME test CA such as Let's Encrypt
Pebble and set `acme.directory_url` to its directory endpoint. HTTP-01 still
requires the configured domain and port 80 to be reachable by that CA.

## Configuration

| YAML field | Required | Default | Description |
| --- | --- | --- | --- |
| `domains` | Yes | | DNS names. Wildcards are not supported by HTTP-01. |
| `scaleway.access_key` | Yes | | Scaleway API access key. |
| `scaleway.secret_key` | Yes | | Scaleway API secret key. |
| `scaleway.project_id` | Yes | | Scaleway project that owns the secrets. |
| `acme.email` | No | | ACME account contact email. |
| `acme.directory_url` | No | Let's Encrypt production directory | Generic ACME directory, allowing another ACME provider. |
| `http_address` | No | `:80` | Address used for HTTP-01 challenge responses. |
| `scaleway.region` | No | `fr-par` | Scaleway Secret Manager region. |
| `scaleway.key_id` | No | | Customer-managed Scaleway Key Manager key ID for secret encryption. |
| `scaleway.secret_prefix` | No | `autocert` | Prefix for deterministic Secret Manager secret names. |

`/healthz` returns `204 No Content`. All other non-ACME requests return `404`.
The configuration parser rejects unknown YAML fields and expands `${VARIABLE}`
references from the process environment. Both `.env` and `config.yaml` are
ignored by Git; keep credentials in `.env` rather than committing them.

## Container and Kubernetes

`Containerfile` builds a static, non-root image. Build it with:

```sh
docker build -f Containerfile -t autocert:local .
```

The Helm chart is in `charts/autocert`. It creates a LoadBalancer Service on
port 80, mounts the rendered YAML configuration, and reads Scaleway credentials
from an existing Kubernetes Secret. See `charts/autocert/README.md` for the
required values and installation commands. Keep the release at one replica
during initial issuance and use a separate `scaleway.secretPrefix` for staging
and production.

## Future deployment targets

The issued PEM material remains in the autocert cache entries in Secret Manager.
Deployment adapters for Cloudflare and Fastly can read these entries through the
same cache contract without changing ACME issuance.
