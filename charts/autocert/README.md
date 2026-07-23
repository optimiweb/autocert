# autocert Helm chart

The chart deploys one ACME HTTP-01 issuer backed by Scaleway Secret Manager.
It creates a LoadBalancer Service on port 80 and configures the application to
listen on unprivileged port 8080 in the Pod.

Create a Kubernetes Secret containing the Scaleway API credentials in the same
namespace as the release:

```sh
kubectl create secret generic autocert-scaleway \
  --from-literal=SCW_ACCESS_KEY=... \
  --from-literal=SCW_SECRET_KEY=...
```

Deploy with a values file containing at least:

```yaml
image:
  repository: ghcr.io/optimiweb/autocert
  tag: latest

domains:
  - example.com

acme:
  email: ops@example.com
  # Test first with the staging directory.
  directoryURL: https://acme-staging-v02.api.letsencrypt.org/directory

scaleway:
  projectID: your-scaleway-project-id
  secretPrefix: autocert-staging
  existingSecret:
    name: autocert-scaleway
```

```sh
helm upgrade --install autocert ./charts/autocert -f values.yaml
```

Point every configured domain to the LoadBalancer address before the issuer
starts. The chart rejects `replicaCount` greater than `1` and uses a `Recreate`
strategy so two issuers cannot race ACME or Secret Manager writes. Use a
different `scaleway.secretPrefix` and omit `acme.directoryURL` for production,
so a staging certificate cannot be read from the production cache.

The process stays up and retries failed initial issuance with capped backoff,
which avoids Kubernetes crash loops consuming ACME validation limits. It logs
periodic certificate-check failures, but certificate expiration should also be
monitored externally. Secret Manager retains disabled cache versions, so monitor
the service's version quota and configure retention according to your policy.

Secret Manager entries use readable names and typed payloads:
`<prefix>-account-key` (opaque), `<prefix>-cert-<domain>` (certificate), and
`<prefix>-http01-<hash>` (opaque). Use a distinct `scaleway.secretPrefix` for
staging and production.

The Secret must contain keys named `SCW_ACCESS_KEY` and `SCW_SECRET_KEY` by
default. Set `scaleway.existingSecret.accessKeyKey` and
`scaleway.existingSecret.secretKeyKey` when using different key names.
