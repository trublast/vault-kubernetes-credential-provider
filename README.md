⚠️ Alpha Release Notice

This project is in very early development and should be considered Alpha software. Expect significant changes, incomplete features, and potential breaking changes between releases.

# Vault Kubernetes Credential Provider

This credential provider enables Kubernetes to automatically authenticate with container registries using credentials stored in Hashicorp Vault. It implements the [Kubelet Credential Provider](https://kubernetes.io/docs/tasks/kubelet-credential-provider/kubelet-credential-provider/) interface, following [KEP-4412](https://github.com/kubernetes/enhancements/blob/master/keps/sig-auth/4412-projected-service-account-tokens-for-kubelet-image-credential-providers/README.md) for supporting service account token authentication for image pulls.

## Features

- **Service Account Token Authentication**: Uses ephemeral Kubernetes service account tokens to authenticate with Vault
- **Vault Kubernetes Auth**: Leverages Vault's Kubernetes authentication method for secure token exchange
- **Dynamic Configuration**: Supports pod-level configuration via service account annotations
- **Flexible Secret Paths**: Configurable Vault secret paths per service account
- **Security-First Design**: Eliminates the need for storing static credentials in the cluster

## How It Works

The credential provider works by:

1. **Token Generation**: Kubelet generates a service account token bound to the specific pod requesting image pull
2. **Plugin Invocation**: Kubelet calls the credential provider with the token and service account annotations
3. **Vault Authentication**: Plugin authenticates with Vault using the Kubernetes auth method and the service account token
4. **Secret Retrieval**: Plugin reads registry credentials (login and password) from the specified Vault path
5. **Image Pull**: Kubelet uses the returned credentials to authenticate with the container registry

## Configuration

### Provider Configuration File

The credential provider can be configured via a configuration file. Example:

```yaml
vault_address: "https://vault.example.com:8200"
kubernetes_auth_role: "kubernetes-role"
kubernetes_auth_mount_path: "kubernetes"
log_level: "info"
insecure_skip_verify: false
http_timeout: 30s
```

Configuration options:
- `vault_address` (required): Address of the Vault server (default: `https://127.0.0.1:8200`)
- `kubernetes_auth_role` (required): Vault role name for Kubernetes authentication
- `kubernetes_auth_mount_path` (optional): Mount path for Kubernetes auth method (default: `kubernetes`)
- `log_level` (optional): Logging level: debug, info, warn, error (default: `info`)
- `insecure_skip_verify` (optional): Skip TLS certificate verification (default: `false`)
- `http_timeout` (optional): HTTP request timeout (default: `30s`)

### Service Account Annotations

The following annotations can be set on the ServiceAccount to override default configuration:

- `secrets-store.deckhouse.io/addr`: Override Vault address for this service account
- `secrets-store.deckhouse.io/auth-path`: Override Kubernetes auth mount path for this service account
- `secrets-store.deckhouse.io/registry-credentials`: Path to Vault secret containing registry credentials (required)

The Vault secret at the specified path must contain:
- `login` or `username`: Registry username
- `password`: Registry password

The secret can be stored in KV v1 or KV v2 format.

## Building

To build the credential provider:

```bash
# Using Makefile (recommended)
make build

# Or using go build directly
go build -o vault-kubernetes-credential-provider .
```

**Note**: Always use the `-o` flag to specify the output binary name. Without it, `go build` will use the directory name which may not match the expected binary name.

## Prerequisites

- **Kubernetes 1.33+** for service account token authentication support (KEP-4412)
- **Hashicorp Vault** with Kubernetes authentication method enabled
- **Vault Role** configured for Kubernetes authentication with appropriate policies

## Vault Setup

### 1. Enable Kubernetes Auth Method

```bash
vault auth enable kubernetes
```

### 2. Configure Kubernetes Auth

```bash
vault write auth/kubernetes/config \
    token_reviewer_jwt="<service-account-jwt>" \
    kubernetes_host="https://kubernetes.default.svc:443" \
    kubernetes_ca_cert=@/path/to/ca.crt
```

### 3. Create Vault Role

```bash
vault write auth/kubernetes/role/kubernetes-role \
    bound_service_account_names=default \
    bound_service_account_namespaces=default \
    policies=registry-credentials-policy \
    ttl=1h
```

### 4. Create Policy for Registry Credentials

```bash
vault policy write registry-credentials-policy - <<EOF
path "secret/data/registry/*" {
  capabilities = ["read"]
}
EOF
```

### 5. Store Registry Credentials in Vault

For KV v2:
```bash
vault kv put secret/registry/my-registry \
    login="myuser" \
    password="mypassword"
```

For KV v1:
```bash
vault write secret/registry/my-registry \
    login="myuser" \
    password="mypassword"
```

## Kubernetes Configuration

### 1. Create Credential Provider Config

```yaml
apiVersion: kubelet.config.k8s.io/v1
kind: CredentialProviderConfig
providers:
  - name: vault-kubernetes-credential-provider
    matchImages:
      - "registry.example.com"
      - "*.example.com"
    defaultCacheDuration: "1h"
    apiVersion: credentialprovider.kubelet.k8s.io/v1
    env:
      - name: VAULT_ADDRESS
        value: "https://vault.example.com:8200"
      - name: VAULT_KUBERNETES_AUTH_ROLE
        value: "kubernetes-role"
    tokenAttributes:
      requireServiceAccount: true
      optionalServiceAccountAnnotationKeys:
        - "secrets-store.deckhouse.io/addr"
        - "secrets-store.deckhouse.io/auth-path"
        - "secrets-store.deckhouse.io/registry-credentials"
```

### 2. Configure RBAC

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: node-credential-providers
rules:
- apiGroups: [""]
  resources: ["serviceaccounts"]
  verbs: ["get", "list"]
- verbs: ["request-serviceaccounts-token-audience"]
  apiGroups: [""]
  resources: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: node-serviceaccount-wide-access-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: node-credential-providers
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: system:node:<node-name>
```

### 3. Install the Plugin

Copy the `vault-kubernetes-credential-provider` binary to the kubelet's credential provider binary directory (typically `/usr/local/bin` or as configured in `image-credential-provider-bin-dir`).

Make sure the binary is executable:
```bash
chmod 755 /usr/local/bin/vault-kubernetes-credential-provider
```

## Usage Example

### Service Account with Annotations

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service-account
  annotations:
    secrets-store.deckhouse.io/registry-credentials: "secret/data/registry/my-registry"
    # Optional: override Vault address
    secrets-store.deckhouse.io/address: "https://vault.example.com:8200"
    # Optional: override Kubernetes auth mount path
    secrets-store.deckhouse.io/auth-path: "custom-kubernetes"
---
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  serviceAccountName: my-service-account
  containers:
  - name: app
    image: registry.example.com/myapp:latest
    imagePullPolicy: Always
```

## Environment Variables

The provider supports configuration via environment variables with the `VAULT_` prefix:

- `VAULT_ADDRESS`: Vault server address
- `VAULT_KUBERNETES_AUTH_ROLE`: Kubernetes auth role name
- `VAULT_KUBERNETES_AUTH_MOUNT_PATH`: Kubernetes auth mount path
- `VAULT_LOG_LEVEL`: Logging level
- `VAULT_INSECURE_SKIP_VERIFY`: Skip TLS verification (true/false)
- `VAULT_HTTP_TIMEOUT`: HTTP timeout duration

## Troubleshooting

### Check Plugin Logs

The credential provider logs to stderr. Check kubelet logs or systemd journal for credential provider output:

```bash
journalctl -u kubelet | grep vault-kubernetes-credential-provider
```

### Verify Vault Authentication

Test Vault authentication manually:

```bash
vault write auth/kubernetes/login \
    role=kubernetes-role \
    jwt="<service-account-token>"
```

### Verify Secret Access

Ensure the Vault role has permissions to read the secret:

```bash
vault read secret/data/registry/my-registry
```

## Security Considerations

- **Least Privilege**: Configure Vault policies to grant minimal required access
- **Token TTL**: Set appropriate TTLs for Vault tokens
- **TLS**: Always use TLS for Vault connections in production
- **Network Policies**: Restrict network access to Vault from nodes
- **Audit Logging**: Enable Vault audit logging for credential access tracking

## License

[Add your license information here]
