package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	credentialproviderapi "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type VaultCredentialProvider struct {
	config *Config
	client *api.Client
}

func NewVaultCredentialProvider(cfg *Config) (*VaultCredentialProvider, error) {
	config := api.DefaultConfig()
	config.Address = cfg.VaultAddress

	if cfg.InsecureSkipVerify {
		tlsConfig := api.TLSConfig{
			Insecure: true,
		}
		if err := config.ConfigureTLS(&tlsConfig); err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
		klog.Warning("TLS certificate verification disabled for Vault")
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	provider := &VaultCredentialProvider{
		config: cfg,
		client: client,
	}

	klog.InfoS("Initialized Vault credential provider", "vaultAddress", cfg.VaultAddress)

	return provider, nil
}

func (v *VaultCredentialProvider) authenticateWithVault(ctx context.Context, serviceAccountToken string) (string, error) {
	klog.V(4).InfoS("Starting Kubernetes authentication with Vault",
		"role", v.config.KubernetesAuthRole,
		"mountPath", v.config.KubernetesAuthMountPath)

	authData := map[string]interface{}{
		"role": v.config.KubernetesAuthRole,
		"jwt":  serviceAccountToken,
	}

	authPath := fmt.Sprintf("auth/%s/login", v.config.KubernetesAuthMountPath)
	secret, err := v.client.Logical().WriteWithContext(ctx, authPath, authData)
	if err != nil {
		klog.ErrorS(err, "Failed to authenticate with Vault using Kubernetes auth")
		return "", fmt.Errorf("failed to authenticate with Vault: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		klog.ErrorS(nil, "Vault authentication returned empty response")
		return "", fmt.Errorf("Vault authentication returned empty response")
	}

	vaultToken := secret.Auth.ClientToken
	if vaultToken == "" {
		klog.ErrorS(nil, "Vault authentication returned empty token")
		return "", fmt.Errorf("Vault authentication returned empty token")
	}

	klog.InfoS("Successfully authenticated with Vault", "tokenLength", len(vaultToken))
	return vaultToken, nil
}

func (v *VaultCredentialProvider) getCredentialsFromVault(ctx context.Context, vaultToken string, secretPath string) (string, string, error) {
	klog.V(4).InfoS("Reading credentials from Vault", "path", secretPath)

	// Set the token for this request
	v.client.SetToken(vaultToken)

	secret, err := v.client.Logical().ReadWithContext(ctx, secretPath)
	if err != nil {
		klog.ErrorS(err, "Failed to read secret from Vault", "path", secretPath)
		return "", "", fmt.Errorf("failed to read secret from Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		klog.ErrorS(nil, "Vault secret is empty or not found", "path", secretPath)
		return "", "", fmt.Errorf("Vault secret not found at path: %s", secretPath)
	}

	// Extract login and password from the secret
	// Vault KV v2 stores data in "data" field, KV v1 stores it directly
	var data map[string]interface{}
	if dataRaw, ok := secret.Data["data"]; ok {
		// KV v2
		if dataMap, ok := dataRaw.(map[string]interface{}); ok {
			data = dataMap
		} else {
			data = secret.Data
		}
	} else {
		// KV v1 or direct data
		data = secret.Data
	}

	login, ok := data["login"].(string)
	if !ok {
		// Try "username" as alternative
		login, ok = data["username"].(string)
		if !ok {
			klog.ErrorS(nil, "Secret does not contain 'login' or 'username' field", "path", secretPath)
			return "", "", fmt.Errorf("secret at path %s does not contain 'login' or 'username' field", secretPath)
		}
	}

	password, ok := data["password"].(string)
	if !ok {
		klog.ErrorS(nil, "Secret does not contain 'password' field", "path", secretPath)
		return "", "", fmt.Errorf("secret at path %s does not contain 'password' field", secretPath)
	}

	klog.InfoS("Successfully retrieved credentials from Vault", "path", secretPath)
	return login, password, nil
}

func (v *VaultCredentialProvider) GetCredentials(ctx context.Context, req *credentialproviderapi.CredentialProviderRequest) (*credentialproviderapi.CredentialProviderResponse, error) {
	image := req.Image

	klog.InfoS("Processing credential request", "image", image)

	if req.ServiceAccountToken == "" {
		klog.ErrorS(nil, "Service account token is required but not provided")
		return nil, fmt.Errorf("service account token is required but not provided")
	}

	// Override configuration from annotations
	v.overrideFromAnnotations(req.ServiceAccountAnnotations)

	if v.config.VaultAddress == "" {
		klog.ErrorS(nil, "Vault address is required but not configured")
		return nil, fmt.Errorf("vault_address is required")
	}

	// Update client address if it was overridden
	if v.config.VaultAddress != v.client.Address() {
		v.client.SetAddress(v.config.VaultAddress)
	}

	// Get secret path from annotation
	secretPath := req.ServiceAccountAnnotations["secres-store.deckhouse.io/registry-credentials"]
	if secretPath == "" {
		klog.ErrorS(nil, "Secret path is required but not provided in annotation secres-store.deckhouse.io/registry-credentials")
		return nil, fmt.Errorf("secret path is required in annotation secres-store.deckhouse.io/registry-credentials")
	}

	// Authenticate with Vault using Kubernetes auth
	vaultToken, err := v.authenticateWithVault(ctx, req.ServiceAccountToken)
	if err != nil {
		klog.ErrorS(err, "Failed to authenticate with Vault")
		return nil, fmt.Errorf("failed to authenticate with Vault: %w", err)
	}

	// Get credentials from Vault
	login, password, err := v.getCredentialsFromVault(ctx, vaultToken, secretPath)
	if err != nil {
		klog.ErrorS(err, "Failed to get credentials from Vault")
		return nil, fmt.Errorf("failed to get credentials from Vault: %w", err)
	}

	// Extract registry host from image
	parts := strings.Split(image, "/")
	if len(parts) == 0 {
		klog.ErrorS(nil, "Invalid image format", "image", image)
		return nil, fmt.Errorf("invalid image format: %s", image)
	}
	registryHost := parts[0]

	klog.InfoS("Returning credentials for registry",
		"registryHost", registryHost,
		"image", image)

	authConfig := credentialproviderapi.AuthConfig{
		Username: login,
		Password: password,
	}

	// Use default cache duration (1 hour) since we don't have token expiration info
	cacheDuration := 1 * time.Hour

	klog.V(4).InfoS("Using cache duration", "cacheDuration", cacheDuration)

	return &credentialproviderapi.CredentialProviderResponse{
		TypeMeta: metav1.TypeMeta{
			APIVersion: credentialproviderapi.SchemeGroupVersion.String(),
			Kind:       "CredentialProviderResponse",
		},
		CacheKeyType:  credentialproviderapi.ImagePluginCacheKeyType,
		CacheDuration: &metav1.Duration{Duration: cacheDuration},
		Auth: map[string]credentialproviderapi.AuthConfig{
			registryHost: authConfig,
		},
	}, nil
}

func (v *VaultCredentialProvider) overrideFromAnnotations(annotations map[string]string) {
	if annotations == nil {
		return
	}

	originalVaultAddress := v.config.VaultAddress
	originalAuthMountPath := v.config.KubernetesAuthMountPath

	if vaultAddress, exists := annotations["secres-store.deckhouse.io/addr"]; exists && vaultAddress != "" {
		v.config.VaultAddress = vaultAddress
		klog.InfoS("Overrode Vault address from annotation", "vaultAddress", vaultAddress)
	}

	if authPath, exists := annotations["secrets-store.deckhouse.io/auth-path"]; exists && authPath != "" {
		v.config.KubernetesAuthMountPath = authPath
		klog.InfoS("Overrode Kubernetes auth mount path from annotation", "authPath", authPath)
	}

	klog.V(4).InfoS("Configuration override summary",
		"originalVaultAddress", originalVaultAddress,
		"newVaultAddress", v.config.VaultAddress,
		"originalAuthMountPath", originalAuthMountPath,
		"newAuthMountPath", v.config.KubernetesAuthMountPath)
}

func setupLogging(logLevel string) {
	logs.InitLogs()

	var verbosity int
	switch strings.ToLower(logLevel) {
	case "debug":
		verbosity = 4
	case "info":
		verbosity = 2
	case "warn", "warning":
		verbosity = 1
	case "error":
		verbosity = 0
	default:
		verbosity = 2
	}

	klog.SetOutput(os.Stderr)
	if err := klog.V(klog.Level(verbosity)).Enabled(); err {
		klog.InfoS("Setting log verbosity", "level", verbosity)
	}

	klog.InfoS("Vault credential provider starting",
		"version", version,
		"commit", commit,
		"date", date,
		"logLevel", logLevel,
		"verbosity", verbosity)
}

func main() {
	flags := NewCommandFlags()

	var rootCmd = &cobra.Command{
		Use:     "vault-kubernetes-credential-provider",
		Short:   "Kubernetes credential provider for Vault",
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadConfig(flags.ConfigFile)
			if err != nil {
				klog.ErrorS(err, "Failed to load configuration")
				return err
			}

			setupLogging(cfg.LogLevel)
			defer logs.FlushLogs()

			klog.InfoS("Starting credential provider request processing")

			provider, err := NewVaultCredentialProvider(cfg)
			if err != nil {
				klog.ErrorS(err, "Failed to create Vault credential provider")
				return err
			}

			var req credentialproviderapi.CredentialProviderRequest
			if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
				klog.ErrorS(err, "Failed to decode credential provider request")
				errorResponse := &credentialproviderapi.CredentialProviderResponse{
					TypeMeta: metav1.TypeMeta{
						APIVersion: credentialproviderapi.SchemeGroupVersion.String(),
						Kind:       "CredentialProviderResponse",
					},
					CacheKeyType:  credentialproviderapi.RegistryPluginCacheKeyType,
					CacheDuration: &metav1.Duration{Duration: 0},
					Auth:          map[string]credentialproviderapi.AuthConfig{},
				}
				if encErr := json.NewEncoder(os.Stdout).Encode(errorResponse); encErr != nil {
					klog.ErrorS(encErr, "Failed to encode error response")
				}
				return err
			}

			klog.InfoS("Received credential provider request",
				"image", req.Image,
				"hasServiceAccountToken", req.ServiceAccountToken != "",
				"annotationCount", len(req.ServiceAccountAnnotations))

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			response, err := provider.GetCredentials(ctx, &req)
			if err != nil {
				klog.ErrorS(err, "Failed to get credentials")
				errorResponse := &credentialproviderapi.CredentialProviderResponse{
					TypeMeta: metav1.TypeMeta{
						APIVersion: credentialproviderapi.SchemeGroupVersion.String(),
						Kind:       "CredentialProviderResponse",
					},
					CacheKeyType:  credentialproviderapi.RegistryPluginCacheKeyType,
					CacheDuration: &metav1.Duration{Duration: 0},
					Auth:          map[string]credentialproviderapi.AuthConfig{},
				}
				if encErr := json.NewEncoder(os.Stdout).Encode(errorResponse); encErr != nil {
					klog.ErrorS(encErr, "Failed to encode error response")
				}
				return err
			}

			klog.InfoS("Successfully generated credential response",
				"authCount", len(response.Auth),
				"cacheKeyType", response.CacheKeyType,
				"cacheDuration", response.CacheDuration.Duration)

			if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
				klog.ErrorS(err, "Failed to encode credential response")
				return err
			}

			klog.InfoS("Credential provider request completed successfully")
			return nil
		},
	}

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := LoadConfig(flags.ConfigFile)
			if err != nil {
				klog.ErrorS(err, "Failed to load configuration")
				return
			}
			setupLogging(cfg.LogLevel)
			defer logs.FlushLogs()
			klog.InfoS("Version information",
				"version", version,
				"commit", commit,
				"built", date)
		},
	}

	rootCmd.PersistentFlags().StringVar(&flags.ConfigFile, "config", "", "Path to configuration file")

	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		klog.ErrorS(err, "Command execution failed")
		logs.FlushLogs()
		os.Exit(1)
	}
}

type CommandFlags struct {
	ConfigFile string
}

func NewCommandFlags() *CommandFlags {
	return &CommandFlags{}
}

type Config struct {
	VaultAddress            string        `mapstructure:"vault_address"`
	KubernetesAuthRole      string        `mapstructure:"kubernetes_auth_role"`
	KubernetesAuthMountPath string        `mapstructure:"kubernetes_auth_mount_path"`
	LogLevel                string        `mapstructure:"log_level"`
	InsecureSkipVerify      bool          `mapstructure:"insecure_skip_verify"`
	HTTPTimeout             time.Duration `mapstructure:"http_timeout"`
}

const (
	defaultConfigName = "vault-kubernetes-credential-provider"
	envPrefix         = "VAULT"
)

func LoadConfig(configFile string) (*Config, error) {
	v := viper.NewWithOptions(viper.ExperimentalBindStruct())

	v.SetDefault("vault_address", "https://127.0.0.1:8200")
	v.SetDefault("kubernetes_auth_mount_path", "kubernetes")
	v.SetDefault("log_level", "info")
	v.SetDefault("insecure_skip_verify", false)
	v.SetDefault("http_timeout", 30*time.Second)

	v.SetEnvPrefix(envPrefix)
	v.AutomaticEnv()

	if configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", configFile, err)
		}
		klog.InfoS("Loaded configuration from file", "configFile", configFile)
	} else {
		// Try to read config from default locations, but don't fail if not found
		if err := v.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
		} else {
			klog.InfoS("Loaded configuration from file", "configFile", v.ConfigFileUsed())
		}
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}
