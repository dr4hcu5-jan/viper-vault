package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/hashicorp/vault/api"
	"github.com/spf13/viper"

	"github.com/dr4hcu5-jan/viper-vault/remote"
)

// nolint: gochecknoinits
func init() {
	remote.RegisterConfigProvider("vault", NewConfigProvider())
}

// ConfigProvider implements reads configuration from Hashicorp Vault.
type ConfigProvider struct {
	clients map[string]*api.Client
}

// NewConfigProvider returns a new ConfigProvider.
func NewConfigProvider() *ConfigProvider {
	return &ConfigProvider{
		clients: make(map[string]*api.Client),
	}
}

func (p ConfigProvider) Get(rp viper.RemoteProvider) (io.Reader, error) {
	client, ok := p.clients[rp.Endpoint()]
	if !ok {
		endpoint := rp.Endpoint()
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to parse provider endpoint: %w", err)
		}

		config := api.DefaultConfig()
		_ = config.ReadEnvironment()
		config.Address = u.String()
		c, err := api.NewClient(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create vault api client: %w", err)
		}

		client = c
		p.clients[endpoint] = c
	}

	secret, err := client.Logical().Read(rp.Path())
	if err != nil {
		return nil, fmt.Errorf("failed to read secret: %w", err)
	}

	if secret == nil {
		return nil, fmt.Errorf("source not found: %s", rp.Path())
	}

	if secret.Data == nil && secret.Warnings != nil {
		return nil, fmt.Errorf("source: %s errors: %v", rp.Path(), secret.Warnings)
	}

	b, err := json.Marshal(secret.Data["data"])
	if err != nil {
		return nil, fmt.Errorf("failed to json encode secret: %w", err)
	}

	return bytes.NewReader(b), nil
}

func (p ConfigProvider) Watch(rp viper.RemoteProvider) (io.Reader, error) {
	return nil, errors.New("watch is not implemented for the vault config provider")
}

func (p ConfigProvider) WatchChannel(rp viper.RemoteProvider) (<-chan *viper.RemoteResponse, chan bool) {
	panic("watch channel is not implemented for the vault config provider")
}
