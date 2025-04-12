package bankvaults

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/bank-vaults/vault-sdk/vault"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/viper"

	"github.com/dr4hcu5-jan/viper-vault/remote"
)

// nolint: gochecknoinits
func init() {
	remote.RegisterConfigProvider("bankvaults", NewConfigProvider())
}

// ConfigProvider implements reads configuration from Hashicorp Vault using Banzai Cloud Bank Vaults client.
type ConfigProvider struct{}

// NewConfigProvider returns a new ConfigProvider.
func NewConfigProvider() *ConfigProvider {
	return &ConfigProvider{}
}

func (p ConfigProvider) Get(rp viper.RemoteProvider) (io.Reader, error) {
	endpoint := rp.Endpoint()
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse provider endpoint: %w", err)
	}

	query := u.Query()
	u.RawQuery = ""

	config := api.DefaultConfig()
	config.Address = u.String()
	rawClient, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw api client: %w", err)
	}

	rawClient.SetToken(query.Get("token"))

	client, err := vault.NewClientFromRawClient(
		rawClient,
		vault.ClientRole(query.Get("role")),
		vault.ClientAuthPath(query.Get("authPath")),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault api client: %w", err)
	}
	defer client.Close() // We close the client here to stop the unnecessary token renewal

	secret, err := client.RawClient().Logical().Read(rp.Path())
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
	return nil, errors.New("watch is not implemented for the bankvaults config provider")
}

func (p ConfigProvider) WatchChannel(rp viper.RemoteProvider) (<-chan *viper.RemoteResponse, chan bool) {
	panic("watch channel is not implemented for the bankvaults config provider")
}
