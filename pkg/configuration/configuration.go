package configuration

import (
	"github.com/jaberchez/operator-data-replace-inline/pkg/vault"
)

type Configuration struct {
	Vault []vault.Config
}
