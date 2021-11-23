package vault

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
)

const (
	serverField           string = "server"
	credentialsTypeField  string = "credentials.type"
	credentialsTokenField string = "credentials.token"
)

type Handler struct{}

func (h *Handler) GetValueFromRegex(pattern string, secret *corev1.Secret) (string, error) {
	var server string
	var token string
	var pathSecret string
	var keySecret string

	if !strings.Contains(pattern, "@") {
		return "", fmt.Errorf("format Vault data unknown: %s. Must be ${name-secret:path-vault-secret@key}", pattern)
	}

	if _, ok := secret.Data[serverField]; !ok {
		return "", fmt.Errorf("data \"%s\" not found in vault secret %s", serverField, secret.ObjectMeta.Name)
	}

	server = string(secret.Data[serverField])

	if _, ok := secret.Data[credentialsTokenField]; !ok {
		return "", fmt.Errorf("data \"%s\" not found in vault secret %s", credentialsTokenField, secret.ObjectMeta.Name)
	}

	if _, ok := secret.Data[credentialsTypeField]; !ok {
		return "", fmt.Errorf("data \"%s\" not found in vault secret %s", credentialsTypeField, secret.ObjectMeta.Name)
	}

	credType := string(secret.Data[credentialsTypeField])

	// Check type authentication allowed
	switch strings.ToLower(credType) {
	case "token":
		if _, ok := secret.Data[credentialsTokenField]; !ok {
			return "", fmt.Errorf("data \"%s\" not found in vault secret %s", credentialsTokenField, secret.ObjectMeta.Name)
		}

		token = string(secret.Data[credentialsTokenField])
	default:
		return "", fmt.Errorf("credentials type \"%s\" not allowed in vault secret %s", credType, secret.ObjectMeta.Name)
	}

	client, err := createVaultClientFromToken(server, token)

	if err != nil {
		return "", err
	}

	vaultRegex := regexp.MustCompile(`\${\s*(?:.+?):(.+?)@(.+?)\s*(?:\|\s*.+?)?\s*}`)

	// Find all matches
	res := vaultRegex.FindAllStringSubmatch(pattern, -1)

	pathSecret = res[0][1]
	keySecret = res[0][2]

	val, err := getSecret(client, pathSecret, keySecret)

	if err != nil {
		return "", err
	}

	return val, nil
}

// getSecret get secret from Vault
func getSecret(client *api.Client, pathSecret string, key string) (string, error) {
	splitData := strings.Split(pathSecret, "/")

	// Check if data exists in path
	if splitData[1] != "data" {
		var pathSecretTmp []string

		for i := range splitData {
			if i == 1 {
				pathSecretTmp = append(pathSecretTmp, "data")
				pathSecretTmp = append(pathSecretTmp, splitData[i])
			} else {
				pathSecretTmp = append(pathSecretTmp, splitData[i])
			}
		}

		pathSecret = strings.Join(pathSecretTmp, "/")
	}

	vaultData, err := client.Logical().Read(pathSecret)

	if err != nil {
		return "", err
	}

	if vaultData == nil {
		// Secret does not exist
		return "", fmt.Errorf("Secret \"%s\" not found", pathSecret)
	}

	v := vaultData.Data["data"]

	if v == nil {
		return "", fmt.Errorf("Data not found in secret \"%s\"", pathSecret)
	}

	d := v.(map[string]interface{})

	for k, v := range d {
		if k == key {
			return v.(string), nil
		}
	}

	return "", fmt.Errorf("Key \"%s\" not found", key)
}

func createVaultClientFromToken(vaultHost, vaultToken string) (*api.Client, error) {
	var httpClient = &http.Client{Timeout: 10 * time.Second}

	client, err := api.NewClient(&api.Config{Address: vaultHost, HttpClient: httpClient})

	if err != nil {
		return nil, err
	}

	client.SetToken(vaultToken)

	return client, nil
}
