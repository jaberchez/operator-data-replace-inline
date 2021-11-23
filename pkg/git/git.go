package git

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
)

const (
	credentialsTypeUserPass string = "userpassword"
	credentialsTypeToken    string = "token"
	credentialsTypeSsh      string = "ssh"

	urlField                    string = "url"
	branchField                 string = "branch"
	pathConfigFileField         string = "pathConfigFile"
	typeField                   string = "typeFile"
	usingCredentialsField       string = "usingCredentials"
	credentialsTypeField        string = "credentials.type"
	credentialsUserField        string = "credentials.user"
	credentialsPasswordField    string = "credentials.password"
	credentialsTokenField       string = "credentials.token"
	credentialsSshPasswordField string = "credentials.ssh.password"
	credentialsSshPemField      string = "credentials.ssh.pem"
)

type Handler struct{}

func (h *Handler) GetValueFromRegex(pattern string, secret *corev1.Secret) (string, error) {
	err := checkCommonSecretFields(secret)

	if err != nil {
		return pattern, err
	}

	usingCredentials := strings.ToLower(string(secret.Data[usingCredentialsField])) == "true"
	url := string(secret.Data[urlField])

	cloneOptions := &git.CloneOptions{
		URL:             url,
		ReferenceName:   plumbing.NewBranchReferenceName(string(secret.Data[branchField])),
		SingleBranch:    true,
		InsecureSkipTLS: true,
	}

	pullOptions := &git.PullOptions{
		ReferenceName:   plumbing.NewBranchReferenceName(string(secret.Data[branchField])),
		SingleBranch:    true,
		InsecureSkipTLS: true,
	}

	if usingCredentials {
		var authMethod transport.AuthMethod

		if _, ok := secret.Data[credentialsTypeField]; !ok {
			return pattern, fmt.Errorf("field \"%s\" not found in git secret %s", credentialsTypeField, secret.ObjectMeta.Name)
		}

		credentialsType := strings.ToLower(string(secret.Data[credentialsTypeField]))

		switch credentialsType {
		case credentialsTypeUserPass, credentialsTypeToken:
			if _, ok := secret.Data[credentialsUserField]; !ok {
				return pattern, fmt.Errorf("field \"%s\" not found in git secret %s", credentialsUserField, secret.ObjectMeta.Name)
			}

			httpBasicAuth := &http.BasicAuth{
				Username: string(secret.Data[credentialsUserField]),
			}

			if credentialsType == credentialsTypeUserPass {
				if _, ok := secret.Data[credentialsPasswordField]; !ok {
					return pattern, fmt.Errorf("field \"%s\" not found in git secret %s", credentialsPasswordField, secret.ObjectMeta.Name)
				}

				httpBasicAuth.Password = string(secret.Data[credentialsPasswordField])
			} else {
				if _, ok := secret.Data[credentialsTokenField]; !ok {
					return pattern, fmt.Errorf("field \"%s\" not found in git secret %s", credentialsTokenField, secret.ObjectMeta.Name)
				}

				httpBasicAuth.Password = string(secret.Data[credentialsTokenField])
			}

			authMethod = httpBasicAuth

		case credentialsTypeSsh:
			if _, ok := secret.Data[credentialsSshPasswordField]; !ok {
				return pattern, fmt.Errorf("field \"%s\" not found in git secret %s", credentialsSshPasswordField, secret.ObjectMeta.Name)
			}

			if _, ok := secret.Data[credentialsSshPemField]; !ok {
				return pattern, fmt.Errorf("field \"%s\" not found in git secret %s", credentialsSshPemField, secret.ObjectMeta.Name)
			}

			publicKeys, err := ssh.NewPublicKeys("git", secret.Data[credentialsSshPemField], string(secret.Data[credentialsSshPasswordField]))

			if err != nil {
				return pattern, fmt.Errorf("generate publickeys failed: %s", err.Error())
			}

			authMethod = publicKeys
		default:
			return pattern, fmt.Errorf("\"credentials.type\" \"%s\" unknown in git secret %s", secret.Data[credentialsTypeField], secret.ObjectMeta.Name)
		}

		cloneOptions.Auth = authMethod
		pullOptions.Auth = authMethod
	}

	dirDest := url[strings.LastIndex(url, "/")+1:]
	dirDest = strings.Replace(dirDest, ".git", "", 1)
	dirDest = fmt.Sprintf("/tmp/%s", dirDest)

	//defer func() {
	//	if _, err := os.Stat(dirDest); !os.IsNotExist(err) {
	//		os.RemoveAll(dirDest)
	//	}
	//}()

	// Check if dir already exists
	if _, err := os.Stat(dirDest); !os.IsNotExist(err) {
		// Repo exists, update
		//
		// We instantiate a new repository targeting the given path (the .git folder)
		r, err := git.PlainOpen(dirDest)

		if err != nil {
			return pattern, fmt.Errorf("instantiating git repo %s: %s", url, err.Error())
		}

		// Get the working directory for the repository
		w, err := r.Worktree()

		if err != nil {
			return pattern, fmt.Errorf("getting working directory git repo %s: %s", url, err.Error())
		}

		//err = w.Pull(&git.PullOptions{RemoteName: "origin"})
		err = w.Pull(pullOptions)

		if err != nil {
			if err != git.NoErrAlreadyUpToDate {
				return pattern, fmt.Errorf("pulling git repo %s: %s", url, err.Error())
			}
		}

	} else {
		// Clone repo
		_, err := git.PlainClone(dirDest, false, cloneOptions)

		if err != nil {
			return pattern, fmt.Errorf("cloning git repo %s: %s", url, err.Error())
		}
	}

	fileConfig := fmt.Sprintf("%s/%s", dirDest, string(secret.Data[pathConfigFileField]))

	if _, err := os.Stat(fileConfig); os.IsNotExist(err) {
		return pattern, fmt.Errorf("file config \"%s\" not found", string(secret.Data[pathConfigFileField]))
	}

	gitRegex := regexp.MustCompile(`\${\s*(?:.+?):(.+?)\s*(?:\|\s*.+?)?\s*}`)

	// Find all matches
	res := gitRegex.FindAllStringSubmatch(pattern, -1)

	gitKey := res[0][1]

	var value string

	if strings.ToLower(string(secret.Data[typeField])) == "yaml" {
		value, err = getValueFromYamlFile(fileConfig, gitKey)

		if err != nil {
			return pattern, err
		}
	} else if strings.ToLower(string(secret.Data[typeField])) == "ini" {
		value, err = getValueFromIniFile(fileConfig, gitKey)

		if err != nil {
			return pattern, err
		}
	}

	return value, nil
}

func checkCommonSecretFields(secret *corev1.Secret) error {
	if _, ok := secret.Data[urlField]; !ok {
		return fmt.Errorf("field \"%s\" not found in git secret %s", urlField, secret.ObjectMeta.Name)
	}

	if _, ok := secret.Data[branchField]; !ok {
		return fmt.Errorf("field \"%s\" not found in git secret %s", branchField, secret.ObjectMeta.Name)
	}

	if _, ok := secret.Data[pathConfigFileField]; !ok {
		return fmt.Errorf("field \"%s\" not found in git secret %s", pathConfigFileField, secret.ObjectMeta.Name)
	} else {
		d := string(secret.Data[pathConfigFileField])

		if d[:1] == "/" {
			return fmt.Errorf("absolute file config path \"%s\" not allowed in git secret %s", d, secret.ObjectMeta.Name)
		}
	}

	if _, ok := secret.Data[typeField]; !ok {
		return fmt.Errorf("field \"%s\" not found in git secret %s", typeField, secret.ObjectMeta.Name)
	} else {
		d := strings.ToLower(string(secret.Data[typeField]))

		if d != "yaml" && d != "ini" {
			return fmt.Errorf("format \"%s\" not allowed for field %s in git secret %s", d, typeField, secret.ObjectMeta.Name)
		}
	}

	if _, ok := secret.Data[usingCredentialsField]; !ok {
		return fmt.Errorf("field \"%s\" not found in git secret %s", usingCredentialsField, secret.ObjectMeta.Name)
	} else {
		d := strings.ToLower(string(secret.Data[usingCredentialsField]))

		if d != "true" && d != "false" {
			return fmt.Errorf("data \"%s\" unknown in git secret %s (allowed \"true\" or \"false\")", usingCredentialsField, secret.ObjectMeta.Name)
		}
	}

	return nil
}

func getValueFromYamlFile(filename string, key string) (string, error) {
	yamlFile, err := ioutil.ReadFile(filename)

	if err != nil {
		return "", err
	}

	var config map[string]interface{}

	err = yaml.Unmarshal(yamlFile, &config)

	if err != nil {
		return "", err
	}

	if _, ok := config[key]; !ok {
		return "", nil
	}

	var value string

	switch config[key].(type) {
	case string:
		value, _ = config[key].(string)
	case int:
		val, _ := config[key].(int)
		value = strconv.Itoa(val)
	case int64:
		val, _ := config[key].(int64)
		value = strconv.FormatInt(val, 10)
	case float32:
		val, _ := config[key].(float32)
		value = fmt.Sprintf("%f", val)
	case float64:
		val, _ := config[key].(float64)
		value = fmt.Sprintf("%f", val)
	default:
		return "", fmt.Errorf("type value unknown of %s in %s", key, filename)
	}

	//value, ok := config[key].(string)
	//
	//if !ok {
	//	return "", fmt.Errorf("value of %s is not a string in %s", key, filename)
	//}

	return value, nil
}

func getValueFromIniFile(filename string, key string) (string, error) {
	gitConf, err := ini.Load(filename)

	if err != nil {
		return "", err
	}

	dat := gitConf.Section("").Key(key).String()

	return dat, nil
}
