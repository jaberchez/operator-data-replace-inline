package utils

// References:
//   https://gist.github.com/pytimer/0ad436972a073bb37b8b6b8b474520fc
//   https://github.com/kubernetes/client-go/blob/v0.19.2/examples/dynamic-create-update-delete-deployment/main.go
//   https://github.com/kubernetes-sigs/controller-runtime/blob/c73b143dc50358328b9153329b3b570b1a0e5623/pkg/client/unstructured_client.go
//   https://github.com/kubernetes/apimachinery/blob/master/pkg/apis/meta/v1/unstructured/helpers.go
//   https://github.com/kubernetes/apimachinery/blob/master/pkg/apis/meta/v1/unstructured/unstructured.go
//   https://dev.to/davidsbond/go-creating-dynamic-kubernetes-informers-1npi
//   https://caiorcferreira.github.io/post/the-kubernetes-dynamic-client/
//   http://yuezhizizhang.github.io/kubernetes/kubectl/client-go/2020/05/13/kubectl-client-go-part-1.html
//   http://yuezhizizhang.github.io/kubernetes/kubectl/client-go/2020/05/13/kubectl-client-go-part-3.html
//   https://miminar.fedorapeople.org/_preview/openshift-enterprise/registry-redeploy/go_client/serializing_and_deserializing.html
//   https://ymmt2005.hatenablog.com/entry/2020/04/14/An_example_of_using_dynamic_client_of_k8s.io/client-go
//   https://dx13.co.uk/articles/2021/01/15/kubernetes-types-using-go/
//   https://erwinvaneyk.nl/kubernetes-unstructured-to-typed/

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"context"

	"github.com/jaberchez/operator-data-replace-inline/pkg/git"
	"github.com/jaberchez/operator-data-replace-inline/pkg/vault"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	"k8s.io/client-go/dynamic"
	crtl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Generic regex to find lines
	// ${name-secret:data}
	// Notes:
	//    - Each provider has its own specific regex
	//    - Is posible to use modifiers with |
	//        There are two kinds of modifers: data modifier and line modifier
	//        Data modifier modifies only the data
	//        Line modifier modifies the whole value of the fiiel
	//        Available modifiers for data (they can be cocatenated | default("test") | base64 ):
	//          - base64
	//          - select
	//          - dict
	//          - default
	//        Available modifiers for line (they can be also cocatenated | base64 | indent4):
	//          - base64
	//          - select
	//          - dict
	//          - default
	//          - indent4
	// Example for Vault: ${vault-01:test/data/sync-ldap@bindPassword | base64}
	// Example for Git: ${git-01:LDAP_URL}
	//lineGenericRegexPattern string = `\${\s*(.+?):(?:.+?)\s*(\|\s*.+?)?\s*}\s*(\|\s*.+?)?`
	lineGenericRegexPattern string = `\${\s*(.+?):(?:.+?)\s*(\|\s*.+?)?\s*}\s*(\|\s*.+)?`

	annotationConfigType string = "datareplaceinline/config-type"

	vaultHandler string = "vault"
	gitHandler   string = "git"
)

var (
	lineRegex            *regexp.Regexp
	regexCommentLine     *regexp.Regexp
	regexIndentModifier  *regexp.Regexp
	regexBase64Modifier  *regexp.Regexp
	regexSelectModifier  *regexp.Regexp
	regexDictModifier    *regexp.Regexp
	regexDefaultModifier *regexp.Regexp
)

func init() {
	lineRegex = regexp.MustCompile(lineGenericRegexPattern)

	// Lines wich ara comments
	regexCommentLine = regexp.MustCompile(`^\s*#.*`)

	// Line modifier indentN
	regexIndentModifier = regexp.MustCompile(`\bindent(\d+)\b`)

	// Data modifier base64
	regexBase64Modifier = regexp.MustCompile(`\bbase64\b`)

	// Data modifier select(regex)
	regexSelectModifier = regexp.MustCompile(`select\s*\(\s*["']?(.+?)["']?\s*\)`)

	// Data modifier dict(key)
	regexDictModifier = regexp.MustCompile(`dict\s*\(\s*["']?(.+?)["']?\s*\)`)

	// Data modifier default(key)
	regexDefaultModifier = regexp.MustCompile(`default\s*\(\s*["']?(.+?)["']?\s*\)`)
}

type Handler interface {
	GetValueFromRegex(reg string, secret *corev1.Secret) (string, error)
}

type K8sUtil struct {
	TypedClient       client.Client
	DynamicClient     dynamic.Interface
	RawManifest       string
	ProcessedManifest string
	GVK               *schema.GroupVersionKind
	GVR               schema.GroupVersionResource
	Object            *unstructured.Unstructured
	Request           crtl.Request
}

func NewK8sUtil(c client.Client, rawManifest string, req crtl.Request) (*K8sUtil, error) {
	k8s := &K8sUtil{
		TypedClient: c,
		RawManifest: rawManifest,
		Request:     req,
	}

	dynClient, err := getDynamicClient()

	if err != nil {
		return nil, err
	}

	k8s.DynamicClient = dynClient

	return k8s, nil
}

// ProcessManifest read the manifest and replace the lines found with regexes
// Return the manifest replaced with the real values
func (k8s *K8sUtil) ProcessManifest() error {
	var output string
	var lineNumber int

	scanner := bufio.NewScanner(strings.NewReader(k8s.RawManifest))

	// Iterate line by line searching regex
	for scanner.Scan() {
		line := scanner.Text()
		lineNumber++

		if isCommentedLine(line) {
			// Don't replace regex in lines wich are commented
			output += line
		} else if foundLine(line) {
			lineTmp, err := k8s.processLine(line, lineNumber)

			if err != nil {
				return err
			}

			// Check if the value is a regex
			// Note: We can configure a value pointing to another datastore
			// Example: Imagine this configuration in a git repo in the file config.ini
			//    CA_CERTIFICATE=${vault-01:pathSecret@key}
			//    The CA certificate is no in the file itself, it is stored in vault
			if foundLine(lineTmp) {
				lineTmp02, err := k8s.processLine(lineTmp, lineNumber)

				if err != nil {
					return err
				}

				lineTmp = lineTmp02
			}

			output += lineTmp
		} else {
			output += line
		}

		output += "\n"
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	k8s.ProcessedManifest = output

	return nil
}

func (k8s *K8sUtil) DecodeManifest() error {
	obj := &unstructured.Unstructured{}

	// Decode YAML into unstructured.Unstructured
	dec := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)
	_, gvk, err := dec.Decode([]byte(k8s.ProcessedManifest), nil, obj)

	if err != nil {
		return err
	}

	k8s.GVK = gvk
	k8s.GVR = k8s.getGVR()
	k8s.Object = obj

	return nil
}

func (k8s *K8sUtil) AddOwnerReference(typeMeta metav1.TypeMeta, objectMeta metav1.ObjectMeta) {
	references := []metav1.OwnerReference{
		metav1.OwnerReference{
			APIVersion: typeMeta.APIVersion,
			Kind:       typeMeta.Kind,
			Name:       objectMeta.Name,
			UID:        objectMeta.UID,
		},
	}

	k8s.Object.SetOwnerReferences(references)
}

func (k8s *K8sUtil) ResourceExists() (bool, error) {
	// GET the resource
	obj, err := k8s.DynamicClient.Resource(k8s.GVR).Namespace(k8s.Request.Namespace).Get(context.Background(), k8s.Object.GetName(), metav1.GetOptions{})

	if err != nil {
		if apierrors.IsNotFound(err) {
			// Resource not found
			return false, nil
		}

		return false, err
	}

	return obj != nil, nil
}

func (k8s *K8sUtil) CreateResource() error {
	return k8s.createUpdateObject("create")
}

func (k8s *K8sUtil) UpdateResource() error {
	return k8s.createUpdateObject("update")
}

// isCommentedLine check if line starts with a comment #
func isCommentedLine(line string) bool {
	return regexCommentLine.MatchString(line)
}

// foundLine check if line contains the generic regex
func foundLine(line string) bool {
	return lineRegex.MatchString(line)
}

// processLine process the line
func (k8s *K8sUtil) processLine(line string, lineNumber int) (string, error) {
	var newLine string

	// Find all matches
	// Note: Remember that in one line could have multiple matches
	// Example:
	//    url: ldaps://${git-01:LDAP_URL}:636/${git-01:LDAP_FILTER}
	res := lineRegex.FindAllStringSubmatch(line, -1)

	// Get Secrets from all matches
	for i := range res {
		pattern := res[i][0]
		nameSecret := res[i][1]
		dataModifier := res[i][2]
		lineModifier := res[i][3]

		// Get Secret
		// Note: All secrets must be stored in the same namespace where the operator is installed
		secret, err := k8s.getKubernetesSecret(os.Getenv("NAMESPACE"), nameSecret)

		if err != nil {
			return "", err
		}

		if secret.ObjectMeta.Annotations == nil {
			return "", fmt.Errorf("secret %s does not provide annotations", nameSecret)
		} else {
			if _, ok := secret.ObjectMeta.Annotations[annotationConfigType]; !ok {
				return "", fmt.Errorf("secret %s annotation \"%s\" not found", nameSecret, annotationConfigType)
			}
		}

		var handler Handler

		// Check type
		switch strings.ToLower(secret.ObjectMeta.Annotations[annotationConfigType]) {
		case vaultHandler:
			handler = &vault.Handler{}
		case gitHandler:
			handler = &git.Handler{}
		default:
			return "", fmt.Errorf("annotation type \"%s\" unknown in secret %s", annotationConfigType, nameSecret)
		}

		val, err := handler.GetValueFromRegex(pattern, secret)

		if err != nil {
			return "", fmt.Errorf("error in line %d: %s", lineNumber, err.Error())
		}

		if len(dataModifier) > 0 {
			if !modifierExists(dataModifier) {
				return "", fmt.Errorf("modifier \"%s\" unknown in line %d", dataModifier, lineNumber)
			}

			val = processModifiers(val, dataModifier)
		}

		newLine = strings.Replace(line, pattern, val, 1)
		line = newLine

		if len(lineModifier) > 0 {
			if !modifierExists(lineModifier) {
				return "", fmt.Errorf("modifier \"%s\" unknown in line %d", lineModifier, lineNumber)
			}

			val = processModifiers(line, lineModifier)

			newLine = strings.Replace(line, line, val, 1)
			line = newLine
		}
	}

	return newLine, nil
}

func (k8s *K8sUtil) getKubernetesSecret(namespace string, name string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}

	err := k8s.TypedClient.Get(context.Background(), client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}, secret)

	if err != nil {
		return secret, err
	}

	return secret, nil
}

func getDynamicClient() (dynamic.Interface, error) {
	config, err := crtl.GetConfig()

	if err != nil {
		return nil, err
	}

	dynClient, err := dynamic.NewForConfig(config)

	if err != nil {
		return nil, err
	}

	return dynClient, nil
}

func (k8s *K8sUtil) getGVR() schema.GroupVersionResource {
	resource := schema.GroupVersionResource{Group: k8s.GVK.Group, Version: k8s.GVK.Version,
		Resource: strings.ToLower(fmt.Sprintf("%ss", k8s.GVK.Kind))}

	return resource
}

func (k8s *K8sUtil) createUpdateObject(action string) error {
	var err error

	if action == "create" {
		_, err = k8s.DynamicClient.Resource(k8s.GVR).Namespace(k8s.Request.Namespace).Create(context.Background(), k8s.Object, metav1.CreateOptions{})
	} else {
		_, err = k8s.DynamicClient.Resource(k8s.GVR).Namespace(k8s.Request.Namespace).Update(context.Background(), k8s.Object, metav1.UpdateOptions{})
	}

	return err
}

func modifierExists(modifier string) bool {
	return regexIndentModifier.MatchString(modifier) ||
		regexBase64Modifier.MatchString(modifier) ||
		regexSelectModifier.MatchString(modifier) ||
		regexDictModifier.MatchString(modifier) ||
		regexDefaultModifier.MatchString(modifier)
}

func processModifiers(dat string, modifier string) string {
	//func processDataModifiers(dat string, modifier string) string {
	// Remove all spaces if any
	modifier = strings.ReplaceAll(modifier, " ", "")

	// Get all modifiers
	modifiers := strings.Split(modifier, "|")

	for j := range modifiers {
		m := modifiers[j]

		// Remove start and end spaces
		m = strings.TrimSpace(m)

		if len(m) > 0 {
			if regexBase64Modifier.MatchString(m) {
				dat = encodingBase64(dat)
			} else if regexSelectModifier.MatchString(m) {
				dat = selectData(dat, m)
			} else if regexDictModifier.MatchString(m) {
				dat = selectDictData(dat, m)
			} else if regexDefaultModifier.MatchString(m) {
				dat = defaultValue(m)
			} else if regexIndentModifier.MatchString(m) {
				// Get the n spaces
				res := regexIndentModifier.FindAllStringSubmatch(m, -1)
				n, _ := strconv.Atoi(res[0][1])
				dat = indent(dat, n)
			}
		}
	}

	return dat
}

//func processLineModifiers(line string, modifier string) string {
//	// Remove all spaces if any
//	//modifier = strings.ReplaceAll(modifier, " ", "")
//
//	if len(modifier) > 0 {
//		// Get all modifiers
//		modifiers := strings.Split(modifier, "|")
//
//		for j := range modifiers {
//			m := modifiers[j]
//
//			// Remove start and end spaces
//			m = strings.TrimSpace(m)
//
//			if len(m) > 0 {
//				if regexIndentModifier.MatchString(m) {
//					// Get the n spaces
//					res := regexIndentModifier.FindAllStringSubmatch(m, -1)
//					n, _ := strconv.Atoi(res[0][1])
//					line = indent(line, n)
//				}
//			}
//		}
//	}
//
//	return line
//}

func encodingBase64(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

// Indent n spaces from begining
func indent(line string, n int) string {
	var output string

	re := regexp.MustCompile(`^\s+`)

	scanner := bufio.NewScanner(strings.NewReader(line))

	for scanner.Scan() {
		line := scanner.Text()

		line = re.ReplaceAllString(line, "")

		output += fmt.Sprintf("%s%s\n", strings.Repeat(" ", n), line)
	}

	if len(output) > 1 {
		// Delete last carriage return
		output = output[:len(output)-1]
	}

	return output
}

func selectData(dat string, modifier string) string {
	// Get regex
	// Notes: Remember regex is between ()
	// Example: select(^one$)
	res := regexSelectModifier.FindAllStringSubmatch(modifier, -1)
	re := regexp.MustCompile(res[0][1])

	d := strings.Split(dat, ",")

	for i := range d {
		tmp := strings.TrimSpace(d[i])

		if re.MatchString(tmp) {
			return tmp
		}
	}

	return dat
}

func selectDictData(dat string, modifier string) string {
	// Get dict key
	// Notes: Remember key is between ()
	// Example: dict(subneta)
	res := regexDictModifier.FindAllStringSubmatch(modifier, -1)
	keySelected := res[0][1]

	// Notes: The data is key01=value01,key02=value02....
	d := strings.Split(dat, ",")

	for i := range d {
		tmp := strings.TrimSpace(d[i])

		// Get key, value
		keyValue := strings.Split(tmp, "=")

		k := strings.TrimSpace(keyValue[0])
		v := strings.TrimSpace(keyValue[1])

		if k == keySelected {
			return v
		}
	}

	return dat
}

func defaultValue(modifier string) string {
	// Get default value
	// Notes: Remember default value is between ()
	// Example: default(foo)
	res := regexDefaultModifier.FindAllStringSubmatch(modifier, -1)
	defaultValueSelected := res[0][1]

	return defaultValueSelected
}
