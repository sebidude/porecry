package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/alecthomas/kingpin"
	"github.com/sebidude/porecry/crypto"
	"github.com/sebidude/porecry/kube"

	gyaml "github.com/ghodss/yaml"
	"gopkg.in/yaml.v2"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	gitcommit    string
	appversion   string
	buildtime    string
	clientconfig *rest.Config
	clientset    *kubernetes.Clientset

	namespace    string
	tlsinfo      string
	tlssecret    string
	tlsnamespace string
	runlocal     = false
	plain        = false

	filename = "-"
	outfile  = "-"

	valuePattern   = regexp.MustCompile(`\[([^\]]+)\]([.\s]*)`)
	porecryPattern = regexp.MustCompile(`(\w+):(\w+),(\w+):(\w+),(\w+):(.*)`)
)

func main() {

	app := kingpin.New(os.Args[0], "encrypt decrypt data.")
	app.Version(fmt.Sprintf("app: %s - commit: %s - version: %s - buildtime: %s", app.Name, gitcommit, appversion, buildtime))
	app.Flag("local", "Run with a locally stored secret. No cluster interaction possible.").BoolVar(&runlocal)
	app.Flag("in", "Input file to read from").Short('i').StringVar(&filename)
	app.Flag("out", "Output file to write the data to").Short('o').StringVar(&outfile)
	app.Flag("secret", "The name of the secret to be used").Short('s').Default("porecry").StringVar(&tlssecret)
	app.Flag("namespace", "The namespace in which the secret should to be initialized").Short('n').Default("porecry").StringVar(&tlsnamespace)
	app.Flag("plain", "Skip base64 encoding for decrypted content").Short('p').BoolVar(&plain)

	app.Command("init", "Generate the cert and key and add the secret for kubecrypt to the cluster.")
	app.Command("enc", "encrypt data")
	app.Command("dec", "decrypt")
	app.Command("post", "postRenderer for rendered helm templates.")

	if len(os.Args) == 1 {
		os.Args = append(os.Args, "post")
	}
	operation := kingpin.MustParse(app.Parse(os.Args[1:]))
	kubeconfig := os.Getenv("KUBECONFIG")
	if len(kubeconfig) < 1 {
		// we try the find the config at the default path.
		// https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/

		currentUser, _ := user.Current()
		if currentUser != nil {
			if len(currentUser.HomeDir) > 0 {
				kubeConfigPath := filepath.Join(currentUser.HomeDir, ".kube", "config")
				_, err := os.Stat(kubeConfigPath)
				if os.IsNotExist(err) && err != nil {
					kubeconfig = ""
				} else {
					kubeconfig = kubeConfigPath
				}
			}
		}
	}
	if !runlocal {
		if len(kubeconfig) < 1 {
			config, err := rest.InClusterConfig()
			if err != nil {
				panic(err.Error())
			}
			clientconfig = config
		} else {
			config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
			if err != nil {
				panic(err.Error())
			}
			clientconfig = config
		}
		var err error
		clientset, err = kubernetes.NewForConfig(clientconfig)
		if err != nil {
			panic(err.Error())
		}
	} else {
		clientset = nil
	}

	if !runlocal {
		if namespace == "" {
			var err error
			namespace, _, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
				clientcmd.NewDefaultClientConfigLoadingRules(),
				&clientcmd.ConfigOverrides{},
			).Namespace()
			if err != nil {
				panic(err.Error())
			}
		}
	} else {
		namespace = "local"
	}

	switch operation {

	case "init":
		priv, _ := crypto.GenerateKeyPair(4096)
		privbytes := crypto.PrivateKeyToBytes(priv)
		out, err := kube.InitSecret(clientset, privbytes, tlsnamespace, tlssecret)
		checkError(err)
		writeOutputToFile(out.Bytes())

	case "enc":
		inputbytes := readInputFromFile(filename)
		ciphertext := encryptData(inputbytes)
		encodedData := base64.RawURLEncoding.EncodeToString(ciphertext)
		writeOutputToFile([]byte(encodedData))

	case "dec":
		inputbytes := readInputFromFile(filename)
		if len(inputbytes) == 0 {
			fmt.Println("input is empty")
			return
		}
		decodedData, err := base64.RawURLEncoding.DecodeString(string(inputbytes))
		if err != nil {
			panic(err)
		}
		data := decryptData(decodedData)

		writeOutputToFile(data)

	case "version":
		fmt.Printf("porecry\n version: %s\n commit: %s\n buildtime: %s\n", appversion, gitcommit, buildtime)

	case "post":
		runPostRenderer()
	default:
		runPostRenderer()
	}
}

func runPostRenderer() {
	inputbytes := readInputFromFile(filename)
	if len(inputbytes) == 0 {
		fmt.Println("input is empty")
		return
	}

	r := bytes.NewReader(inputbytes)
	dec := yaml.NewDecoder(r)
	dec.SetStrict(true)

	var yamlmap map[string]interface{}
	for dec.Decode(&yamlmap) == nil {
		data, err := yaml.Marshal(yamlmap)
		checkError(err)

		err = gyaml.Unmarshal(data, &yamlmap)
		checkError(err)

		renderedMap := postRenderer(yamlmap)
		data, err = yaml.Marshal(renderedMap)
		checkError(err)

		data = append([]byte("---\n"), data...)
		writeOutputToFile(data)
		yamlmap = make(map[string]interface{})

	}
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func readInputFromFile(filename string) []byte {
	var inputError error
	var input *os.File
	if filename == "-" {
		input = os.Stdin
	} else {
		input, inputError = os.Open(filename)
		checkError(inputError)
		defer input.Close()
	}

	data, err := ioutil.ReadAll(input)
	checkError(err)
	return data
}

func writeOutputToFile(data []byte) {
	if outfile == "-" {
		fmt.Print(string(data))
		return
	}

	output, err := os.Create(outfile)
	checkError(err)
	defer output.Close()
	output.Write(data)
}

func decryptData(data []byte) []byte {
	priv, _, err := loadKeysFromSecret(tlssecret, tlsnamespace)
	checkError(err)

	cleartext, err := crypto.Decrypt(rand.Reader, priv, data)
	checkError(err)
	return cleartext
}

func encryptData(data []byte) []byte {
	// load the key from the secret
	_, pub, err := loadKeysFromSecret(tlssecret, tlsnamespace)
	checkError(err)

	ciphertext := crypto.Encrypt(rand.Reader, pub, data)
	return ciphertext
}

func postRenderer(yamlmap map[string]interface{}) map[string]interface{} {
	renderedMap := yamlmap
	for k, value := range yamlmap {
		switch value.(type) {
		case map[string]interface{}:
			renderedMap[k] = postRenderer(value.(map[string]interface{}))
		case string:
			match := valuePattern.FindAllStringSubmatch(value.(string), -1)
			if len(match) != 1 {
				continue
			}

			submatch := match[0]
			if len(submatch) != 3 {
				continue
			}
			data := submatch[2]

			porecryMatch := porecryPattern.FindAllStringSubmatch(submatch[1], -1)
			if len(porecryMatch) != 1 {
				continue
			}
			porecrySubmatch := porecryMatch[0]
			if len(porecrySubmatch) != 7 {
				continue
			}
			// [op:decrypt,mode:cluster,secret:kubecrypt/kubecrypt]ciphertext
			//   1   2      3     4       5        6                    7
			operation := porecrySubmatch[2]
			mode := porecrySubmatch[4]
			tlsinfo = porecrySubmatch[6]

			if mode == "local" {
				tlssecret = filepath.Join(tlsinfo)
				runlocal = true
			} else {
				runlocal = false
				tlsinfoparts := strings.Split(tlsinfo, "/")
				if len(tlsinfoparts) != 2 {
					checkError(fmt.Errorf("Malformed tlsinfo. Use -t namespace/secret."))
				}
				tlsnamespace = tlsinfoparts[0]
				tlssecret = tlsinfoparts[1]
			}

			if operation == "encrypt" {
				c := encryptData([]byte(data))
				renderedMap[k] = fmt.Sprintf("[op:decrypt,mode:%s,secret:%s]%s",
					mode,
					tlsinfo,
					base64.RawURLEncoding.EncodeToString(c))
			} else {
				s, err := base64.RawURLEncoding.DecodeString(data)
				checkError(err)
				c := decryptData(s)
				if plain {
					renderedMap[k] = string(c)
				} else {
					renderedMap[k] = base64.StdEncoding.EncodeToString(c)
				}
			}
		}
	}

	return renderedMap
}

func getOutputFile() *os.File {
	if outfile == "-" {
		return os.Stdout
	}

	// output the ciphertext
	output, err := os.Create(outfile)
	checkError(err)
	return output
}

func loadKeysFromSecret(secretname, ns string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	var secret corev1.Secret
	var err error
	if runlocal {
		filename := filepath.Join(secretname)
		content, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, nil, err
		}
		s, err := kube.SecretsFromManifestBytes(content)
		checkError(err)
		secret = *s
	} else {
		secrets := kube.GetSecretList(clientset, ns)
		for _, s := range secrets.Items {
			if s.Name == secretname {
				secret = s
				break
			}
		}
	}

	if _, ok := secret.Data["privatekey"]; !ok {
		checkError(fmt.Errorf("No privatekey found in secret."))
	}

	keypem := secret.Data["privatekey"]
	key, err := crypto.BytesToPrivateKey(keypem)
	checkError(err)

	return key, key.Public().(*rsa.PublicKey), err
}
