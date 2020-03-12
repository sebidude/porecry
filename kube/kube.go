package kube

import (
	"bytes"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
)

type Output interface {
	Write(p []byte) (n int, err error)
}

func GetSecretList(clientset *kubernetes.Clientset, namespace string) *corev1.SecretList {
	secrets, err := clientset.CoreV1().Secrets(namespace).List(metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	return secrets
}

func ToManifest(o interface{}, out Output) {
	e := json.NewYAMLSerializer(json.DefaultMetaFactory, nil, nil)
	obj := o.(runtime.Object)
	err := e.Encode(obj, out)
	if err != nil {
		panic(err)
	}

}

func SecretsFromManifestBytes(m []byte) (*corev1.Secret, error) {
	s := new(corev1.Secret)
	dec := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(m), len(m))
	if err := dec.Decode(&s); err != nil {
		return nil, err
	}
	return s, nil
}

func InitSecret(clientset *kubernetes.Clientset, privbytes []byte, namespace string, secretname string) (*bytes.Buffer, error) {
	data := make(map[string][]byte)
	data["privatekey"] = privbytes

	s := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		Type: corev1.SecretTypeOpaque,
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretname,
			Namespace: namespace,
		},
		Data: data,
	}

	var out bytes.Buffer
	ToManifest(s, &out)
	return &out, nil

}

func NewSecret(data map[string][]byte, name string) *corev1.Secret {
	s := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		Type: corev1.SecretTypeOpaque,
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Data: data,
	}
	return s
}
