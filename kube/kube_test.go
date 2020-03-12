package kube

import (
	"testing"

	"github.com/sebidude/porecry/crypto"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestInitSecret(t *testing.T) {
	key, _ := crypto.GenerateKeyPair(1024)
	keybytes := crypto.PrivateKeyToBytes(key)
	t.Run("success", func(t *testing.T) {
		out, initError := InitSecret(nil, keybytes, "local", "helmsecret")
		assert.NoError(t, initError, "Secret must be generated")

		s, err := SecretsFromManifestBytes(out.Bytes())
		assert.NoError(t, err, "Secret must be read from bytes")
		assert.Equal(t, "local", s.Namespace, "Namespace must match")
	})
}

func TestSecretFromManifestBytes(t *testing.T) {
	key, _ := crypto.GenerateKeyPair(1024)
	keybytes := crypto.PrivateKeyToBytes(key)
	out, initError := InitSecret(nil, keybytes, "local", "helmsecret")
	assert.NoError(t, initError, "Secret must be generated")

	t.Run("success", func(t *testing.T) {
		s, err := SecretsFromManifestBytes(out.Bytes())
		assert.NoError(t, err, "Secret must be read from secret.yaml")
		assert.Equal(t, "Secret", s.TypeMeta.Kind, "Object must be of type Secret.")
		assert.Equal(t, corev1.SecretType("Opaque"), s.Type, "Secret must be of type Opaque.")

	})

	t.Run("fail", func(t *testing.T) {
		_, err := SecretsFromManifestBytes([]byte("boo"))
		assert.Error(t, err, "Secret must be read from secret.yaml")
	})

}

func TestNewSecret(t *testing.T) {
	data := make(map[string][]byte)
	data["pass"] = []byte("test123")

	s := NewSecret(data, "testsecret")
	assert.IsType(t, corev1.Secret{}, *s, "Secret must be of type v1.Secret")
	assert.Equal(t, "test123", string(s.Data["pass"]), "Secret must contain correct data")
}
