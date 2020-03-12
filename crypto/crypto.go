package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
)

var (
	label = []byte("9c96d939c7f30920e17c18d7e97cc7e85a2f03d78c6b563ff38964ee02477d94")
)

func Decrypt(rnd io.Reader, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 2 {
		return nil, fmt.Errorf("ciphertext is too short")
	}
	rsaLen := int(binary.BigEndian.Uint16(ciphertext))
	if len(ciphertext) < rsaLen+2 {
		return nil, fmt.Errorf("ciphertext is too short")
	}

	rsaCipher := ciphertext[2 : rsaLen+2]
	aesCipher := ciphertext[rsaLen+2:]

	sessionKey, err := rsa.DecryptOAEP(sha256.New(), rnd, privKey, rsaCipher, label)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	aed, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	zeroNonce := make([]byte, aed.NonceSize())

	plaintext, err := aed.Open(nil, zeroNonce, aesCipher, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func Encrypt(rnd io.Reader, pubKey *rsa.PublicKey, plaintext []byte) []byte {
	// Generate a random symmetric key
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(rnd, sessionKey); err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		panic(err)
	}

	aed, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	rsaCiphertext, err := rsa.EncryptOAEP(sha256.New(), rnd, pubKey, sessionKey, label)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, 2)
	binary.BigEndian.PutUint16(ciphertext, uint16(len(rsaCiphertext)))
	ciphertext = append(ciphertext, rsaCiphertext...)

	zeroNonce := make([]byte, aed.NonceSize())

	ciphertext = aed.Seal(ciphertext, zeroNonce, plaintext, nil)

	return ciphertext
}

// GenerateKeyPair generates a new key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return privkey, &privkey.PublicKey
}

func GetPublicKey(priv *rsa.PrivateKey) *rsa.PublicKey {
	return &priv.PublicKey
}

func ReadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	keybytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	key, err := BytesToPrivateKey(keybytes)
	return key, err
}

// PrivateKeyToBytes private key to bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

// PublicKeyToBytes public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes, nil
}

// BytesToPrivateKey bytes to private key
func BytesToPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return key, nil
}
