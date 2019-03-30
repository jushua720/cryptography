package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	enc "github.com/btcsuite/btcutil/base58"
)

type Keys struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

type Signature struct {
	R string
	S string
}

type PubKeyCoordinate struct {
	X string
	Y string
}

func GenerateKeys() (*Keys, error) {
	var keys Keys

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := &privKey.PublicKey

	keys.PrivateKey, keys.PublicKey = encodeKeys(privKey, pubKey)

	return &keys, nil
}

func encodeKeys(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {

	pubKeyEncoded := enc.Encode(elliptic.Marshal(elliptic.P256(), publicKey.X, publicKey.Y))
	privKeyEncoded := hex.EncodeToString(privateKey.D.Bytes())

	return privKeyEncoded, pubKeyEncoded
}

func GetHash(s string) string {
	signedBytes := make([]int8, sha256.Size)
	unsignedBytes := make([]byte, 0, len(signedBytes))

	checksum := sha256.Sum256([]byte(s))

	for i := range checksum {
		signedBytes[i] = int8(checksum[i])
	}

	for _, b := range signedBytes {
		unsignedBytes = append(unsignedBytes, byte(b))
	}

	hash := enc.Encode(unsignedBytes)
	return hash
}

func Sign(privateKey string, hash string) (*Signature, error) {
	var signature Signature

	key := getPrivateKeyFromHex(privateKey)
	r, s, err := ecdsa.Sign(rand.Reader, key, []byte(hash))
	if err != nil {
		return nil, err
	}
	signature.R = fmt.Sprint(r)
	signature.S = fmt.Sprint(s)

	return &signature, nil
}

func getPrivateKeyFromHex(key string) *ecdsa.PrivateKey {
	keyBytes := getBytesFromHex(key)

	privKey := new(ecdsa.PrivateKey)
	privKey.PublicKey.Curve = elliptic.P256()
	privKey.D = new(big.Int).SetBytes(keyBytes)

	return privKey
}

func getBytesFromHex(str string) []byte {
	if len(str) > 1 {
		if str[0:2] == "0x" || str[0:2] == "0X" {
			str = str[2:]
		}
	}
	if len(str)%2 == 1 {
		str = "0" + str
	}

	bytes, _ := hex.DecodeString(str)

	return bytes
}

func Verify(pubKey, msg, R, S string) bool {

	pub := getPubKeyFromHex(pubKey)
	return ecdsa.Verify(&pub, []byte(msg), getBigInt(R), getBigInt(S))
}

func getBigInt(val string) *big.Int {
	bigInt := new(big.Int)
	bigInt, ok := bigInt.SetString(val, 10)
	if !ok {
		return nil
	}
	return bigInt
}

func getPubKeyFromHex(key string) ecdsa.PublicKey {

	keyBytes := enc.Decode(key)
	x, y := elliptic.Unmarshal(elliptic.P256(), keyBytes)
	pubKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	fmt.Println("X ", pubKey.X)
	fmt.Println("Y ", pubKey.Y)

	return pubKey
}

func GetPubKeyFromXY(x, y string) string {

	X := new(big.Int)
	X, ok := X.SetString(x, 10)
	if !ok {
		return ""
	}

	Y := new(big.Int)
	Y, ok = Y.SetString(y, 10)
	if !ok {
		return ""
	}

	pubKey := enc.Encode(elliptic.Marshal(elliptic.P256(), X, Y))

	return pubKey
}

func main() {
	fmt.Println("== GenerateKeys ==")
	keys, _ := GenerateKeys()

	fmt.Println("   PrivateKey:", keys.PrivateKey)
	fmt.Println("   PublicKey :", keys.PublicKey)

	fmt.Println("== GetHash ==")
	hash := GetHash("message")

	fmt.Println("        Hash :", hash)

	fmt.Println("== Sign ==")
	signature, _ := Sign(keys.PrivateKey, hash)

	fmt.Println("           R :", signature.R)
	fmt.Println("           S :", signature.S)

	fmt.Println("== Verify ==")
	isVerified := Verify(keys.PublicKey, hash, signature.R, signature.S)
	fmt.Println("    Verified :", isVerified)
}
