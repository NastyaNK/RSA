package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", main_page)
	http.HandleFunc("/keys", keys_page)
	http.HandleFunc("/public", download_pubkey)
	http.HandleFunc("/private", download_privkey)
	http.ListenAndServe(":80", nil)
}

func keys_page(w http.ResponseWriter, r *http.Request) {
	GenerateKeyPair(5000)
	index, _ := ioutil.ReadFile("keys.html")
	w.Write([]byte(index))
}

func download_pubkey(w http.ResponseWriter, r *http.Request) {
	content, _ := ioutil.ReadFile("public")
	download(w, content, "public.pem")
}

func download_privkey(w http.ResponseWriter, r *http.Request) {
	content, _ := ioutil.ReadFile("private")
	download(w, content, "private.pem")
}

func download(w http.ResponseWriter, data []byte, filename string) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Write(data)
}

func main_page(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseMultipartForm(1024)
		keyf, _, err := r.FormFile("key")
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		key, _ := ioutil.ReadAll(keyf)
		keyf.Close()
		isEncrypt := r.FormValue("type") == "1"
		priv, pub := BytesToKey(key, !isEncrypt)
		if priv == nil && pub == nil {
			w.Write([]byte("Ключ не правильный, повторите попытку или создайте новые"))
			return
		}
		file, handler, err := r.FormFile("file")
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		content, _ := ioutil.ReadAll(file)
		file.Close()
		if isEncrypt {
			content = encrypt(content, pub)
		} else {
			content = decrypt(content, priv)
		}
		download(w, content, handler.Filename)
	} else {
		index, _ := ioutil.ReadFile("index.html")
		w.Write([]byte(index))
	}
}

func encrypt(msg []byte, pub *rsa.PublicKey) []byte {
	hash := sha512.New()
	ciphertext, _ := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	return ciphertext
}

func decrypt(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha512.New()
	plaintext, _ := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	return plaintext
}

func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)
	return privBytes
}

func PublicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, _ := x509.MarshalPKIXPublicKey(pub)
	pubBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubASN1,
		},
	)
	return pubBytes
}

func GenerateKeyPair(bits int) {
	privkey, _ := rsa.GenerateKey(rand.Reader, bits)
	privfile, _ := os.Create("private")
	privfile.Write(PrivateKeyToBytes(privkey))
	privfile.Close()
	pubfile, _ := os.Create("public")
	pubfile.Write(PublicKeyToBytes(&privkey.PublicKey))
	pubfile.Close()
}

func BytesToKey(msg []byte, isPriv bool) (*rsa.PrivateKey, *rsa.PublicKey) {
	block, _ := pem.Decode(msg)
	b := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		b, _ = x509.DecryptPEMBlock(block, nil)
	}
	if isPriv {
		key, _ := x509.ParsePKCS1PrivateKey(b)
		return key, nil
	}
	ifc, _ := x509.ParsePKIXPublicKey(b)
	key, _ := ifc.(*rsa.PublicKey)
	return nil, key
}
