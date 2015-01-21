package main

import (
	"fmt"
	"log"
	"time"
	"net/http"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rand"
	"math/big"
	"os"
)

func main(){
	fmt.Println("Starting up");
	http.Handle("/", http.FileServer(http.Dir("./public/")))
	http.HandleFunc("/submit", submitHandler)
	log.Fatal(http.ListenAndServeTLS(":8040", "./private/server.crt", "./private/key.pem", nil))
}

func submitHandler(w http.ResponseWriter, r *http.Request){
	if r.Method == "POST" {
		signedpubkeystr := r.FormValue("pubkey")//signed by clients private key
		signedpubkey := []byte(signedpubkeystr)
		cert := sign(signedpubkey)
		w.Header().Set("Content-Type", "application/x-x509-user-cert")
		fmt.Fprintf(w, "%s", cert)
	} else {
		fmt.Fprintf(w, "<h1>Wrong method :P</h1>")
	}
}

//Structures reflecting those found in RFC 3180
type SubjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type PublicKeyAndChallenge struct {
	Spki SubjectPublicKeyInfo
	Challenge string
}

type SignedPublicKeyAndChallenge struct{
	PublicKeyAndChallenge PublicKeyAndChallenge
	SignitureAlgorithm pkix.AlgorithmIdentifier
	Signiture asn1.BitString
}

func sign (signeePubKeySigned []byte) []byte{
	signerPath := "./private/key.pem"
	signerFile, err := os.Open(signerPath)
	if err != nil {
		log.Fatal(err)
	}
	signerInfo, err := os.Stat(signerPath)
	if err != nil {
		log.Fatal(err)
	}
	signerPrivKey := make([]byte, signerInfo.Size())
	_, err = signerFile.Read(signerPrivKey)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Person",
		},
		NotBefore: time.Now(),
		NotAfter: time.Unix(time.Now().Unix() + 365 * 24 * int64(time.Hour.Seconds()), 0),
		SignatureAlgorithm: x509.SHA256WithRSA,
		KeyUsage: x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}},
		BasicConstraintsValid: true,
		IsCA: true,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}
	signeeKeySigned := make([]byte, 2048)
	_ , err = base64.StdEncoding.Decode(signeeKeySigned, signeePubKeySigned)
	if ( err != nil ){
		log.Fatal(err)
	}
	//Parse should be asn.1 encoded
	var signee SignedPublicKeyAndChallenge
	_, err = asn1.Unmarshal(signeeKeySigned, &signee)
	if err != nil {
		log.Fatal(err)
	}
	encodedPubKey, err := asn1.Marshal(signee.PublicKeyAndChallenge.Spki)
	if err != nil {
		log.Fatal(err)
	}
	pubKey, err := x509.ParsePKIXPublicKey(encodedPubKey)
	if err != nil {
		log.Fatal(err)
	}
	//TODO: Check the key against signature
	block, _ := pem.Decode(signerPrivKey)
	signerPriv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if ( err != nil ){
		log.Fatal(err.Error())
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, signerPriv)
	if ( err != nil ){
		log.Fatal(err)
	}
	return cert;
}
