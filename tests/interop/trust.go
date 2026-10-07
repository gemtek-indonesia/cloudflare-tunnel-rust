package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/cloudflare/cloudflared/tlsconfig"
	"github.com/rs/zerolog"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type trustInput struct {
	Kind string `json:"kind"`
	PEM  string `json:"pem"`
	Name string `json:"name"`
	Path string `json:"path"`
}

func main() {
	var input trustInput
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	if err = json.Unmarshal(data, &input); err != nil {
		panic(err)
	}
	if input.Kind == "cache" {
		cache(input.Name)
		return
	}
	out := map[string]any{}
	encoded, err := base64.StdEncoding.DecodeString(input.PEM)
	if err != nil {
		panic(err)
	}
	var pool *x509.CertPool
	switch input.Kind {
	case "append":
		pool = x509.NewCertPool()
		out["ok"] = pool.AppendCertsFromPEM(encoded)
	case "hostname":
		block, _ := pem.Decode(encoded)
		if block == nil {
			out["ok"] = false
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		out["ok"] = err == nil && cert.VerifyHostname(input.Name) == nil
	case "native":
		pool, err = x509.SystemCertPool()
		out["ok"] = err == nil
	case "origin":
		logger := zerolog.New(io.Discard)
		pool, err = tlsconfig.LoadOriginCA(input.Path, &logger)
		out["ok"] = err == nil
	default:
		panic("unknown synthetic trust operation")
	}
	if pool != nil {
		out["count"] = len(pool.Subjects())
	}
	if err = json.NewEncoder(os.Stdout).Encode(out); err != nil {
		panic(err)
	}
}

func cache(mode string) {
	dir, err := os.MkdirTemp("", "native-cache-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "edge.test"}, DNSNames: []string{"edge.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	file := filepath.Join(dir, "roots.pem")
	if mode == "failure" {
		if err = os.Mkdir(file, 0700); err != nil {
			panic(err)
		}
	} else if mode == "empty" {
		err = os.WriteFile(file, []byte("invalid pem"), 0600)
	} else {
		err = os.WriteFile(file, data, 0600)
	}
	if err != nil {
		panic(err)
	}
	os.Setenv("SSL_CERT_FILE", file)
	os.Setenv("SSL_CERT_DIR", filepath.Join(dir, "missing"))
	first, firstErr := x509.SystemCertPool()
	out := map[string]any{"first_ok": firstErr == nil}
	if first != nil {
		out["first_count"] = len(first.Subjects())
	}
	if mode == "failure" {
		if err = os.Remove(file); err != nil {
			panic(err)
		}
	}
	if mode == "success" {
		err = os.WriteFile(file, []byte("changed pem"), 0600)
	} else {
		err = os.WriteFile(file, data, 0600)
	}
	if err != nil {
		panic(err)
	}
	second, secondErr := x509.SystemCertPool()
	out["second_ok"] = secondErr == nil
	if second != nil {
		out["second_count"] = len(second.Subjects())
		_, verifyErr := cert.Verify(x509.VerifyOptions{Roots: second, DNSName: "edge.test"})
		out["explicit_verify_ok"] = verifyErr == nil
	}
	_, verifyErr := cert.Verify(x509.VerifyOptions{DNSName: "edge.test"})
	out["default_verify_ok"] = verifyErr == nil
	if err = json.NewEncoder(os.Stdout).Encode(out); err != nil {
		panic(err)
	}
}
