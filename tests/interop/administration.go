package main

import (
	"github.com/cloudflare/cloudflared/cmd/cloudflared/tunnel"
	"os"
)

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	output, err := tunnel.RustInteropAdministrationJSON(data)
	if err != nil {
		panic(err)
	}
	if _, err := os.Stdout.Write(append(output, '\n')); err != nil {
		panic(err)
	}
}
