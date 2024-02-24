package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/jakobilobi/go-httpstat"
)

func main() {
	args := os.Args
	if len(args) < 2 {
		log.Fatalf("Usage: go run main.go URL")
	}
	req, err := http.NewRequest("GET", args[1], nil)
	if err != nil {
		log.Fatal(err)
	}

	var result httpstat.Result
	ctx := httpstat.WithHTTPStat(req.Context(), &result)
	req = req.WithContext(ctx)

	client := http.DefaultClient
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		log.Fatal(err)
	}
	res.Body.Close()
	result.End()

	fmt.Printf("%+v\n", result)
}
