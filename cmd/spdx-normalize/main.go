package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bojieli/tunless/internal/spdxnormalize"
)

func main() {
	epoch := flag.Int64("epoch", -1, "Unix timestamp for creationInfo.created")
	namespace := flag.String("namespace", "", "stable SPDX document namespace")
	flag.Parse()
	if flag.NArg() != 1 || *epoch < 0 || *namespace == "" {
		fmt.Fprintln(os.Stderr, "usage: spdx-normalize --epoch UNIX_TIMESTAMP --namespace HTTPS_URL SPDX_JSON")
		os.Exit(2)
	}

	path := flag.Arg(0)
	input, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read SPDX document: %v\n", err)
		os.Exit(1)
	}
	output, err := spdxnormalize.Normalize(input, *epoch, *namespace)
	if err != nil {
		fmt.Fprintf(os.Stderr, "normalize SPDX document: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(path, output, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write SPDX document: %v\n", err)
		os.Exit(1)
	}
}
