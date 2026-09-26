// Command healthcheck performs an HTTP readiness probe against a FortressWAF
// listener.
//
// It exists because the runtime image is distroless (no shell, no wget), so
// Docker and docker-compose healthchecks need a self-contained static binary.
//
//	usage: healthcheck <url>
//
// Exit code 0 when the endpoint answers 2xx, 1 on any other outcome.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: healthcheck <url>")
		os.Exit(2)
	}
	target := os.Args[1]

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck %s: %v\n", target, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "healthcheck %s: unexpected status %d\n", target, resp.StatusCode)
		os.Exit(1)
	}
}
