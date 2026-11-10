// Minimal threaded static file server for lab canaries.
// usage: fileserver <bind-addr:port> <dir>
package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: fileserver <addr:port> <dir>")
		os.Exit(2)
	}
	h := http.FileServer(http.Dir(os.Args[2]))
	srv := &http.Server{Addr: os.Args[1], Handler: h}
	fmt.Println("serving", os.Args[1], os.Args[2])
	if err := srv.ListenAndServe(); err != nil {
		fmt.Println("err:", err)
	}
}
