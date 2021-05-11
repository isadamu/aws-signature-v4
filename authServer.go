package main

import (
	"fmt"
	"net/http"
	"os"
)

type AuthServer struct {
	author *AwsRequestAuthor
}

func NewAuthServer() *AuthServer {
	as := &AuthServer{
		author: NewAwsRequestAuthor(),
	}
	return as
}

// 会阻塞
func (as *AuthServer) httpServerRun() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", as.AuthHandler)

	_, _ = fmt.Fprintf(os.Stdout, "auth server start at :8801\n")

	err := http.ListenAndServe(":8801", mux)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, err.Error()+"\n")
	}
}

func (as *AuthServer) AuthHandler(w http.ResponseWriter, r *http.Request) {

	_, _ = fmt.Fprintf(os.Stdout, "receive request from [%s], host: [%s], url: [%s]\n", r.RemoteAddr, r.Host, r.URL.String())

	statusCode := http.StatusOK

	err := as.author.AuthRequest(r, AccessKey, SecretKey)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "auth failed\n")
		statusCode = http.StatusForbidden
	}

	w.WriteHeader(statusCode)
}
