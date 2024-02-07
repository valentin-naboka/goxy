package handler

import (
	"crypto/tls"
	"goxy/cert"
	"io"
	"log"
	"net/http"
)

func ProxyConnect(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodConnect {
		http.Error(w, "Method is not allowed", http.StatusMethodNotAllowed)
		return
	}

	destConn, err := tls.Dial("tcp", req.Host, nil)
	if err != nil {
		http.Error(w, "Failed to connect to host", http.StatusInternalServerError)
		return
	}
	defer destConn.Close()

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking is not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijacking is failed", http.StatusInternalServerError)
		return
	}

	cer, key, err := cert.LoadRootCA("root-ca.crt", "root-ca.key")
	_, _, _ = cer, key, err
	cfg := &tls.Config{GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		log.Println(chi.ServerName)
		tlsCert := cert.GenerateCert(chi.ServerName, cer, key)
		return tlsCert, nil
	}}

	c := tls.Server(clientConn, cfg)
	go runTunneling(c, destConn)
	runTunneling(destConn, c)

}

func runTunneling(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}
