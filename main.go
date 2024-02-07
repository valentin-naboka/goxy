package main

import (
	"goxy/handler"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	go func() {
		if err := http.ListenAndServe(":1080", http.HandlerFunc(handler.LogMiddleware(handler.ProxyConnect))); err != nil {
			log.Fatal(err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
