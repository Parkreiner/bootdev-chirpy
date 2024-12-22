package main

import (
	"log"
	"net/http"
	"strconv"
)

const portNumber = 8080

func main() {
	mux := http.NewServeMux()
	server := http.Server{
		Addr:    ":" + strconv.Itoa(portNumber),
		Handler: mux,
	}

	mux.Handle(
		"/app/",
		http.StripPrefix("/app", http.FileServer(http.Dir("."))),
	)

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)

		_, err := w.Write([]byte("OK"))
		if err != nil {
			log.Printf("Unable to write response to header. Error: %v\n", err)
		}
	})

	log.Fatal(server.ListenAndServe())
}
