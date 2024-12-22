package main

import (
	"log"
	"net/http"
	"strconv"
	"sync/atomic"
)

const portNumber = 8080

type apiConfig struct {
	fileserverHits atomic.Uint32
}

func (c *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (c *apiConfig) hitsSinceLastShutdown(
	w http.ResponseWriter,
	_ *http.Request,
) {
	headers := w.Header()
	headers.Set("Cache-Control", "no-cache")

	hits := c.fileserverHits.Load()
	msg := "Hits: " + strconv.Itoa(int(hits))
	headers.Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(msg))
}

func (c *apiConfig) resetHits(w http.ResponseWriter, _ *http.Request) {
	c.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
}

func main() {
	mux := http.NewServeMux()
	server := http.Server{
		Addr:    ":" + strconv.Itoa(portNumber),
		Handler: mux,
	}

	apiCfg := apiConfig{}
	mux.Handle(
		"/app/",
		http.StripPrefix(
			"/app",
			apiCfg.middlewareMetricsInc(
				http.FileServer(http.Dir(".")),
			),
		),
	)

	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, _ *http.Request) {
		headers := w.Header()
		headers.Set("Cache-Control", "no-cache")
		headers.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)

		_, err := w.Write([]byte("OK"))
		if err != nil {
			log.Printf("Unable to write response to header. Error: %v\n", err)
		}
	})

	mux.HandleFunc("GET /api/metrics", apiCfg.hitsSinceLastShutdown)
	mux.HandleFunc("POST /api/reset", apiCfg.resetHits)

	log.Fatal(server.ListenAndServe())
}
