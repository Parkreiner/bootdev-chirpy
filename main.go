package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
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

// TODO: Might need to refactor this logic and update the overall approach.
// Boot.dev just instructs you to return a populated HTML template when the
// /admin/metrics endpoint gets hit, with no guidance on how to do that. Not
// sure if that gets covered in the static site generator unit or the blog
// aggregator unit. This works, but it's definitely not scalable long-term
func (c *apiConfig) adminMetricsRoute(w http.ResponseWriter, _ *http.Request) {
	headers := w.Header()

	file, err := os.ReadFile("./templates/adminMetrics.html")
	if err != nil {
		headers.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Unable to process request for admins route"))
		return
	}

	populated := fmt.Sprintf(string(file), c.fileserverHits.Load())
	headers.Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(populated))
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
		"GET /app/",
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
		w.WriteHeader(http.StatusOK)

		_, err := w.Write([]byte("OK"))
		if err != nil {
			log.Printf("Unable to write response to header. Error: %v\n", err)
		}
	})

	mux.HandleFunc("POST /admin/reset", apiCfg.resetHits)
	mux.HandleFunc("GET /admin/metrics", apiCfg.adminMetricsRoute)

	log.Fatal(server.ListenAndServe())
}
