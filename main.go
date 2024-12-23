package main

import (
	"encoding/json"
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

func validateChirp(w http.ResponseWriter, r *http.Request) {
	type UnvalidatedInput struct {
		Body string `json:"body"`
	}

	type JsonResponse struct {
		Valid bool `json:"valid"`
	}

	type ErrorResponse struct {
		Error string `json:"error"`
	}

	headers := w.Header()
	decoder := json.NewDecoder(r.Body)

	input := UnvalidatedInput{}
	err := decoder.Decode(&input)
	if err != nil {
		bytes, err := json.Marshal(ErrorResponse{
			Error: "Unable to decode input",
		})
		if err != nil {
			log.Printf("Unable to encode static error response")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusBadRequest)
		headers.Set("Content-Type", "application/json")
		w.Write(bytes)
		return
	}

	// I hate that I have to do this, but this is Boot.dev instructs you to do.
	// Rather than just treat an invalid input as something that produces a
	// false value, you just treat it as an error instead??? It not only makes
	// the code longer, but also makes the behavior more unintuitive for users??
	if len(input.Body) > 140 {
		bytes, err := json.Marshal(ErrorResponse{
			Error: "Chirp is too long",
		})
		if err != nil {
			log.Printf("Unable to encode static error response")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusBadRequest)
		headers.Set("Content-Type", "application/json")
		w.Write(bytes)
		return
	}

	bytes, err := json.Marshal(JsonResponse{
		Valid: true,
	})
	if err != nil {
		log.Printf("Unable to encode static valid input response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	headers.Set("Content-Type", "application/json")
	w.Write(bytes)
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

	mux.HandleFunc("POST /api/validate_chirp", validateChirp)
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
