package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com.com/Parkreiner/bootdev-chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

const portNumber = 8080

type apiConfig struct {
	fileserverHits atomic.Uint32
	isProduction   bool
	queries        *database.Queries
}

func (c *apiConfig) middlewareIncrementHitsOnVisit(
	next http.Handler,
) http.Handler {
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
func (c *apiConfig) adminMetrics(w http.ResponseWriter, _ *http.Request) {
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

func (c *apiConfig) resetAll(w http.ResponseWriter, r *http.Request) {
	if c.isProduction {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	err := c.queries.DeleteAllUsers(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Only reset hits if we know we were able to delete the users
	c.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
}

func validateChirp(w http.ResponseWriter, r *http.Request) {
	type UnvalidatedInput struct {
		Body string `json:"body"`
	}

	type JsonResponse struct {
		CleanedBody string `json:"cleaned_body"`
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

	words := strings.Split(input.Body, " ")
	profanity := []string{"kerfuffle", "sharbert", "fornax"}
	for i, word := range words {
		normalized := strings.ToLower(word)
		if slices.Contains(profanity, normalized) {
			words[i] = "****"
		}
	}

	bytes, err := json.Marshal(JsonResponse{
		CleanedBody: strings.Join(words, " "),
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

func healthStats(w http.ResponseWriter, _ *http.Request) {
	_, err := w.Write([]byte("OK"))
	if err != nil {
		log.Printf("Unable to write response to header. Error: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	headers := w.Header()
	headers.Set("Cache-Control", "no-cache")
	headers.Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
}

func (c *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	type createUserJson struct {
		Email string `json:"email"`
	}

	type createdUserResponse struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	payload := createUserJson{}
	err := decoder.Decode(&payload)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	newDbUser, err := c.queries.CreateUser(r.Context(), payload.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	bytes, err := json.Marshal(createdUserResponse{
		Id:        newDbUser.ID,
		CreatedAt: newDbUser.CreatedAt,
		UpdatedAt: newDbUser.UpdatedAt,
		Email:     newDbUser.Email,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	headers := w.Header()
	headers.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(bytes)
}

func main() {
	// Load all required env variables
	err := godotenv.Load("./.env")
	if err != nil {
		log.Fatal("Unable to load .env file. Is it present?")
	}
	dbUrl := os.Getenv("DB_URL")
	if dbUrl == "" {
		log.Fatal("Missing DB_URL environment variable")
	}
	isProduction := os.Getenv("PLATFORM") != "dev"

	// Set up database
	dbInstance, err := sql.Open("postgres", dbUrl)
	if err != nil {
		log.Fatalf("Error instantiating database with URL %s", dbUrl)
	}

	// Initialize "global" config (which is passed implicitly by using its
	// methods as route handlers)
	apiCfg := apiConfig{
		queries:      database.New(dbInstance),
		isProduction: isProduction,
	}

	// Set up server multiplexer
	mux := http.NewServeMux()
	server := http.Server{
		Addr:    ":" + strconv.Itoa(portNumber),
		Handler: mux,
	}

	// Handle all static file serving
	mux.Handle(
		"GET /app/",
		http.StripPrefix(
			"/app",
			apiCfg.middlewareIncrementHitsOnVisit(
				http.FileServer(http.Dir(".")),
			),
		),
	)

	// Routes accessible to all users
	mux.HandleFunc("POST /api/users", apiCfg.createUser)
	mux.HandleFunc("POST /api/validate_chirp", validateChirp)
	mux.HandleFunc("GET /api/healthz", healthStats)

	// Admin-only routes
	mux.HandleFunc("POST /admin/reset", apiCfg.resetAll)
	mux.HandleFunc("GET /admin/metrics", apiCfg.adminMetrics)

	log.Fatal(server.ListenAndServe())
}
