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

func processDecodingError(
	writer http.ResponseWriter,
	err error,
	clientErrorMessage string,
) {
	type ErrorResponse struct {
		Error string `json:"error"`
	}

	log.Print(err)
	bytes, err := json.Marshal(ErrorResponse{
		Error: clientErrorMessage,
	})
	if err != nil {
		log.Printf("Unable to encode static error response")
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	writer.WriteHeader(http.StatusBadRequest)
	headers := writer.Header()
	headers.Set("Content-Type", "application/json")
	writer.Write(bytes)
}

func removeProfanity(input string) string {
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
	words := strings.Split(input, " ")
	for i, word := range words {
		normalized := strings.ToLower(word)
		if slices.Contains(profaneWords, normalized) {
			words[i] = "****"
		}
	}

	return strings.Join(words, " ")
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

	err = c.queries.DeleteAllChirps(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Only reset hits if we know we were able to delete the users
	c.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
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
		processDecodingError(w, err, "Request payload is invalid")
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

func (c *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {
	type chirpPayload struct {
		Body   string    `json:"body"`
		UserId uuid.UUID `json:"user_id"`
	}

	type errorResponse struct {
		Error string `json:"error"`
	}

	headers := w.Header()
	decoder := json.NewDecoder(r.Body)
	payload := chirpPayload{}

	err := decoder.Decode(&payload)
	if err != nil {
		processDecodingError(w, err, "Request payload is invalid")
		return
	}

	if len(payload.Body) > 140 {
		bytes, err := json.Marshal(errorResponse{
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

	if payload.Body == "" {
		bytes, err := json.Marshal(errorResponse{
			Error: "Chirp is empty",
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

	dbChirp, err := c.queries.CreateChirp(
		r.Context(),
		database.CreateChirpParams{
			UserID: payload.UserId,
			Body:   removeProfanity(payload.Body),
		},
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	type CreatedChirpResponse struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserId    uuid.UUID `json:"user_id"`
	}
	bytes, err := json.Marshal(CreatedChirpResponse{
		Id:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserId:    dbChirp.UserID,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

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
	mux.HandleFunc("POST /api/chirps", apiCfg.createChirp)
	mux.HandleFunc("GET /api/healthz", healthStats)

	// Admin-only routes
	mux.HandleFunc("POST /admin/reset", apiCfg.resetAll)
	mux.HandleFunc("GET /admin/metrics", apiCfg.adminMetrics)

	log.Fatal(server.ListenAndServe())
}
