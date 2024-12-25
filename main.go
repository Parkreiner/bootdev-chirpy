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

	"github.com.com/Parkreiner/bootdev-chirpy/internal/auth"
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

type UserCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SecureUserResponse struct {
	Id        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

type ChirpResponse struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Id        uuid.UUID `json:"id"`
	Body      string    `json:"body"`
	UserId    uuid.UUID `json:"user_id"`
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
	decoder := json.NewDecoder(r.Body)
	payload := UserCredentials{}
	err := decoder.Decode(&payload)
	if err != nil {
		processDecodingError(w, err, "Request payload is invalid")
		return
	}

	hashed, err := auth.HashPassword(payload.Password)
	if err != nil {
		log.Printf("Unable to hash password %s. Error: %v", payload.Password, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	newDbUser, err := c.queries.CreateUser(r.Context(), database.CreateUserParams{
		Email:          payload.Email,
		HashedPassword: hashed,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	bytes, err := json.Marshal(SecureUserResponse{
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

	bytes, err := json.Marshal(ChirpResponse{
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

func (c *apiConfig) GetChirp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("chirpId")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	parsed, err := uuid.Parse(id)
	if err != nil {
		log.Printf(
			"Unable to convert user-provided ID %s into ID. Error: %v\n",
			id,
			err,
		)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	chirp, err := c.queries.GetChirp(r.Context(), parsed)
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("Unable to retrieve chirp for ID %s. Error: %v\n", parsed, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resChirp := ChirpResponse{
		Id:        chirp.ID,
		Body:      chirp.Body,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		UserId:    chirp.UserID,
	}
	bytes, err := json.Marshal(resChirp)
	if err != nil {
		log.Printf("Unable to marshal chirp %v. Error %v\n", resChirp, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	headers := w.Header()
	headers.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(bytes)
}

func (c *apiConfig) GetAllChirps(w http.ResponseWriter, r *http.Request) {
	dbChirps, err := c.queries.GetAllChirps(r.Context())
	if err != nil {
		log.Printf("Unable to get all chirps: error %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	responseChirps := make([]ChirpResponse, 0, len(dbChirps))
	for _, chirp := range dbChirps {
		responseChirps = append(responseChirps, ChirpResponse{
			Id:        chirp.ID,
			Body:      chirp.Body,
			UserId:    chirp.UserID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
		})
	}

	bytes, err := json.Marshal(responseChirps)
	if err != nil {
		log.Printf(
			"Unable to serialize chirps %v. Error: %v",
			responseChirps,
			err,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	headers := w.Header()
	headers.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(bytes)
}

func (c *apiConfig) login(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	payload := UserCredentials{}
	err := decoder.Decode(&payload)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	dbUser, err := c.queries.GetUserByEmail(r.Context(), payload.Email)
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Printf(
			"Error getting user from database for email %s. Error: %v",
			payload.Email,
			err,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = auth.CheckPasswordHash(payload.Password, dbUser.HashedPassword)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	bytes, err := json.Marshal(SecureUserResponse{
		Id:        dbUser.ID,
		UpdatedAt: dbUser.UpdatedAt,
		CreatedAt: dbUser.CreatedAt,
		Email:     dbUser.Email,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	headers := w.Header()
	headers.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
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
	mux.HandleFunc("POST /api/login", apiCfg.login)
	mux.HandleFunc("POST /api/users", apiCfg.createUser)
	mux.HandleFunc("GET /api/chirps", apiCfg.GetAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpId}", apiCfg.GetChirp)
	mux.HandleFunc("POST /api/chirps", apiCfg.createChirp)
	mux.HandleFunc("GET /api/healthz", healthStats)

	// Admin-only routes
	mux.HandleFunc("POST /admin/reset", apiCfg.resetAll)
	mux.HandleFunc("GET /admin/metrics", apiCfg.adminMetrics)

	log.Fatal(server.ListenAndServe())
}
