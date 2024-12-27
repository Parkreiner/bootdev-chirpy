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
	"github.com.com/Parkreiner/bootdev-chirpy/internal/secret"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

const portNumber = 8080

type ApiKeys struct {
	Polka string
}

type apiConfig struct {
	fileserverHits atomic.Uint32
	isProduction   bool
	queries        *database.Queries
	jwtSecret      secret.Secret[string]
	apiKeys        ApiKeys
}

type UserCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserResponse struct {
	Id          uuid.UUID `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Email       string    `json:"email"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
}

type UserResponseWithTokens struct {
	UserResponse
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
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
		log.Println("Failed to delete all users")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = c.queries.DeleteAllChirps(r.Context())
	if err != nil {
		log.Println("Failed to delete all chirps")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = c.queries.DeleteAllRefreshTokens(r.Context())
	if err != nil {
		log.Println("Failed to delete all refresh tokens")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Only reset hits if we know we were able to delete the users
	c.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
}

func (c *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	log.Println("Creating new user")
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
		if strings.Contains(err.Error(), "duplicate key value") {
			log.Printf(
				"Cannot create user for email '%s'; email already exists\n",
				payload.Email,
			)
			w.WriteHeader(400)
			return
		}

		log.Printf(
			"Unable to create user for email '%s' and password '%s'. Error: %v\n",
			payload.Email,
			payload.Password,
			err,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	bytes, err := json.Marshal(UserResponse{
		Id:          newDbUser.ID,
		CreatedAt:   newDbUser.CreatedAt,
		UpdatedAt:   newDbUser.UpdatedAt,
		Email:       newDbUser.Email,
		IsChirpyRed: newDbUser.IsChirpyRed,
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
		Body string `json:"body"`
	}

	type errorResponse struct {
		Error string `json:"error"`
	}

	accessToken, err := auth.GetBearerToken(&r.Header)
	if err != nil {
		log.Println("Bearer token is missing or invalid")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	userId, err := auth.ValidateJwt(accessToken, c.jwtSecret)
	if err != nil {
		log.Printf("Unable to validate token '%s'.\nError: %v\n", accessToken, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	headers := w.Header()
	decoder := json.NewDecoder(r.Body)
	payload := chirpPayload{}

	err = decoder.Decode(&payload)
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
			UserID: userId,
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
	query := r.URL.Query()

	orderBy := strings.ToUpper(query.Get("sort"))
	if orderBy != "" && orderBy != "ASC" && orderBy != "DESC" {
		log.Printf("Request trying to sort by invalid value %s\n", orderBy)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if orderBy == "" {
		orderBy = "ASC"
	}

	rawAuthorId := query.Get("author_id")
	var authorId uuid.UUID
	if rawAuthorId != "" {
		id, err := uuid.Parse(rawAuthorId)
		if err != nil {
			log.Printf("Unable to parse UUID %s\n", rawAuthorId)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		authorId = id
	}

	dbChirps, err := c.queries.GetChirps(r.Context(), database.GetChirpsParams{
		OrderBy: orderBy,
		UserID: uuid.NullUUID{
			UUID:  authorId,
			Valid: rawAuthorId != "",
		},
	})
	if err != nil {
		log.Printf(
			"Unable to query chirps. Author ID: '%s'. Sorting method: '%s'. Error: %v\n",
			rawAuthorId,
			orderBy,
			err,
		)
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

	accessToken, err := auth.MakeJWT(dbUser.ID, c.jwtSecret)
	if err != nil {
		log.Printf(
			"Unable to produce new JWT for user ID '%s'. Error: %v\n",
			dbUser.ID,
			err,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	refreshPayload, err := auth.MakeRefreshToken()
	if err != nil {
		log.Printf("Unable to generate refresh token. Error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	refreshTokenEntry, err := c.queries.CreateNewRefreshToken(
		r.Context(),
		database.CreateNewRefreshTokenParams{
			Token:  refreshPayload,
			UserID: dbUser.ID,
		},
	)
	if err != nil {
		log.Printf("Unable to write refresh token to database. Error: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	bytes, err := json.Marshal(UserResponseWithTokens{
		Token:        accessToken,
		RefreshToken: refreshTokenEntry.Token,
		UserResponse: UserResponse{
			Id:          dbUser.ID,
			UpdatedAt:   dbUser.UpdatedAt,
			CreatedAt:   dbUser.CreatedAt,
			Email:       dbUser.Email,
			IsChirpyRed: dbUser.IsChirpyRed,
		},
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

func (c *apiConfig) RefreshAccessToken(w http.ResponseWriter, r *http.Request) {
	type RefreshAccessTokenResponse struct {
		Token string `json:"token"`
	}

	refreshToken, err := auth.GetBearerToken(&r.Header)
	if err != nil {
		log.Println("Missing bearer token")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	dbRefreshToken, err := c.queries.GetRefreshToken(r.Context(), refreshToken)
	if err == sql.ErrNoRows {
		log.Printf("No token found for %s.\nError: %v\n", refreshToken, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err != nil {
		log.Printf(
			"Unable to complete query for token %s.\nError: %v\n",
			refreshToken,
			err,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	tokenIsAlreadyRevoked := dbRefreshToken.RevokedAt.Valid
	if tokenIsAlreadyRevoked {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	tokenIsExpired := time.Now().After(dbRefreshToken.ExpiresAt)
	if tokenIsExpired {
		log.Printf("Token %s is expired\n", refreshToken)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// If we can't find a user when we already have a refresh token entry,
	// that's a very good sign that there's something wrong with our database;
	// no need to treat lack of results as special exception case
	user, err := c.queries.GetUserById(r.Context(), dbRefreshToken.UserID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	newAccessToken, err := auth.MakeJWT(user.ID, c.jwtSecret)
	if err != nil {
		log.Printf("Unable to generate new JWT for user ID %s\n", user.ID)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	bytes, err := json.Marshal(RefreshAccessTokenResponse{
		Token: newAccessToken,
	})
	if err != nil {
		log.Printf("Unable to serialize token into JSON. Error: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	headers := w.Header()
	headers.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(bytes)
}

func (c *apiConfig) revokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(&r.Header)
	if err != nil {
		log.Println("Missing bearer token")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	dbToken, err := c.queries.GetRefreshToken(r.Context(), refreshToken)
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Printf(
			"Unable to match token to database record. Token: %s\nError: %v\n",
			refreshToken,
			err,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	tokenAlreadyRevoked := dbToken.RevokedAt.Valid
	if tokenAlreadyRevoked {
		log.Printf(
			"Trying to revoke token that was revoked at %s. Token: %s\n",
			dbToken.RevokedAt.Time,
			dbToken.Token,
		)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = c.queries.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		log.Printf("Unable to revoke token %s.\nError: %v\n", refreshToken, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (c *apiConfig) updateLoginCredentials(
	w http.ResponseWriter,
	r *http.Request,
) {
	accessToken, err := auth.GetBearerToken(&r.Header)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	userId, err := auth.ValidateJwt(accessToken, c.jwtSecret)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	decoder := json.NewDecoder(r.Body)
	cred := UserCredentials{}
	err = decoder.Decode(&cred)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if cred.Email == "" || cred.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	hashed, err := auth.HashPassword(cred.Password)
	if err != nil {
		log.Printf("Unable to hash password %s. Error: %v\n", cred.Password, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	updatedUser, err := c.queries.UpdateLoginCredentials(
		r.Context(),
		database.UpdateLoginCredentialsParams{
			ID:             userId,
			Email:          cred.Email,
			HashedPassword: hashed,
		},
	)
	if err != nil {
		log.Printf(
			"Unable to update login credentials for user ID %s.\nNew email: %s.\nNew password: %s\nError: %v",
			userId,
			cred.Email,
			cred.Password,
			err,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	bytes, err := json.Marshal(UserResponse{
		Id:          updatedUser.ID,
		Email:       updatedUser.Email,
		CreatedAt:   updatedUser.CreatedAt,
		UpdatedAt:   updatedUser.UpdatedAt,
		IsChirpyRed: updatedUser.IsChirpyRed,
	})
	if err != nil {
		log.Printf(
			"unable to serialize database response into JSON for user %s. Error: %v\n",
			updatedUser.ID,
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

func (c *apiConfig) deleteChirp(w http.ResponseWriter, r *http.Request) {
	chirpId := r.PathValue("chirpId")
	chirpUuid, err := uuid.Parse(chirpId)
	if err != nil {
		log.Printf("Unable to parse ID %s.\nError %v\n", chirpId, err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	accessToken, err := auth.GetBearerToken(&r.Header)
	if err != nil {
		log.Println("Bearer for access token is missing")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	userId, err := auth.ValidateJwt(accessToken, c.jwtSecret)
	if err != nil {
		log.Printf("Unable to parse token %s.\nError %v\n", accessToken, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	deletedChirp, err := c.queries.DeleteChirp(
		r.Context(),
		database.DeleteChirpParams{
			ID:     chirpUuid,
			UserID: userId,
		},
	)
	if err == sql.ErrNoRows {
		log.Printf("Chirp ID %s not found in database\n", chirpUuid)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if err != nil {
		log.Printf(
			"Unable to delete chirp for chirp ID %s and user ID %s.\nError: %v\n",
			chirpUuid,
			userId,
			err,
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Printf("Deleted chirp %s. Chirp body: %v\n", chirpUuid, deletedChirp)
	w.WriteHeader(http.StatusNoContent)
}

func (c *apiConfig) upgradeUserSubscription(
	w http.ResponseWriter,
	r *http.Request,
) {
	type PolkaWebhookData struct {
		UserId string `json:"user_id"`
	}

	type PolkaWebhookRequest struct {
		Event string           `json:"event"`
		Data  PolkaWebhookData `json:"data"`
	}

	apiKey, err := auth.GetApiKey(&r.Header)
	if err != nil {
		log.Printf("Unable to parse API key. Error %v\n", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if apiKey != c.apiKeys.Polka {
		log.Println("Supplied API key is invalid")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	decoder := json.NewDecoder(r.Body)
	payload := PolkaWebhookRequest{}
	err = decoder.Decode(&payload)
	if err != nil {
		log.Printf("Unable to parse request. Error: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if payload.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	userId, err := uuid.Parse(payload.Data.UserId)
	if err != nil {
		log.Printf("Unable to parse user ID from event. Error: %v\n", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	_, err = c.queries.UpgradeUserSubscriptionStatus(r.Context(), userId)
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Printf("Unable to upgrade user %s. Error %v\n", userId, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
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
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("Missing JWT secret")
	}
	polkaApiKey := os.Getenv("POLKA_API_KEY")
	if polkaApiKey == "" {
		log.Fatal("Missing Polka API key")
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
		queries:        database.New(dbInstance),
		isProduction:   isProduction,
		fileserverHits: atomic.Uint32{},
		jwtSecret:      secret.New(jwtSecret),
		apiKeys: ApiKeys{
			Polka: polkaApiKey,
		},
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

	// Routes for specific resources in the app's domain
	mux.HandleFunc("POST /api/users", apiCfg.createUser)
	mux.HandleFunc("PUT /api/users", apiCfg.updateLoginCredentials)
	mux.HandleFunc("GET /api/chirps", apiCfg.GetAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpId}", apiCfg.GetChirp)
	mux.HandleFunc("POST /api/chirps", apiCfg.createChirp)
	mux.HandleFunc("DELETE /api/chirps/{chirpId}", apiCfg.deleteChirp)

	// Non-specific routes
	mux.HandleFunc("POST /api/login", apiCfg.login)
	mux.HandleFunc("POST /api/refresh", apiCfg.RefreshAccessToken)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeRefreshToken)
	mux.HandleFunc("GET /api/healthz", healthStats)

	// Admin-only routes
	mux.HandleFunc("POST /admin/reset", apiCfg.resetAll)
	mux.HandleFunc("GET /admin/metrics", apiCfg.adminMetrics)

	// Webhooks
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.upgradeUserSubscription)

	log.Fatal(server.ListenAndServe())
}
