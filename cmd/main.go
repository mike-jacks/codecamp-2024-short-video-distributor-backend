package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/joho/godotenv"
	"github.com/mike-jacks/codecamp-2024-short-video-distributor-backend/db"
	"github.com/mike-jacks/codecamp-2024-short-video-distributor-backend/graph"
	"github.com/rs/cors"
)

const defaultPort = "8080"

func main() {
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning:Error loading .env file: %v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	db := initDatabase()
	defer db.Close()

	// Test database connection
	if err := db.Ping(context.Background()); err != nil {
		log.Fatalf("Error pinging database: %v", err)
	}

	resolver := graph.NewResolver(db.DB())

	srv := handler.NewDefaultServer(graph.NewExecutableSchema(graph.Config{Resolvers: resolver}))

	// Create a new cors middleware
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: true,
	})

	// Create a new router
	mux := http.NewServeMux()

	// Routes with cors middleware
	mux.Handle("/", playground.Handler("GraphQL playground", "/query"))
	mux.Handle("/query", corsHandler.Handler(srv))
	handleOAuthCallback(mux, resolver)

	log.Printf("connect to http://localhost:%s/ for GraphQL playground", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func initDatabase() db.Database {
	config := &db.PostgresConfig{
		Host:     os.Getenv("PGHOST"),
		Port:     os.Getenv("PGPORT"),
		User:     os.Getenv("POSTGRES_USER"),
		Password: os.Getenv("POSTGRES_PASSWORD"),
		DBName:   os.Getenv("POSTGRES_DB"),
		SSLMode:  "disable",
	}

	db, err := db.NewDatabase(db.PostgresType, config)
	if err != nil {
		log.Fatalf("Error creating database: %v", err)
	}

	if err := db.Connect(); err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	return db
}

func handleOAuthCallback(mux *http.ServeMux, resolver *graph.Resolver) {
	mux.HandleFunc("/auth/youtube/callback", func(w http.ResponseWriter, r *http.Request) {
		// Only allow GET requests
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get the state parameter (session token)
		state := r.URL.Query().Get("state")
		if state == "" {
			http.Error(w, "Session token not found", http.StatusBadRequest)
			return
		}

		// Validate session and get user ID
		userID, err := resolver.YoutubeService.ValidateAndGetUserID(state)
		if err != nil {
			log.Printf("Validating session failed: %v", err)
			http.Error(w, "Invalid or expired session", http.StatusBadRequest)
			return
		}

		// Get the authorization code
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Authorization code not found", http.StatusBadRequest)
			return
		}

		// Handle the authorization
		_, err = resolver.YoutubeService.ExchangeAndSaveToken(r.Context(), code, userID)
		if err != nil {
			log.Printf("Handling callback failed: %v", err)
			http.Error(w, "Failed to handle callback", http.StatusInternalServerError)
		}

		frontendURL := os.Getenv("FRONTEND_URL")
		if frontendURL == "" {
			log.Fatal("FRONTEND_URL is not set")
		}

		http.Redirect(w, r, frontendURL, http.StatusTemporaryRedirect)

	})
	mux.HandleFunc("/auth/tiktok/callback", func(w http.ResponseWriter, r *http.Request) {
		// Get the state parameter (session token)
		state := r.URL.Query().Get("state")
		if state == "" {
			http.Error(w, "Session token not found", http.StatusBadRequest)
			return
		}

		// Validate session and get user ID
		userID, err := resolver.TikTokService.ValidateAndGetUserID(state)
		if err != nil {
			log.Printf("Validating session failed: %v", err)
			http.Error(w, "Invalid or expired session", http.StatusBadRequest)
			return
		}

		// Get the authorization code
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Authorization code not found", http.StatusBadRequest)
			return
		}

		// Handle the authorization
		_, err = resolver.TikTokService.ExchangeAndSaveToken(r.Context(), code, userID)
		if err != nil {
			log.Printf("Handling callback failed: %v", err)
			http.Error(w, "Failed to handle callback", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, os.Getenv("FRONTEND_URL"), http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/auth/instagram/callback", func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement TikTok OAuth callback
	})
}
