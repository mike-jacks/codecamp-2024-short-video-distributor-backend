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
	handleOAuthCallback(mux)

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

func handleOAuthCallback(mux *http.ServeMux) {
	mux.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		// Only allow GET requests
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get the authorization code
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Authorization code not found", http.StatusBadRequest)
			return
		}

		// Get error if present
		if err := r.URL.Query().Get("error"); err != "" {
			errDescription := r.URL.Query().Get("error_description")
			log.Printf("OAuth error: %s - %s", err, errDescription)
			http.Error(w, "Authorization failed: "+errDescription, http.StatusBadRequest)
			return
		}

		// Log the successful authorization
		log.Printf("Received OAuth callback with code: %s", code)

		// Set response headers
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")

		// Return success page
		successHTML := `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Authorization Successful</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        justify-content: center;
                        height: 100vh;
                        margin: 0;
                        background-color: #f0f2f5;
                    }
                    .container {
                        text-align: center;
                        padding: 20px;
                        background-color: white;
                        border-radius: 8px;
                        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                    }
                    h1 {
                        color: #1a73e8;
                        margin-bottom: 16px;
                    }
                    p {
                        color: #5f6368;
                        margin-bottom: 24px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Authorization Successful</h1>
                    <p>You can close this window and return to the application.</p>
                </div>
                <script>
                    // Close the window after 3 seconds
                    setTimeout(() => {
                        window.close();
                    }, 3000);
                </script>
            </body>
            </html>
        `
		w.Write([]byte(successHTML))
	})
}
