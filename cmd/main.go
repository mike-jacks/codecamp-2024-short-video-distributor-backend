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

	http.Handle("/", playground.Handler("GraphQL playground", "/query"))
	http.Handle("/query", srv)

	log.Printf("connect to http://localhost:%s/ for GraphQL playground", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
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
