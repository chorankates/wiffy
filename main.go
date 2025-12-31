package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/conor/wiffy/api"
	"github.com/conor/wiffy/database"
	"github.com/conor/wiffy/scanner"
)

func main() {
	// Validate nmap is installed
	if err := scanner.ValidateNmap(); err != nil {
		log.Fatal(err)
	}

	// Initialize database
	dbPath := os.Getenv("WIFFY_DB_PATH")
	if dbPath == "" {
		dbPath = "./wiffy.db"
	}

	db, err := database.NewDB(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	log.Println("Database initialized at:", dbPath)

	// Create API server
	server := api.NewServer(db)

	// Determine port
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Start server
	addr := fmt.Sprintf(":%s", port)
	log.Printf("🚀 Wiffy server starting on http://localhost%s\n", addr)
	log.Printf("📊 Open your browser to http://localhost%s\n", addr)

	if err := http.ListenAndServe(addr, server); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

