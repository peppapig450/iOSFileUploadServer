package main

import (
	"crypto/subtle"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ServerConfig struct {
	uploadDir     string
	port          string
	maxUploadSize int64
	authToken     string
}

func main() {
	// Define and parse command-line flags
	dir := flag.String("dir", "uploads", "Directory to save uploaded files")
	port := flag.String("port", "9090", "Port to run the server on")
	maxUploadSize := flag.Int64("max-size", 50<<20, "Maximum upload file size bytes (default 50MB)")
	flag.Parse()

	authToken := os.Getenv("UPLOAD_SERVER_AUTHTOKEN")

	// Validate that an auth token is provided
	if authToken == "" {
		log.Fatalf("ERROR: An authentication token must be provided. Make sure environment variable is set.")
	}

	// Configure logging with timestamp and additional details
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// Ensure the upload directory exists
	if err := os.MkdirAll(*dir, os.ModePerm); err != nil {
		log.Fatalf("Error creating upload directory: %v", err)
	}

	// Create server configuration
	config := ServerConfig{
		uploadDir:     *dir,
		port:          *port,
		maxUploadSize: *maxUploadSize,
		authToken:     authToken,
	}
	// Create a custom ServeMux for routing
	mux := http.NewServeMux()

	// Add routes with authentication
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		// Authenticate the request
		if !config.authenticateRequest(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			log.Printf("DENIED: Unauthorized upload attempt\n"+
				"  Method: %s\n"+
				"  Path: %s\n"+
				"  User-Agent: %s",
				r.Method,
				r.URL.Path,
				r.UserAgent(),
			)
			return
		}

		// Process upload if authenticated
		uploadHandler(w, r, config.uploadDir, config.maxUploadSize)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "File server is running on port %s. Use /upload to upload files.", config.port)
	})

	// Configure server with timeouts
	server := &http.Server{
		Addr:         ":" + config.port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting server on  %s", *port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error starting server: %v", err)
	}
}

// authenticateRequest checks if the provided token is valid
func (c *ServerConfig) authenticateRequest(r *http.Request) bool {
	// Check token in multiple places for flexibility

	// 1. Authorization header
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if c.compareToken(token) {
			return true
		}
	}

	// 2. Query parameter
	if c.compareToken(r.URL.Query().Get("token")) {
		return true
	}

	// 3. Form/Multipart value
	if err := r.ParseMultipartForm(10 << 20); err == nil {
		if c.compareToken(r.FormValue("token")) {
			return true
		}
	}

	return false
}

// compareToken uses constant-time comparison to prevent timing attacks
func (c *ServerConfig) compareToken(providedToken string) bool {
	return subtle.ConstantTimeCompare(
		[]byte(providedToken),
		[]byte(c.authToken),
	) == 1
}

func uploadHandler(w http.ResponseWriter, r *http.Request, dir string, maxUploadSize int64) {
	// Validate request method
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Limit total request body size
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	// Parse multipart form
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	var content []byte
	var filename string
	var err error

	// Check for base64 content
	if base64Content := r.FormValue("base64"); base64Content != "" {
		filename = r.FormValue("filename")
		if filename == "" {
			http.Error(w, "Missing filename for base64 content", http.StatusBadRequest)
			return
		}

		// Decode base64 content
		content, err = base64.StdEncoding.DecodeString(base64Content)
		if err != nil {
			log.Printf("Error decoding base64 content: %v", err)
			http.Error(w, fmt.Sprintf("Error saving base64 file: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		// Handle fiel uploads
		file, handler, fileErr := r.FormFile("file")
		if fileErr != nil {
			log.Printf("Error retrieving the file: %v", fileErr)
			http.Error(w, "Error retrieving file", http.StatusBadRequest)
			return
		}
		defer file.Close()

		filename = handler.Filename
		content, err = io.ReadAll(file)
		if err != nil {
			log.Printf("Error reading file content: %v", err)
			http.Error(w, "Error reading file", http.StatusInternalServerError)
			return
		}
	}

	// Validate file size
	if int64(len(content)) > maxUploadSize {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	// Sanitize filename
	filename = sanitizeFilename(filename)

	// Save the file
	if err := saveFile(dir, filename, content); err != nil {
		log.Printf("Failed to save file %q: %v", filename, err)
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}

	log.Printf("File %s uploaded successfully", filename)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "File %s uploaded successfully!", filename)
}

// saveFile saves the given content to a file in the specified directory
func saveFile(dir, filename string, content []byte) error {
	savePath := filepath.Join(dir, filename)
	return os.WriteFile(savePath, content, 0644)
}

// sanitizeFilename removes potentially dangerous characters and prevents directory traversal
func sanitizeFilename(filename string) string {
	// Replace or remove potentially dangerous characters
	filename = filepath.Base(filename)
	filename = strings.ReplaceAll(filename, "/", "")
	filename = strings.ReplaceAll(filename, "\\", "")

	// If filename is empty after sanitization, generate a unique name
	if filename == "" {
		filename = fmt.Sprintf("upload_%s", time.Now().Format("20060102_150405"))
	}

	return filename
}
