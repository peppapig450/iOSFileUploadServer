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
	debug         bool
}

// debugLogger wraps our logging functionality
type debugLogger struct {
	enabled bool
}

func (d *debugLogger) Printf(format string, v ...interface{}) {
	if d.enabled {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func main() {
	// Define and parse command-line flags
	dir := flag.String("dir", "uploads", "Directory to save uploaded files")
	port := flag.String("port", "9090", "Port to run the server on")
	maxUploadSize := flag.Int64("max-size", 50<<20, "Maximum upload file size bytes (default 50MB)")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	authToken := os.Getenv("UPLOAD_SERVER_AUTHTOKEN")

	// Validate that an auth token is provided
	if authToken == "" {
		log.Fatalf("ERROR: An authentication token must be provided. Make sure environment variable is set.")
	}

	// Configure logging with timestamp and additional details
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// Initialize debug logger
	debugLog := &debugLogger{enabled: *debug}
	if *debug {
		log.Printf("Debug logging enabled")
	}
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
		debug:         *debug,
	}
	// Create a custom ServeMux for routing
	mux := http.NewServeMux()

	// Add routes with authentication
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if config.debug {
			dumpRequestDetails(r, debugLog)
		}
		// Authenticate the request
		if !config.authenticateRequest(r, debugLog) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			log.Printf("DENIED: Unauthorized upload attempt\n"+
				"  Method: %s\n"+
				"  Path: %s\n"+
				"  Headers: %+v\n"+
				"  User-Agent: %s",
				r.Method,
				r.URL.Path,
				r.Header,
				r.UserAgent(),
			)
			return
		}

		// Process upload if authenticated
		uploadHandler(w, r, config.uploadDir, config.maxUploadSize, debugLog)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if config.debug {
			dumpRequestDetails(r, debugLog)
		}
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

	debugLog.Printf("Server configuration: %+v", config)
	log.Printf("Starting server on  %s", *port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error starting server: %v", err)
	}
}

// dumpRequestDetails logs detailed information about the incoming request
func dumpRequestDetails(r *http.Request, debugLog *debugLogger) {
	debugLog.Printf("Incoming connection details:")
	debugLog.Printf("  Remote Address: %s", r.RemoteAddr)
	debugLog.Printf("  Method: %s", r.Method)
	debugLog.Printf("  URL: %s", r.URL.String())
	debugLog.Printf("  Protocol: %s", r.Proto)
	debugLog.Printf("  Host: %s", r.Host)
	debugLog.Printf("  Headers:")
	for name, headers := range r.Header {
		for _, h := range headers {
			debugLog.Printf("    %s: %s", name, h)
		}
	}
	debugLog.Printf("  ContentLength: %d", r.ContentLength)
	debugLog.Printf("  TransferEncoding: %v", r.TransferEncoding)
	debugLog.Printf("  TLS Connection: %v", r.TLS != nil)
	if r.TLS != nil {
		debugLog.Printf("    TLS Version: %x", r.TLS.Version)
		debugLog.Printf("    TLS CipherSuite: %x", r.TLS.CipherSuite)
		debugLog.Printf("    TLS Server Name: %s", r.TLS.ServerName)
	}
}

// authenticateRequest checks if the provided token is valid
func (c *ServerConfig) authenticateRequest(r *http.Request, debugLog *debugLogger) bool {
	debugLog.Printf("Attempting authentication for request from %s", r.RemoteAddr)
	// Check token in multiple places for flexibility

	// 1. Authorization header
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		debugLog.Printf("Found Bearer token in Authorization header")
		if c.compareToken(token) {
			debugLog.Printf("Bearer token authentication successful")
			return true
		}
		debugLog.Printf("Bearer token authentication failed")
	}

	// 2. Query parameter
	if token := r.URL.Query().Get("token"); token != "" {
		debugLog.Printf("Found token in query parameters")
		if c.compareToken(token) {
			debugLog.Printf("Query parameter token authentication successful")
			return true
		}
		debugLog.Printf("Query parameter token authentication failed")
	}

	// 3. Form/Multipart value
	if err := r.ParseMultipartForm(10 << 20); err == nil {
		if token := r.FormValue("token"); token != "" {
			debugLog.Printf("Found token in form data")
			if c.compareToken(token) {
				debugLog.Printf("Form token authentication successful")
				return true
			}
			debugLog.Printf("Form token authentication failed")
		}
	}

	debugLog.Printf("All authentication methods failed")
	return false
}

// compareToken uses constant-time comparison to prevent timing attacks
func (c *ServerConfig) compareToken(providedToken string) bool {
	return subtle.ConstantTimeCompare(
		[]byte(providedToken),
		[]byte(c.authToken),
	) == 1
}

func uploadHandler(w http.ResponseWriter, r *http.Request, dir string, maxUploadSize int64, debugLog *debugLogger) {
	// Validate request method
	if r.Method != http.MethodPost {
		debugLog.Printf("Invalid request method: %s", r.Method)
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	debugLog.Printf("Processing upload request from %s", r.RemoteAddr)

	// Limit total request body size
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	// Parse multipart form
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		debugLog.Printf("Failed to parse multipart form: %v", err)
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	// Track upload results
	type uploadResult struct {
		filename string
		size     int
		err      error
	}
	var results []uploadResult

	// Handle base64 content if present
	if base64Content := r.FormValue("base64"); base64Content != "" {
		debugLog.Printf("Processing base64 encoded content")
		filename := r.FormValue("filename")
		if filename == "" {
			debugLog.Printf("Missing filename for base64 content")
			http.Error(w, "Missing filename for base64 content", http.StatusBadRequest)
			return
		}

		// Decode base64 content
		content, err := base64.StdEncoding.DecodeString(base64Content)
		if err != nil {
			debugLog.Printf("Error decoding base64 content: %v", err)
			http.Error(w, fmt.Sprintf("Error decoding base64 file: %v", err), http.StatusBadRequest)
			return
		}

		// Save base64 file
		sanitizedFilename := sanitizeFilename(filename)
		err = saveFile(dir, sanitizedFilename, content)
		results = append(results, uploadResult{
			filename: sanitizedFilename,
			size:     len(content),
			err:      err,
		})
	}

	// Handle multiple file uploads
	if files := r.MultipartForm.File["file"]; len(files) > 0 {
		debugLog.Printf("Processing %d files from multipart form", len(files))

		for _, fileHeader := range files {
			debugLog.Printf("Processing file: %s (size: %d)", fileHeader.Filename, fileHeader.Size)

			// Validate individual file size
			if fileHeader.Size > maxUploadSize {
				debugLog.Printf("File %s exceeds size limit (%d > %d)", fileHeader.Filename, fileHeader.Size, maxUploadSize)
				results = append(results, uploadResult{
					filename: fileHeader.Filename,
					size:     int(fileHeader.Size),
					err:      fmt.Errorf("file exceeds maximum size of %d bytes", maxUploadSize),
				})
				continue
			}

			// Open the file
			file, err := fileHeader.Open()
			if err != nil {
				debugLog.Printf("Error opening file %s: %v", fileHeader.Filename, err)
				results = append(results, uploadResult{
					filename: fileHeader.Filename,
					size:     int(fileHeader.Size),
					err:      err,
				})
				continue
			}
			defer file.Close()

			// Read file content
			content, err := io.ReadAll(file)
			if err != nil {
				debugLog.Printf("Error reading file %s: %v", fileHeader.Filename, err)
				results = append(results, uploadResult{
					filename: fileHeader.Filename,
					size:     int(fileHeader.Size),
					err:      err,
				})
				continue
			}

			// Sanitize filename and save
			sanitizedFilename := sanitizeFilename(fileHeader.Filename)
			err = saveFile(dir, sanitizedFilename, content)
			results = append(results, uploadResult{
				filename: sanitizedFilename,
				size:     len(content),
				err:      err,
			})
		}
	}

	// Return results
	if len(results) == 0 {
		debugLog.Printf("No files were processed")
		http.Error(w, "No files were uploaded", http.StatusBadRequest)
		return
	}

	// Generate response
	w.Header().Set("Content-Type", "text/plain")

	// Check for any errors
	hasErrors := false
	var response strings.Builder
	for _, result := range results {
		if result.err != nil {
			hasErrors = true
			response.WriteString(fmt.Sprintf("Failed to upload %s: %v\n", result.filename, result.err))
		} else {
			response.WriteString(fmt.Sprintf("Successfully uploaded %s (%d bytes)\n", result.filename, result.size))
			debugLog.Printf("Successfully saved file %q (%d bytes) to %s", result.filename, result.size, dir)
		}
	}

	if hasErrors {
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	fmt.Fprintf(w, response.String())
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
