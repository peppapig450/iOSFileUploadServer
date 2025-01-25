package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	// Define and parse command-line flags
	dir := flag.String("dir", "uploads", "Directory to save uploaded files")
	port := flag.String("port", "9090", "Port to run the server on")
	flag.Parse()

	// Ensure the upload directory exists
	if err := os.MkdirAll(*dir, os.ModePerm); err != nil {
		log.Fatalf("Error creating upload directory: %v", err)
	}

	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		uploadHandler(w, r, *dir)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "File server is running on port %s. Use /upload to upload files.", *port)
	})

	log.Printf("Starting server on port %s", *port)
	if err := http.ListenAndServe(":"+*port, nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

func uploadHandler(w http.ResponseWriter, r *http.Request, dir string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	r.ParseMultipartForm(25 << 20) // Limit upload size to ~25 mb

	// Handle base-64 encoded content
	if base64Content := r.FormValue("base64"); base64Content != "" {
		filename := r.FormValue("filename")
		if filename == "" {
			log.Println("Missing filename for base64 content")
			http.Error(w, "Missing filename for base64 content", http.StatusBadRequest)
			return
		}

		decodedData, err := base64.StdEncoding.DecodeString(base64Content)
		if err != nil {
			log.Printf("Error decoding base64 content: %v", err)
			http.Error(w, fmt.Sprintf("Error saving base64 file: %v", err), http.StatusInternalServerError)
			return
		}

		savePath := filepath.Join(dir, filename)
		// Open the file for writing. Create it if it doesn't exist, truncate it if it does
		file, err := os.OpenFile(savePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Printf("Failed to open file %q: %v", savePath, err)
			http.Error(w, fmt.Sprintf("Error saving base64 file: %v", err), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		n, err := file.Write(decodedData)
		if err != nil {
			log.Printf("Failed to write to file %q: %v", savePath, err)
			http.Error(w, fmt.Sprintf("Error saving base64 file: %v", err), http.StatusInternalServerError)
			return
		}
		if n != len(decodedData) {
			log.Printf("Partial write to file %q: wrote %d bytes, expected %d", savePath, n, len(decodedData))
			http.Error(w, fmt.Sprintf("Error saving base64 file: %v", err), http.StatusInternalServerError)
			return
		}

		log.Printf("Base64 file %s uploaded successfully", filename)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Base64 file %s uploaded successfully!", filename)
		return
	}

	// Handle file uploads
	file, handler, err := r.FormFile("file")
	if err != nil {
		log.Printf("Error retrieving the file: %v", err)
		http.Error(w, fmt.Sprintf("Error retrieving the file: %v", err), http.StatusInternalServerError)
		return
	}
	defer file.Close()
	savePath := filepath.Join(dir, handler.Filename)
	saveFile, err := os.Create(savePath)
	if err != nil {
		log.Printf("Error creating file: %v", err)
		http.Error(w, fmt.Sprintf("Error creating file: %v", err), http.StatusInternalServerError)
		return
	}
	defer saveFile.Close()

	if _, err := io.Copy(saveFile, file); err != nil {
		log.Printf("Error saving file: %v", err)
		http.Error(w, fmt.Sprintf("Error saving file: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("File %s uploaded successfully", handler.Filename)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "File %s uploaded successfully!", handler.Filename)

}
