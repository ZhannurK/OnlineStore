package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"programming/db"
)

type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type Request struct {
	Message string `json:"message"`
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	fmt.Println("Request recieved")

	if r.Method == http.MethodPost {
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Message == "" {
			json.NewEncoder(w).Encode(Response{"fail", "Invalid JSON message"})
			return
		}
		fmt.Println("Received message:", req.Message)
		json.NewEncoder(w).Encode(Response{"success", "Data successfully received"})
		return
	}

	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(Response{"success", "GET request received"})
		return
	}

	json.NewEncoder(w).Encode(Response{"fail", "Method not allowed"})
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Server is running on port 8080...")
	http.ListenAndServe(":8080", nil)

	// Подключение к MongoDB
	err := db.ConnectMongoDB()
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}
	defer db.DisconnectMongoDB()

	// Роуты
	http.HandleFunc("/create", db.CreateUserHandler)

	fmt.Println("Server is running on port 8080...")
	http.ListenAndServe(":8080", nil)
}
