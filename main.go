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

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	fmt.Println("Request received")

	if r.Method == http.MethodPost {
		var req struct {
			Name  string `json:"name"`
			Email string `json:"email"`
			ID    string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			fmt.Println("Error decoding JSON:", err)
			json.NewEncoder(w).Encode(Response{"fail", "Invalid JSON format"})
			return
		}

		if req.Name == "" || req.Email == "" {
			json.NewEncoder(w).Encode(Response{"fail", "Missing required fields: 'name' and 'email'"})
			return
		}

		fmt.Printf("Received Name: %s, Email: %s\n", req.Name, req.Email)

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
	err := db.ConnectMongoDB()
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}
	defer db.DisconnectMongoDB()

	http.HandleFunc("/", handler)
	http.HandleFunc("/create", db.CreateUserHandler)
	http.HandleFunc("/users", db.GetAllUsersHandler)
	http.HandleFunc("/users/update", db.UpdateUserHandler)
	http.HandleFunc("/users/delete", db.DeleteUserHandler)

	fmt.Println("Server is running on port 8080...")
	err = http.ListenAndServe(":8080", http.DefaultServeMux)
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
