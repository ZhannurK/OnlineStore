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
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Email == "" {
			json.NewEncoder(w).Encode(Response{"fail", "Invalid JSON message. 'name' and 'email' are required."})
			return
		}

		fmt.Printf("Received Name: %s, Email: %s\n", req.Name, req.Email)

		// Success response
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
	log.Fatal(http.ListenAndServe(":8080", nil))
}
