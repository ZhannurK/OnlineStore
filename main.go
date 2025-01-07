package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"programming/db"

	"go.mongodb.org/mongo-driver/bson"
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

func createHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		db.CreateUserHandler(w, r)
		return
	}
	if r.Method == http.MethodGet {
		createGetHandler(w, r)
		return
	}
}

func createGetHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func getSneakers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	collection := client.Database("OnlineStore").Collection("sneakers")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, bson.M{}) // Получаем все документы из коллекции
	if err != nil {
		http.Error(w, "Error fetching sneakers", http.StatusInternalServerError)
		log.Println("Error fetching sneakers:", err)
		return
	}
	defer cursor.Close(ctx)

	var sneakers []bson.M
	if err = cursor.All(ctx, &sneakers); err != nil {
		http.Error(w, "Error parsing sneakers", http.StatusInternalServerError)
		log.Println("Error parsing sneakers:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sneakers) // Возвращаем данные в формате JSON
}

func main() {
	err := db.ConnectMongoDB()
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}
	defer db.DisconnectMongoDB()

	// Отдача статических файлов
	fs := http.FileServer(http.Dir("./"))
	http.Handle("/", fs)

	// API маршруты
	http.HandleFunc("/sneakers", getSneakers)

	fmt.Println("Server is running on port 8080...")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

//http://localhost:8080/sneakers
//http://localhost:8080/users/create
