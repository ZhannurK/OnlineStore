package db

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

type User struct {
	Name  string `json:"name" bson:"name" required:"true"`
	Email string `json:"email" bson:"email"`
	ID    string `json:"id" bson:"id"`
}

type UserUpdate struct {
	Name   string `json:"name" bson:"name"`
	Email  string `json:"email" bson:"email"`
	ID     string `json:"id" bson:"id"`
	Update struct {
		Name  string `json:"name" bson:"name"`
		Email string `json:"email" bson:"email"`
		ID    string `json:"id" bson:"id"`
	} `json:"update" bson:"update"`
}

func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fmt.Println("Request received create")

	var user User

	err2 := json.NewDecoder(r.Body).Decode(&user)

	if err2 != nil {
		fmt.Println("Error decoding JSON: ", err2.Error())
		http.Error(w, "Invalid JSON input", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := userCollection.InsertOne(ctx, bson.D{{"id", user.ID}, {"name", user.Name}, {"email", user.Email}})
	if err != nil {
		fmt.Println("Error inserting user:", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
}

func GetAllUsersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fmt.Println("Request received")

	id := r.URL.Query().Get("id")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if id != "" {
		var user User
		err := userCollection.FindOne(ctx, bson.M{"id": id}).Decode(&user)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(user)
		return
	}

	cursor, err := userCollection.Find(ctx, bson.M{})
	if err != nil {
		http.Error(w, "Failed to fetch users", http.StatusInternalServerError)
		fmt.Println("Error fetching users:", err)
		return
	}
	defer cursor.Close(ctx)

	var users []User
	if err := cursor.All(ctx, &users); err != nil {
		http.Error(w, "Failed to parse users", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(users)
}

func UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fmt.Println("Request received")

	var user UserUpdate
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		fmt.Println("Error input JSON:", err)
		http.Error(w, "Invalid JSON input", http.StatusBadRequest)
		return
	}

	fmt.Println(user)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.D{{"id", user.ID}}
	update := bson.D{{"$set", bson.D{{"name", user.Update.Name}, {"email", user.Update.Email}, {"id", user.Update.ID}}}}

	result, err := userCollection.UpdateOne(ctx, filter, update)
	if err != nil || result.MatchedCount == 0 {
		fmt.Println("Error input JSON:", err)
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "User updated successfully"})
}

func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fmt.Println("Request received")

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil || user.Name == "" || user.Email == "" {
		fmt.Println("Error deleting:", err)
		http.Error(w, "Invalid JSON input", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"name": user.Name, "email": user.Email}
	result, err := userCollection.DeleteOne(ctx, filter)
	if err != nil || result.DeletedCount == 0 {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "User deleted successfully"})
}
