package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestMain(m *testing.M) {

	jwtKey = []byte(os.Getenv("JWTSECRET"))
	if len(jwtKey) == 0 {
		jwtKey = []byte("test_secret_key") // Fallback for tests
	}

	os.Exit(m.Run())
}

func TestHandleError(t *testing.T) {
	recorder := httptest.NewRecorder()
	statusCode := http.StatusBadRequest
	message := "Test error message"

	handleError(recorder, statusCode, message, nil)

	if recorder.Code != statusCode {
		t.Errorf("Expected status code %d, got %d", statusCode, recorder.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if response["error"] != message {
		t.Errorf("Expected error message '%s', got '%s'", message, response["error"])
	}
}

func TestGetUsers(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	recorder := httptest.NewRecorder()

	mockDB := setupMockDatabase()
	defer mockDB.Disconnect(context.Background())
	db = mockDB

	getUsers(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, recorder.Code)
	}

	var users []User
	if err := json.NewDecoder(recorder.Body).Decode(&users); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if len(users) == 0 {
		t.Errorf("Expected non-empty user list, got %d users", len(users))
	}
}

func TestLoginEndpoint(t *testing.T) {
	// Start the server with the login handler
	server := httptest.NewServer(http.HandlerFunc(login))
	defer server.Close()

	// Setup test database with matching credentials
	mockDB := setupMockDatabase()
	defer mockDB.Disconnect(context.Background())
	db = mockDB

	// Test payload
	payload := `{"email":"test@example.com","password":"password123"}`

	// Send POST request
	resp, err := http.Post(server.URL+"/login", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// Parse the response body
	var response map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if response["status"] != "success" {
		t.Errorf("Expected status 'success', got '%s'", response["status"])
	}
}

func setupMockDatabase() *mongo.Client {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatalf("Failed to connect to test MongoDB: %v", err)
	}

	collection := client.Database("db").Collection("users")

	// Clean up any existing test data
	_, err = collection.DeleteMany(ctx, bson.M{"email": "test@example.com"})
	if err != nil {
		log.Fatalf("Failed to clean up test data: %v", err)
	}

	// Insert mock user with matching credentials
	_, err = collection.InsertOne(ctx, User{
		Email:    "test@example.com",
		Password: "password123", // Ensure this matches the test payload
		Name:     "Test User",
		Verified: true,
	})
	if err != nil {
		log.Fatalf("Failed to insert mock data: %v", err)
	}

	return client
}
