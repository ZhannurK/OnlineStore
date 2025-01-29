package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
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

func TestLoginEndpointWithSelenium(t *testing.T) {
	// Start Selenium WebDriver
	const chromeDriverPath = "./selenium-project/chromedriver-win64/chromedriver.exe"
	// "./chrome-win64/chromedriver.exe" // Path to ChromeDriver

	// Start ChromeDriver service
	service, err := selenium.NewChromeDriverService(chromeDriverPath, 4444)
	if err != nil {
		t.Fatalf("Failed to start ChromeDriver service: %v", err)
	}
	defer service.Stop()

	// Set up Selenium WebDriver with Chrome
	caps := selenium.Capabilities{"browserName": "chrome"}
	chromeCaps := chrome.Capabilities{
		Path: "",
		Args: []string{
			"--headless",
			"--disable-gpu",
			"--no-sandbox",
		},
	}
	caps.AddChrome(chromeCaps)

	wd, err := selenium.NewRemote(caps, "http://localhost:4444/wd/hub")
	if err != nil {
		t.Fatalf("Failed to connect to WebDriver: %v", err)
	}
	defer wd.Quit()

	// Navigate to the authorization page
	if err := wd.Get("/login"); err != nil {
		t.Fatalf("Failed to load authorization page: %v", err)
	}

	// Find and fill email and password fields
	emailField, err := wd.FindElement(selenium.ByID, "email")
	if err != nil {
		t.Fatalf("Failed to find email field: %v", err)
	}
	emailField.SendKeys("test@example.com")

	passwordField, err := wd.FindElement(selenium.ByID, "password")
	if err != nil {
		t.Fatalf("Failed to find password field: %v", err)
	}
	passwordField.SendKeys("password123")

	// Click the login button
	loginButton, err := wd.FindElement(selenium.ByID, "submit")
	if err != nil {
		t.Fatalf("Failed to find login button: %v", err)
	}
	loginButton.Click()

	// Wait for and verify the result
	time.Sleep(3 * time.Second) // Add a short delay for the page to respond
	alertText, err := wd.AlertText()
	if err != nil {
		t.Fatalf("Failed to retrieve alert text: %v", err)
	}

	expectedAlert := "Welcome Test User!"
	if alertText != expectedAlert {
		t.Errorf("Expected alert '%s', got '%s'", expectedAlert, alertText)
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
