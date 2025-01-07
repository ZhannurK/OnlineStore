package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/time/rate"
)

var (
	db      *mongo.Client
	logger  = logrus.New()
	limiter = rate.NewLimiter(1, 3)
)

type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

func init() {
	// Set up structured logging
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)

	// Connect to MongoDB
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		logger.WithError(err).Fatal("Failed to connect to MongoDB")
	}
	if err = db.Ping(ctx, nil); err != nil {
		logger.WithError(err).Fatal("Failed to ping MongoDB")
	}
	logger.Info("Connected to MongoDB")
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/users", getUsers).Methods(http.MethodGet)
	r.HandleFunc("/login", login).Methods(http.MethodPost)
	r.HandleFunc("/signup", signup).Methods(http.MethodPost)
	r.HandleFunc("/login", func(writer http.ResponseWriter, request *http.Request) {
		http.ServeFile(writer, request, "./store/authorization.html")
	}).Methods(http.MethodGet)
	r.HandleFunc("/signup", func(writer http.ResponseWriter, request *http.Request) {
		http.ServeFile(writer, request, "./store/signup.html")
	}).Methods(http.MethodGet)
	r.Use(rateLimitMiddleware)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}
	// Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info("Starting server on :8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Server failed")
		}
	}()

	<-quit
	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.WithError(err).Fatal("Server forced to shutdown")
	}
	logger.Info("Server exited gracefully")
}

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			logger.Warn("Rate limit exceeded")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("Rate limit exceeded. Try again later."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	logger.WithField("action", "get_users").Info("Fetching users from MongoDB")
	collection := db.Database("db").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, map[string]interface{}{})
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Database query error", err)
		return
	}
	defer cursor.Close(ctx)

	var users []User
	for cursor.Next(ctx) {
		var user User
		if err := cursor.Decode(&user); err != nil {
			handleError(w, http.StatusInternalServerError, "Error reading user data", err)
			return
		}
		users = append(users, user)
	}

	if len(users) == 0 {
		handleError(w, http.StatusNotFound, "No users found", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func login(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	fmt.Println("Received request for login", r.Body)

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		handleError(w, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	fmt.Println("Decoded creds: \n ", creds)

	collection := db.Database("db").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user User
	err := collection.FindOne(ctx, map[string]interface{}{"email": creds.Email}).Decode(&user)
	if err != nil {
		handleError(w, http.StatusUnauthorized, "Invalid email, or password", err)
		return
	}

	logger.WithFields(logrus.Fields{
		"userID": user.ID,
		"email":  user.Email,
	}).Info("User logged in successfully")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func signup(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		handleError(w, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	collection := db.Database("db").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := collection.InsertOne(ctx, User{
		Email:    creds.Email,
		Name:     creds.Name,
		Password: creds.Password,
	})
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Error creating user", err)
		return
	}

	logger.WithFields(logrus.Fields{
		"email": creds.Email,
		"name":  creds.Name,
	}).Info("User signed up successfully")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "User signed up successfully"})
}

func handleError(w http.ResponseWriter, statusCode int, message string, err error) {
	if err != nil {
		logger.WithError(err).Error(message)
	} else {
		logger.Error(message)
	}

	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	json.NewEncoder(w).Encode(response)
}
