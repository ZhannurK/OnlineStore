package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/lpernett/godotenv"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/time/rate"

	gomail "gopkg.in/mail.v2"
)

var (
	db      *mongo.Client
	logger  = logrus.New()
	limiter = rate.NewLimiter(50, 50)
)

type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

func init() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Couldn`t reach users home directory: %v", err)
	}

	logFilePath := filepath.Join(homeDir, "Downloads", "server-logs.txt")

	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Couldn`t open file for logers: %v", err)
	}

	logger.SetOutput(file)
	logger.SetFormatter(&logrus.TextFormatter{})

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

var jwtKey []byte

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	jwtKey = []byte(os.Getenv("JWTSECRET"))

	r := mux.NewRouter()

	r.HandleFunc("/sneakers", getSneakers).Methods(http.MethodGet)
	r.HandleFunc("/shoes", func(writer http.ResponseWriter, request *http.Request) {
		http.ServeFile(writer, request, "./store/shoes.html")
	}).Methods(http.MethodGet)

	r.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		http.ServeFile(writer, request, "./store/store.html")
	}).Methods(http.MethodGet)

	r.HandleFunc("/contact", func(writer http.ResponseWriter, request *http.Request) {
		http.ServeFile(writer, request, "./store/contact.html")
	}).Methods(http.MethodGet)

	r.PathPrefix("/public").Handler(http.FileServer(http.Dir("./store")))

	r.HandleFunc("/users", getUsers).Methods(http.MethodGet)
	r.HandleFunc("/login", login).Methods(http.MethodPost)
	r.HandleFunc("/signup", signup).Methods(http.MethodPost)
	r.HandleFunc("/login", func(writer http.ResponseWriter, request *http.Request) {
		http.ServeFile(writer, request, "./store/authorization.html")
	}).Methods(http.MethodGet)
	r.HandleFunc("/signup", func(writer http.ResponseWriter, request *http.Request) {
		http.ServeFile(writer, request, "./store/signup.html")
	}).Methods(http.MethodGet)
	profileHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.ServeFile(writer, request, "./store/profile.html")
	})
	r.Handle("/profile", AuthMiddleware(profileHandler)).Methods(http.MethodGet)
	r.Handle("/profile", AuthMiddleware(http.HandlerFunc(changePasswordHandler))).Methods(http.MethodPost)

	r.HandleFunc("/sendEmail", sendEmailHandler).Methods(http.MethodPost)

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

// key is an unexported type for keys defined in this package.
// This prevents collisions with keys defined in other packages.
type key int

// userKey is the key for user.User values in Contexts. It is
// unexported; clients use user.NewContext and user.FromContext
// instead of using this key directly.
var userKey key = 333

// NewContext returns a new Context that carries value u.
func NewContext(ctx context.Context, u *string) context.Context {
	return context.WithValue(ctx, userKey, u)
}

// FromContext returns the User value stored in ctx, if any.
func FromContext(ctx context.Context) (*string, bool) {
	u, ok := ctx.Value(userKey).(*string)
	return u, ok
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		OldPassword     string `json:"oldPassword"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirmPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		handleError(w, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	if creds.ConfirmPassword != creds.Password {
		handleError(w, http.StatusBadRequest, fmt.Sprintf("passwords are not the same %s %s", creds.ConfirmPassword, creds.Password), errors.New("confirmation failed"))
		return
	}

	collection := db.Database("db").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	email, ok := FromContext(r.Context())
	if !ok {
		handleError(w, http.StatusBadRequest, "no email in context "+*email, errors.New("no email in context"))
		return
	}

	var user User

	err1 := collection.FindOne(ctx, bson.M{"email": *email}).Decode(&user)
	if err1 != nil {
		handleError(w, http.StatusBadRequest, "no user with this email "+*email, err1)
		return
	}

	if creds.OldPassword != user.Password {
		handleError(w, http.StatusBadRequest, "old password is not correct", err1)
		return
	}

	_, err1 = collection.DeleteOne(ctx, bson.M{"email": *email})
	if err1 != nil {
		handleError(w, http.StatusInternalServerError, "can not update user", err1)
		return
	}

	_, err1 = collection.InsertOne(ctx, User{
		Email:    user.Email,
		Name:     user.Name,
		Password: creds.Password,
	})
	if err1 != nil {
		handleError(w, http.StatusInternalServerError, "Error updating user", err1)
		return
	}

	//sent(email, "password changed message")
	logger.WithFields(logrus.Fields{
		"email": user.Email,
		"name":  user.Name,
	}).Info("User changed password successfully")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "User changed password successfully"})
}

// Rate limit middleware
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

	sortBy := r.URL.Query().Get("sort")
	emailFilter := r.URL.Query().Get("email")
	pageStr := r.URL.Query().Get("page")
	pageSizeStr := r.URL.Query().Get("pageSize")

	logger.WithFields(logrus.Fields{
		"emailFilter": emailFilter,
		"sortBy":      sortBy,
		"page":        pageStr,
		"pageSize":    pageSizeStr,
	}).Info("Received request to get users with filters")

	pageInt := 1
	pageSizeInt := 9

	if pageStr != "" {
		if val, err := fmt.Sscanf(pageStr, "%d", &pageInt); err == nil && val > 0 {
		}
	}

	if pageSizeStr != "" {
		if val, err := fmt.Sscanf(pageSizeStr, "%d", &pageSizeInt); err == nil && val > 0 {
		}
	}

	filter := bson.M{}
	if emailFilter != "" {
		filter["email"] = bson.M{"$regex": emailFilter, "$options": "i"}
	}

	var sortFields bson.D
	switch sortBy {
	case "nameAsc":
		sortFields = bson.D{{Key: "name", Value: 1}}
	case "nameDesc":
		sortFields = bson.D{{Key: "name", Value: -1}}
	case "createdAt":
		sortFields = bson.D{{Key: "created_at", Value: 1}}
	case "id":
		sortFields = bson.D{{Key: "_id", Value: 1}}
	default:
		sortFields = bson.D{{Key: "created_at", Value: -1}}
	}

	skip := int64((pageInt - 1) * pageSizeInt)
	limit := int64(pageSizeInt)

	findOptions := options.Find().
		SetSort(sortFields).
		SetSkip(skip).
		SetLimit(limit)

	collection := db.Database("db").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, filter, findOptions)
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

type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func login(w http.ResponseWriter, r *http.Request) {

	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	fmt.Println("Received request for login")

	// Decode JSON body into creds
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		handleError(w, http.StatusBadRequest, "Invalid request payload", err)
		return
	}
	defer r.Body.Close()

	fmt.Println("Decoded creds:", creds)

	collection := db.Database("db").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user User
	err := collection.FindOne(ctx, map[string]interface{}{"email": creds.Email}).Decode(&user)
	if err != nil {
		// If the user is not found or any other DB error
		handleError(w, http.StatusUnauthorized, "Invalid email or password", err)
		return
	}

	// TODO: In production, check hashed password using bcrypt or other secure method
	if user.Password != creds.Password {
		handleError(w, http.StatusUnauthorized, "Invalid email or password", nil)
		return
	}

	// Build the JWT claims
	expiresAt := time.Now().Add(24 * time.Hour) // token expiration, e.g. 24h from now
	claims := &Claims{
		Email: user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "Pullo",
			Subject:   user.Email,
		},
	}

	// Create the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with your secret key
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Could not generate token", err)
		return
	}

	// Log successful login
	logger.WithFields(logrus.Fields{
		"userID": user.ID,
		"email":  user.Email,
	}).Info("User logged in successfully")

	// Return token and/or user information as JSON
	//w.Header().Set("Content-Type", "application/json")
	//json.NewEncoder(w).Encode(map[string]interface{}{
	//	"tokenString": tokenString,
	//	"token":       token,
	//	"expires_at":  expiresAt.Format(time.RFC3339),
	//})
	http.SetCookie(w, &http.Cookie{
		Name:    "JWT",
		Value:   "Bearer " + tokenString,
		Expires: expiresAt,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "name": user.Name, "email": user.Email})
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Extract the "Authorization" header: "Bearer <token>"
		authCookie, err := r.Cookie("JWT")
		if err != nil || authCookie.Value == "" {
			handleError(w, http.StatusUnauthorized, "Missing Authorization cookie", nil)
			return
		}

		bearerToken := authCookie.Value
		parts := strings.Split(bearerToken, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			handleError(w, http.StatusUnauthorized, "Invalid Authorization cookie format", nil)
			return
		}
		tokenString := parts[1]

		// 2. Parse & validate the JWT token
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			// Ensure the signing method is HMAC
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			handleError(w, http.StatusUnauthorized, "Invalid or expired token", err)
			fmt.Println("Error:", err)
			str, err := json.Marshal(token)
			if err != nil {
				fmt.Println("Error:", err)
			}
			fmt.Println("Token:", string(str))
			return
		}

		ctx := NewContext(r.Context(), &claims.Email)
		// 4. Proceed to the next handler with the updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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

// Обработка ошибок
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

func getSneakers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	collection := db.Database("OnlineStore").Collection("sneakers")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, bson.M{})
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
	json.NewEncoder(w).Encode(sneakers)
}

type Sneaker struct {
	Model string  `json:"model"`
	Brand string  `json:"brand"`
	Color string  `json:"color"`
	Price float64 `json:"price"`
}

// sendEmailHandler handles POST requests to /sendEmail
// Expects JSON with { "to": "...", "subject": "...", "body": "...", "attachment": "..." }
func sendEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		To         string `json:"to"`
		Subject    string `json:"subject"`
		Body       string `json:"body"`
		Attachment string `json:"attachment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handleError(w, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	if err := sendMail(req.To, req.Subject, req.Body, req.Attachment); err != nil {
		handleError(w, http.StatusInternalServerError, "Failed to send email", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Email sent successfully",
	})
}

// sendMail uses Gomail to send an email with optional attachment
func sendMail(to, subject, body, attachmentPath string) error {
	mailHost := os.Getenv("MAIL_HOST")
	if mailHost == "" {
		mailHost = "sandbox.smtp.mailtrap.io"
	}
	mailPort := 587
	mailUser := os.Getenv("MAIL_USERNAME")
	if mailUser == "" {
		mailUser = "default_username"
	}
	mailPass := os.Getenv("MAIL_PASSWORD")
	if mailPass == "" {
		mailPass = "default_password"
	}

	msg := gomail.NewMessage()
	msg.SetHeader("From", mailUser)
	msg.SetHeader("To", to)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/plain", body)

	if attachmentPath != "" {
		msg.Attach(attachmentPath)
	}

	dialer := gomail.NewDialer(mailHost, mailPort, mailUser, mailPass)
	if err := dialer.DialAndSend(msg); err != nil {
		logger.WithError(err).Error("Failed to send email via Gomail")
		return err
	}

	logger.WithFields(logrus.Fields{
		"to":      to,
		"subject": subject,
	}).Info("Email sent successfully")
	return nil
}
