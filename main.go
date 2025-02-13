package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/lpernett/godotenv"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/time/rate"
	gomail "gopkg.in/mail.v2"
)

var (
	db      *mongo.Client
	logger  = logrus.New()
	limiter = rate.NewLimiter(50, 50)
	jwtKey  []byte
)

type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

type CartItem struct {
	SneakerID primitive.ObjectID `json:"sneakerId" bson:"sneakerId"`
	Quantity  int                `json:"quantity" bson:"quantity"`
}

type User struct {
	ID                string     `json:"id" bson:"_id,omitempty"`
	Email             string     `json:"email" bson:"email"`
	Name              string     `json:"name" bson:"name"`
	Password          string     `json:"password" bson:"password"`
	Verified          bool       `json:"verified" bson:"verified"`
	ConfirmationToken string     `json:"confirmationToken" bson:"confirmationToken"`
	Role              string     `json:"role" bson:"role"`
	Cart              []CartItem `json:"cart" bson:"cart"`
}

type TransactionStatus string

const (
	StatusPending  TransactionStatus = "Pending Payment"
	StatusPaid     TransactionStatus = "Paid"
	StatusDeclined TransactionStatus = "Declined"
)

type Transaction struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	TransactionID string             `bson:"transactionId" json:"transactionId"`
	UserID        string             `bson:"userId" json:"userId"`
	CartItems     []CartItem         `bson:"cartItems" json:"cartItems"`
	TotalAmount   float64            `bson:"totalAmount" json:"totalAmount"`
	Status        TransactionStatus  `bson:"status" json:"status"`
	CreatedAt     time.Time          `bson:"createdAt" json:"createdAt"`
	UpdatedAt     time.Time          `bson:"updatedAt" json:"updatedAt"`
}

type Sneaker struct {
	ID    primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Brand string             `json:"brand" bson:"brand"`
	Model string             `json:"model" bson:"model"`
	Price int                `json:"price" bson:"price"`
	Color string             `json:"color" bson:"color"`
}

type key int

var userKey key = 333

func NewContext(ctx context.Context, u *string) context.Context {
	return context.WithValue(ctx, userKey, u)
}

func FromContext(ctx context.Context) (*string, bool) {
	u, ok := ctx.Value(userKey).(*string)
	return u, ok
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			handleError(w, http.StatusUnauthorized, "Invalid or expired token", err)
			return
		}

		ctx := NewContext(r.Context(), &claims.Email)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	logger.SetOutput(os.Stdout)
	logger.SetFormatter(&logrus.TextFormatter{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err = mongo.Connect(ctx, options.Client().ApplyURI(os.Getenv("MONGO_CONNECT")))
	if err != nil {
		logger.WithError(err).Fatal("Failed to connect to MongoDB")
	}
	if err = db.Ping(ctx, nil); err != nil {
		logger.WithError(err).Fatal("Failed to ping MongoDB")
	}
	logger.Info("Connected to MongoDB")
}

func main() {

	jwtKey = []byte(os.Getenv("JWTSECRET"))

	r := mux.NewRouter()

	r.Use(rateLimitMiddleware)

	r.HandleFunc("/shoes", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./store/shoes.html")
	}).Methods(http.MethodGet)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./store/store.html")
	}).Methods(http.MethodGet)
	r.HandleFunc("/contact", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./store/contact.html")
	}).Methods(http.MethodGet)
	r.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./store/signup.html")
	}).Methods(http.MethodGet)
	profileHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./store/profile.html")
	})
	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./store/authorization.html")
	}).Methods(http.MethodGet)
	r.Handle("/admin", AuthMiddleware(roleMiddleware("admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./store/adminPanel.html")
	})))).Methods(http.MethodGet)
	r.HandleFunc("/cart", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./store/cart.html")
	}).Methods(http.MethodGet)
	r.HandleFunc("/payment", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./store/payment.html")
	}).Methods(http.MethodGet)

	r.PathPrefix("/public").Handler(http.FileServer(http.Dir("./store")))
	r.HandleFunc("/sneakers", getSneakers).Methods(http.MethodGet)
	r.HandleFunc("/users", getUsers).Methods(http.MethodGet)
	r.HandleFunc("/login", login).Methods(http.MethodPost)
	r.HandleFunc("/signup", signup).Methods(http.MethodPost)
	r.Handle("/profile", AuthMiddleware(profileHandler)).Methods(http.MethodGet)
	r.Handle("/profile", AuthMiddleware(http.HandlerFunc(changePasswordHandler))).Methods(http.MethodPost)
	r.Handle("/api/user-profile", AuthMiddleware(http.HandlerFunc(getUserProfileHandler))).Methods(http.MethodGet)
	r.HandleFunc("/sendEmail", sendEmailHandler).Methods(http.MethodPost)
	r.HandleFunc("/confirm", confirmEmailHandler).Methods(http.MethodGet)
	r.Handle("/admin", AuthMiddleware(roleMiddleware("admin", http.HandlerFunc(createSneaker)))).Methods(http.MethodPost)
	r.Handle("/admin/{id}", AuthMiddleware(roleMiddleware("admin", http.HandlerFunc(updateSneaker)))).Methods(http.MethodPut)
	r.Handle("/admin/{id}", AuthMiddleware(roleMiddleware("admin", http.HandlerFunc(deleteSneaker)))).Methods(http.MethodDelete)
	r.Handle("/api/cart", AuthMiddleware(http.HandlerFunc(addToCartHandler))).Methods(http.MethodPost)
	r.Handle("/api/cart", AuthMiddleware(http.HandlerFunc(getCartHandler))).Methods(http.MethodGet)
	r.Handle("/api/cart/{sneakerId}", AuthMiddleware(http.HandlerFunc(removeFromCartHandler))).Methods(http.MethodDelete)
	r.Handle("/api/checkout", AuthMiddleware(http.HandlerFunc(checkoutHandler))).Methods(http.MethodPost)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info("Starting server on :8080")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

func handleError(w http.ResponseWriter, statusCode int, message string, err error) {
	if err != nil {
		logger.WithError(err).Error(message)
	} else {
		logger.Error(message)
	}
	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		return
	}
}

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			logger.Warn("Rate limit exceeded")
			w.WriteHeader(http.StatusTooManyRequests)
			_, err := w.Write([]byte("Rate limit exceeded. Try again later."))
			if err != nil {
				return
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

func roleMiddleware(targetRole string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, ok := FromContext(r.Context())
		if !ok {
			handleError(w, http.StatusBadRequest, "No email in context", errors.New("missing email in context"))
			return
		}
		collection := db.Database("db").Collection("users")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var user User
		err := collection.FindOne(ctx, bson.M{"email": *email}).Decode(&user)
		if err != nil {
			handleError(w, http.StatusBadRequest, "No user with this email", err)
			return
		}

		if user.Role != targetRole {
			handleError(w, http.StatusForbidden, "You do not have permission to access this resource", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func generateRandomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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

	var existingUser User
	err := collection.FindOne(ctx, bson.M{"email": creds.Email}).Decode(&existingUser)
	if err == nil {
		handleError(w, http.StatusConflict, "User with that email already exists", nil)
		return
	}

	token, err := generateRandomToken()
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Failed to generate token", err)
		return
	}

	newUser := User{
		Email:             creds.Email,
		Password:          creds.Password,
		Name:              creds.Name,
		Verified:          false,
		ConfirmationToken: token,
		Role:              "user",
	}
	_, err = collection.InsertOne(ctx, newUser)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Error creating user", err)
		return
	}

	logger.WithFields(logrus.Fields{"email": creds.Email}).Info("User signed up (unverified)")

	confirmURL := fmt.Sprintf("http://localhost:8080/confirm?token=%s", token)

	emailBody := fmt.Sprintf(`
        <h1>Welcome to Pullo, %s!</h1>
        <p>Please confirm your email by clicking the button below.</p>
        <p>
          <a style="background-color: #008CBA; color: white; padding: 8px 16px; 
                    text-decoration: none; border-radius: 4px;" 
             href="%s">
             Confirm Your Account
          </a>
        </p>
    `, creds.Name, confirmURL)

	go func(to, subject, body string) {
		if err := sendMail(to, subject, body, ""); err != nil {
			logger.Errorf("Could not send confirmation mail to %s: %v", to, err)
		}
	}(creds.Email, "Confirm Your Pullo Registration", emailBody)

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]string{
		"message": "User created but unverified. Check your email to confirm.",
	})
	if err != nil {
		return
	}
}

func confirmEmailHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		handleError(w, http.StatusBadRequest, "Missing token in query string", nil)
		return
	}

	collection := db.Database("db").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user User
	err := collection.FindOne(ctx, bson.M{"confirmationToken": token}).Decode(&user)
	if err != nil {
		handleError(w, http.StatusBadRequest, "Invalid or expired token", err)
		return
	}

	filter := bson.M{"confirmationToken": token}
	update := bson.M{"$set": bson.M{"verified": true, "confirmationToken": ""}}

	_, err = collection.UpdateOne(ctx, filter, update)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Could not verify user", err)
		return
	}

	logger.WithFields(logrus.Fields{"email": user.Email}).Info("User confirmed successfully")

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]string{
		"message": "Email confirmed! You may now log in.",
	})
	if err != nil {
		return
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	fmt.Println("Received request for login")

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		handleError(w, http.StatusBadRequest, "Invalid request payload", err)
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(r.Body)
	fmt.Println("Decoded creds:", creds)

	collection := db.Database("db").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user User
	err := collection.FindOne(ctx, bson.M{"email": creds.Email}).Decode(&user)
	if err != nil {
		handleError(w, http.StatusUnauthorized, "Invalid email or password", err)
		return
	}

	if user.Password != creds.Password {
		handleError(w, http.StatusUnauthorized, "Invalid email or password", nil)
		return
	}
	if !user.Verified {
		handleError(w, http.StatusForbidden, "Please confirm your email before logging in", nil)
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour)
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
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Could not generate token", err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "JWT",
		Value:   "Bearer " + tokenString,
		Expires: expiresAt,
	})

	logger.WithFields(logrus.Fields{"email": user.Email}).Info("User logged in successfully")

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"name":   user.Name,
		"email":  user.Email,
	})
	if err != nil {
		return
	}
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
		handleError(w, http.StatusBadRequest, "Passwords do not match", errors.New("password mismatch"))
		return
	}

	collection := db.Database("db").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	email, ok := FromContext(r.Context())
	if !ok {
		handleError(w, http.StatusBadRequest, "No email in context", errors.New("missing email in context"))
		return
	}

	var user User
	err := collection.FindOne(ctx, bson.M{"email": *email}).Decode(&user)
	if err != nil {
		handleError(w, http.StatusBadRequest, "No user with this email", err)
		return
	}
	if user.Password != creds.OldPassword {
		handleError(w, http.StatusBadRequest, "Old password is incorrect", nil)
		return
	}

	_, err = collection.DeleteOne(ctx, bson.M{"email": user.Email})
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Cannot remove old user doc", err)
		return
	}

	user.Password = creds.Password
	_, err = collection.InsertOne(ctx, user)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Error updating user", err)
		return
	}

	err = sendMail(user.Email, "Pullo password changed",
		"Your Pullo account password was changed successfully.",
		"C:\\Users\\zhann\\GolandProjects\\programming\\store\\public\\images\\passChange.png")
	if err != nil {
		return
	}

	logger.WithFields(logrus.Fields{"email": user.Email}).Info("User changed password successfully")

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]string{
		"message": "User changed password successfully",
	})
	if err != nil {
		return
	}
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	logger.WithField("action", "get_users").Info("Fetching users from MongoDB")

	sortBy := r.URL.Query().Get("sort")
	emailFilter := r.URL.Query().Get("email")
	pageStr := r.URL.Query().Get("page")
	pageSizeStr := r.URL.Query().Get("pageSize")

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
	findOptions := options.Find().SetSort(sortFields).SetSkip(skip).SetLimit(limit)

	collection := db.Database("db").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, filter, findOptions)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Database query error", err)
		return
	}
	defer func(cursor *mongo.Cursor, ctx context.Context) {
		err := cursor.Close(ctx)
		if err != nil {

		}
	}(cursor, ctx)

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
	err = json.NewEncoder(w).Encode(users)
	if err != nil {
		return
	}
}

func getSneakers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pageStr := r.URL.Query().Get("page")
	pageSizeStr := r.URL.Query().Get("pageSize")

	pageNum := 1
	pageSize := 5

	if pageStr != "" {
		if val, err := strconv.Atoi(pageStr); err == nil && val > 0 {
			pageNum = val
		}
	}
	if pageSizeStr != "" {
		if val, err := strconv.Atoi(pageSizeStr); err == nil && val > 0 {
			pageSize = val
		}
	}

	skip := int64((pageNum - 1) * pageSize)
	limit := int64(pageSize)

	opts := options.Find().SetSkip(skip).SetLimit(limit)

	collection := db.Database("OnlineStore").Collection("sneakers")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		http.Error(w, "Error fetching sneakers", http.StatusInternalServerError)
		log.Println("Error fetching sneakers:", err)
		return
	}
	defer func(cursor *mongo.Cursor, ctx context.Context) {
		err := cursor.Close(ctx)
		if err != nil {

		}
	}(cursor, ctx)

	var sneakers []bson.M
	if err := cursor.All(ctx, &sneakers); err != nil {
		http.Error(w, "Error parsing sneakers", http.StatusInternalServerError)
		log.Println("Error parsing sneakers:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(sneakers)
	if err != nil {
		return
	}
}

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
	err := json.NewEncoder(w).Encode(map[string]string{
		"message": "Email sent successfully",
	})
	if err != nil {
		return
	}
}

func sendMail(to, subject, body, attachmentPath string) error {
	username := os.Getenv("PULLOEMAIL")
	password := os.Getenv("PULLOEMAIL_PASSWORD")

	msg := gomail.NewMessage()
	msg.SetHeader("From", username)
	msg.SetHeader("To", to)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/html", body)

	if attachmentPath != "" {
		msg.Attach(attachmentPath)
	}

	dialer := gomail.NewDialer(os.Getenv("PULLO_EMAIL_PROVIDER"), 587, username, password)
	if err := dialer.DialAndSend(msg); err != nil {
		logger.WithFields(logrus.Fields{"Module": "SendMail"}).Error(err)
		return errors.New("failed to send email: " + err.Error())
	}
	logger.WithFields(logrus.Fields{"to": to, "subject": subject}).Info("Email sent successfully")
	return nil
}

func getUserProfileHandler(w http.ResponseWriter, r *http.Request) {
	email, ok := FromContext(r.Context())
	if !ok {
		handleError(w, http.StatusUnauthorized, "Unauthorized access", nil)
		return
	}

	collection := db.Database("db").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user User
	err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		handleError(w, http.StatusNotFound, "User not found", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]string{
		"name":  user.Name,
		"email": user.Email,
	})
	if err != nil {
		return
	}
}

func createSneaker(w http.ResponseWriter, r *http.Request) {
	collection := db.Database("OnlineStore").Collection("sneakers")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var s Sneaker
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, "Invalid request payload for sneaker", http.StatusBadRequest)
		return
	}
	res, err := collection.InsertOne(ctx, s)
	if err != nil {
		http.Error(w, "Failed to create sneaker", http.StatusInternalServerError)
		logger.WithError(err).Error("Insert sneaker error")
		return
	}
	logger.WithField("action", "createSneaker").Info("Sneaker created")

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Sneaker created successfully",
		"id":      res.InsertedID,
	})
	if err != nil {
		return
	}
}

func updateSneaker(w http.ResponseWriter, r *http.Request) {
	collection := db.Database("OnlineStore").Collection("sneakers")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	vars := mux.Vars(r)
	idHex := vars["id"]
	objID, err := primitive.ObjectIDFromHex(idHex)
	if err != nil {
		http.Error(w, "Invalid ID format", http.StatusBadRequest)
		return
	}

	var s Sneaker
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, "Invalid JSON for sneaker update", http.StatusBadRequest)
		return
	}

	filter := bson.M{"_id": objID}
	update := bson.M{"$set": bson.M{
		"brand": s.Brand,
		"model": s.Model,
		"price": s.Price,
		"color": s.Color,
	}}
	res, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		http.Error(w, "Failed to update sneaker", http.StatusInternalServerError)
		logger.WithError(err).Error("Update sneaker error")
		return
	}
	if res.MatchedCount == 0 {
		http.Error(w, "No sneaker found with that ID", http.StatusNotFound)
		return
	}
	logger.WithField("action", "updateSneaker").Info("Sneaker updated")

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]string{
		"message": "Sneaker updated successfully",
	})
	if err != nil {
		return
	}
}

func deleteSneaker(w http.ResponseWriter, r *http.Request) {
	collection := db.Database("OnlineStore").Collection("sneakers")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	vars := mux.Vars(r)
	idHex := vars["id"]
	objID, err := primitive.ObjectIDFromHex(idHex)
	if err != nil {
		http.Error(w, "Invalid ID format", http.StatusBadRequest)
		return
	}

	res, err := collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		http.Error(w, "Failed to delete sneaker", http.StatusInternalServerError)
		logger.WithError(err).Error("Delete sneaker error")
		return
	}
	if res.DeletedCount == 0 {
		http.Error(w, "No sneaker found to delete", http.StatusNotFound)
		return
	}
	logger.WithField("action", "deleteSneaker").Info("Sneaker deleted")

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]string{
		"message": "Sneaker deleted successfully",
	})
	if err != nil {
		return
	}
}

func addToCartHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SneakerID string `json:"sneakerId"`
		Quantity  int    `json:"quantity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handleError(w, http.StatusBadRequest, "Invalid request payload", err)
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(r.Body)

	if req.Quantity < 1 {
		req.Quantity = 1
	}

	objID, err := primitive.ObjectIDFromHex(req.SneakerID)
	if err != nil {
		handleError(w, http.StatusBadRequest, "Invalid sneakerId format", err)
		return
	}

	email, ok := FromContext(r.Context())
	if !ok {
		handleError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}

	userCol := db.Database("db").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user User
	if err := userCol.FindOne(ctx, bson.M{"email": *email}).Decode(&user); err != nil {
		handleError(w, http.StatusNotFound, "User not found", err)
		return
	}

	found := false
	for i, item := range user.Cart {
		if item.SneakerID == objID {
			// increment
			user.Cart[i].Quantity += req.Quantity
			found = true
			break
		}
	}
	if !found {
		user.Cart = append(user.Cart, CartItem{
			SneakerID: objID,
			Quantity:  req.Quantity,
		})
	}

	filter := bson.M{"email": user.Email}
	update := bson.M{"$set": bson.M{"cart": user.Cart}}
	if _, err := userCol.UpdateOne(ctx, filter, update); err != nil {
		handleError(w, http.StatusInternalServerError, "Failed to update cart", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]string{
		"message": "Item added to cart successfully",
	})
	if err != nil {
		return
	}
}

func getCartHandler(w http.ResponseWriter, r *http.Request) {
	email, ok := FromContext(r.Context())
	if !ok {
		handleError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}

	userCol := db.Database("db").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user User
	if err := userCol.FindOne(ctx, bson.M{"email": *email}).Decode(&user); err != nil {
		handleError(w, http.StatusNotFound, "User not found", err)
		return
	}

	sneakersCol := db.Database("OnlineStore").Collection("sneakers")
	var cartItems []bson.M
	for _, cartItem := range user.Cart {
		var sneaker Sneaker
		err := sneakersCol.FindOne(ctx, bson.M{"_id": cartItem.SneakerID}).Decode(&sneaker)
		if err == nil {
			cartItems = append(cartItems, bson.M{
				"sneakerId": cartItem.SneakerID,
				"quantity":  cartItem.Quantity,
				"brand":     sneaker.Brand,
				"model":     sneaker.Model,
				"price":     sneaker.Price,
				"color":     sneaker.Color,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(cartItems)
	if err != nil {
		return
	}
}

func removeFromCartHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idHex := vars["sneakerId"]

	sneakerID, err := primitive.ObjectIDFromHex(idHex)
	if err != nil {
		handleError(w, http.StatusBadRequest, "Invalid ID format", err)
		return
	}

	email, ok := FromContext(r.Context())
	if !ok {
		handleError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}

	userCol := db.Database("db").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user User
	if err := userCol.FindOne(ctx, bson.M{"email": *email}).Decode(&user); err != nil {
		handleError(w, http.StatusNotFound, "User not found", err)
		return
	}

	newCart := make([]CartItem, 0, len(user.Cart))
	for _, item := range user.Cart {
		if item.SneakerID != sneakerID {
			newCart = append(newCart, item)
		}
	}
	user.Cart = newCart

	if _, err := userCol.UpdateOne(ctx, bson.M{"email": user.Email},
		bson.M{"$set": bson.M{"cart": user.Cart}}); err != nil {
		handleError(w, http.StatusInternalServerError, "Failed to remove item", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]string{
		"message": "Item removed from cart",
	})
	if err != nil {
		return
	}
}

func checkoutHandler(w http.ResponseWriter, r *http.Request) {
	email, ok := FromContext(r.Context())
	if !ok {
		handleError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}

	userCol := db.Database("db").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user User
	if err := userCol.FindOne(ctx, bson.M{"email": *email}).Decode(&user); err != nil {
		handleError(w, http.StatusNotFound, "User not found", err)
		return
	}

	if len(user.Cart) == 0 {
		handleError(w, http.StatusBadRequest, "Cart is empty", nil)
		return
	}

	sneakersCol := db.Database("OnlineStore").Collection("sneakers")
	var total float64
	for _, ci := range user.Cart {
		var sneaker Sneaker
		if err := sneakersCol.FindOne(ctx, bson.M{"_id": ci.SneakerID}).Decode(&sneaker); err == nil {
			total += float64(sneaker.Price) * float64(ci.Quantity)
		}
	}

	txCollection := db.Database("OnlineStore").Collection("transactions")
	transactionID := primitive.NewObjectID().Hex() // or some other unique string
	newTx := Transaction{
		TransactionID: transactionID,
		UserID:        user.ID,
		CartItems:     user.Cart,
		TotalAmount:   total,
		Status:        StatusPending,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	res, err := txCollection.InsertOne(ctx, newTx)
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Failed to create transaction", err)
		return
	}

	payload := map[string]interface{}{
		"transactionId": transactionID,
		"cartItems":     user.Cart,
		"customer": map[string]interface{}{
			"id":    user.ID,
			"name":  user.Name,
			"email": user.Email,
		},
		"totalAmount": total,
	}
	payloadBytes, _ := json.Marshal(payload)

	microserviceURL := "http://localhost:8081/payment"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(microserviceURL, "application/json", strings.NewReader(string(payloadBytes)))
	if err != nil {
		handleError(w, http.StatusInternalServerError, "Payment service error", err)
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	var microResp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&microResp); err != nil {
		handleError(w, http.StatusInternalServerError, "Invalid microservice response", err)
		return
	}

	newStatus := StatusDeclined
	if microResp.Success {
		newStatus = StatusPaid
	}

	filter := bson.M{"_id": res.InsertedID}
	update := bson.M{
		"$set": bson.M{
			"status":    newStatus,
			"updatedAt": time.Now(),
		},
	}
	if _, err := txCollection.UpdateOne(ctx, filter, update); err != nil {
		handleError(w, http.StatusInternalServerError, "Failed to update transaction status", err)
		return
	}

	if microResp.Success {
		if _, err := userCol.UpdateOne(ctx, bson.M{"email": user.Email}, bson.M{"$set": bson.M{"cart": []CartItem{}}}); err != nil {
			logger.Error("Failed to clear cart after payment: ", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]interface{}{
		"transactionId": transactionID,
		"message":       microResp.Message,
		"success":       microResp.Success,
	})
	if err != nil {
		return
	}
}
