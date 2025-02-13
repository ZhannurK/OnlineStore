package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	gomail "gopkg.in/mail.v2"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/jung-kurt/gofpdf"
	"github.com/lpernett/godotenv"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ------------------------------------------------------------------------
// MODELS
// ------------------------------------------------------------------------

type PaymentRequest struct {
	TransactionID string      `json:"transactionId"`
	CartItems     interface{} `json:"cartItems"` // could be []Item or similar
	Customer      Customer    `json:"customer"`
	TotalAmount   float64     `json:"totalAmount"`
}

type Customer struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type PaymentResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	PaymentURL string `json:"paymentUrl,omitempty"`
}

type PaymentForm struct {
	CardNumber     string `json:"cardNumber"`
	ExpirationDate string `json:"expirationDate"`
	CVV            string `json:"cvv"`
	Name           string `json:"name"`
	Address        string `json:"address"`
}

type FormPaymentRequest struct {
	TransactionID string      `json:"transactionId"`
	CartItems     interface{} `json:"cartItems"`
	Customer      Customer    `json:"customer"`
	TotalAmount   float64     `json:"totalAmount"`
	PaymentForm   PaymentForm `json:"paymentForm"`
}

type CartItem struct {
	SneakerID primitive.ObjectID `json:"sneakerId" bson:"sneakerId"`
	Quantity  int                `json:"quantity" bson:"quantity"`
}

type User struct {
	ID                string `json:"id" bson:"_id,omitempty"`
	Email             string `json:"email" bson:"email"`
	Name              string `json:"name" bson:"name"`
	Password          string `json:"password" bson:"password"`
	Verified          bool   `json:"verified" bson:"verified"`
	ConfirmationToken string `json:"confirmationToken" bson:"confirmationToken"`
	Role              string `json:"role" bson:"role"`

	Cart []CartItem `json:"cart" bson:"cart"`
}

type TransactionStatus string

const (
	StatusPending   TransactionStatus = "Pending Payment"
	StatusPaid      TransactionStatus = "Paid"
	StatusDeclined  TransactionStatus = "Declined"
	StatusCompleted TransactionStatus = "Completed"
)

type Transaction struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	TransactionID string             `bson:"transactionId" json:"transactionId"`
	UserID        string             `bson:"userId"        json:"userId"`
	CartItems     []CartItem         `bson:"cartItems"     json:"cartItems"`
	TotalAmount   float64            `bson:"totalAmount"   json:"totalAmount"`
	Status        TransactionStatus  `bson:"status"        json:"status"`
	CreatedAt     time.Time          `bson:"createdAt"     json:"createdAt"`
	UpdatedAt     time.Time          `bson:"updatedAt"     json:"updatedAt"`
}

// ------------------------------------------------------------------------
// GLOBALS
// ------------------------------------------------------------------------

var (
	db           *mongo.Client
	logger       = logrus.New()
	dbCollection *mongo.Collection
)

// ------------------------------------------------------------------------
// MAIN
// ------------------------------------------------------------------------
func main() {
	// Load environment variables from .env if present
	if err := godotenv.Load("../.env"); err != nil {
		logger.Warn("No .env file found or error loading it. Proceeding with system env variables.")
	}

	logger.SetOutput(os.Stdout)
	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

	// Connect to MongoDB
	if err := connectMongoDB(); err != nil {
		logger.WithError(err).Fatal("Failed to initialize MongoDB connection.")
	}
	logger.Info("Connected to MongoDB successfully.")

	// Setup router
	r := mux.NewRouter()

	// Serve static files from "/public" if needed (CSS, etc.)
	r.PathPrefix("/public").Handler(http.FileServer(http.Dir("./")))

	// 1) ENDPOINT: POST /payment
	//    Mark transaction as Pending, respond with the payment URL
	r.HandleFunc("/payment", paymentHandler).Methods(http.MethodPost)

	// 2) GET /payment/form => Serve Payment HTML Form
	r.HandleFunc("/payment/form", paymentFormHandler).Methods(http.MethodGet)

	// 3) POST /payment/submit => Process Payment Form data
	r.HandleFunc("/payment/submit", paymentSubmitHandler).Methods(http.MethodPost)

	// Convenience: GET /payment => Serve the same HTML form
	// e.g. http://localhost:8081/payment?transactionId=XYZ
	r.HandleFunc("/payment", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "payment.html")
	}).Methods(http.MethodGet)

	// Start the HTTP server
	srv := &http.Server{
		Addr:    ":8081",
		Handler: r,
	}

	// Graceful shutdown handling
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Infof("Starting server on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.WithError(err).Fatal("Server failed")
		}
	}()

	<-quit
	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.WithError(err).Fatal("Server forced to shutdown.")
	}

	if db != nil {
		if err := db.Disconnect(ctx); err != nil {
			logger.WithError(err).Error("Error disconnecting Mongo client.")
		}
	}

	logger.Info("Server exited gracefully.")
}

// ------------------------------------------------------------------------
// CONNECT TO MONGODB
// ------------------------------------------------------------------------
func connectMongoDB() error {
	mongoURI := os.Getenv("MONGO_CONNECT")
	if mongoURI == "" {
		// Fallback example only
		mongoURI = "mongodb+srv://app:dUp1o7jI28uvLAwh@cluster.dnxyg.mongodb.net/?retryWrites=true&w=majority&appName=Cluster"
		logger.Warn("Using fallback Mongo URI for demonstration.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		return fmt.Errorf("mongo.Connect error: %w", err)
	}
	if err = client.Ping(ctx, nil); err != nil {
		return fmt.Errorf("mongo.Ping error: %w", err)
	}

	db = client
	db := db.Database("OnlineStore")
	dbCollection = db.Collection("transactions")

	return nil
}

// ------------------------------------------------------------------------
//  1. POST /payment
//     Mark transaction as "Pending Payment", return payment URL
//
// ------------------------------------------------------------------------
func paymentHandler(w http.ResponseWriter, r *http.Request) {
	var req PaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.WithError(err).Error("Failed to decode PaymentRequest")
		respondJSON(w, http.StatusBadRequest, false, "Invalid request", "")
		return
	}

	// Mark transaction as "Pending Payment" in DB
	updateTransactionStatus(req.TransactionID, "Pending Payment")

	// Return a URL to the payment form
	paymentURL := fmt.Sprintf("http://localhost:8081/payment?transactionId=%s", req.TransactionID)

	// Respond with success + the link
	respondJSON(w, http.StatusOK, true,
		"Transaction created. Please open form to complete payment.",
		paymentURL,
	)
}

// ------------------------------------------------------------------------
// 2) GET /payment/form => Serves Payment HTML Form
// ------------------------------------------------------------------------
func paymentFormHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.ServeFile(w, r, "payment.html") // Make sure payment.html is in the same dir or adjust path
}

// ------------------------------------------------------------------------
// 3) POST /payment/submit => Process Payment Form data
//   - Validate card (mock)
//   - If valid => set "Paid" => generate PDF => email => set "Completed"
//   - If invalid => "Declined"
//
// ------------------------------------------------------------------------
func paymentSubmitHandler(w http.ResponseWriter, r *http.Request) {
	var req FormPaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, false, "Invalid JSON body: "+err.Error(), "")
		return
	}

	// 1. Mock card validation
	if !mockValidateCard(req.PaymentForm.CardNumber, req.PaymentForm.ExpirationDate, req.PaymentForm.CVV) {
		updateTransactionStatus(req.TransactionID, "Declined")
		respondJSON(w, http.StatusOK, false,
			"Payment declined (mock validation fails: card is invalid/expired)",
			"",
		)
		return
	}

	// 2. If valid => Mark transaction as "Paid"
	updateTransactionStatus(req.TransactionID, "Paid")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := map[string]interface{}{"transactionId": req.TransactionID}
	var tx Transaction

	if err := dbCollection.FindOne(ctx, filter).Decode(&tx); err != nil {
		logger.Error("Cannot decode transaction ", err.Error())
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	filter2 := map[string]interface{}{"_id": tx.UserID}
	var user User
	if err := db.Database("db").Collection("users").FindOne(ctx2, filter2).Decode(&user); err != nil {
		logger.Error("Cannot decode user ", err.Error())
	}

	// 3. Generate & email PDF receipt
	paymentReq := PaymentRequest{
		TransactionID: req.TransactionID,
		CartItems:     req.CartItems,
		Customer:      Customer{user.ID, user.Name, user.Email},
		TotalAmount:   req.TotalAmount,
	}
	if err := generateAndSendReceiptPDF(paymentReq); err != nil {
		respondJSON(w, http.StatusInternalServerError, false,
			"Receipt generation failed: "+err.Error(),
			"",
		)
		return
	}

	// 4. After emailing, Mark transaction as "Completed"
	updateTransactionStatus(req.TransactionID, "Completed")

	// 5. Respond success
	respondJSON(w, http.StatusOK, true, "Payment successful! Receipt emailed.", "")
}

// ------------------------------------------------------------------------
// HELPER: respondJSON
// ------------------------------------------------------------------------
func respondJSON(w http.ResponseWriter, status int, success bool, msg string, paymentURL string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(PaymentResponse{
		Success:    success,
		Message:    msg,
		PaymentURL: paymentURL,
	})
}

// ------------------------------------------------------------------------
// HELPER: mockValidateCard (Naive example checking expiration date + length)
// ------------------------------------------------------------------------
func mockValidateCard(cardNumber, expiration, cvv string) bool {
	parts := strings.Split(expiration, "/")
	if len(parts) != 2 {
		return false
	}

	monthStr := parts[0]
	yearStr := parts[1]

	month, errM := strconv.Atoi(monthStr)
	year, errY := strconv.Atoi(yearStr)
	if errM != nil || errY != nil {
		return false
	}

	// Convert to full year if only last two digits
	if year < 50 {
		year += 2000
	} else if year < 100 {
		year += 1900
	}

	now := time.Now()
	currentYear := now.Year()
	currentMonth := int(now.Month())

	// If year < current year => expired
	if year < currentYear {
		return false
	}
	// Same year but month < currentMonth => expired
	if year == currentYear && month < currentMonth {
		return false
	}
	// Basic length checks
	if len(cardNumber) < 8 || len(cvv) < 3 {
		return false
	}
	return true
}

// ------------------------------------------------------------------------
// Update a Transaction Status in MongoDB
// ------------------------------------------------------------------------
func updateTransactionStatus(transactionID, status string) {
	if dbCollection == nil {
		logger.Warn("No DB collection available, skipping DB update.")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := map[string]interface{}{"transactionId": transactionID}
	update := map[string]interface{}{
		"$set": map[string]interface{}{
			"status":    status,
			"updatedAt": time.Now(),
		},
	}

	_, err := dbCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		logger.WithError(err).Errorf("Failed to update transaction status for %s to %s", transactionID, status)
	} else {
		logger.Infof("Transaction %s updated to %s", transactionID, status)
	}
}

// ------------------------------------------------------------------------
// HELPER: generateAndSendReceiptPDF
// ------------------------------------------------------------------------

func generateInvoicePDF(transactionID, username, email string, cartItems interface{}, totalAmount float64) (string, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetFont("Arial", "", 12)

	// Title
	pdf.AddPage()
	pdf.Cell(40, 10, "Pullo Project - Fiscal Receipt")
	pdf.Ln(10)

	// Transaction Details
	now := time.Now().Format("2006-01-02 15:04:05")
	pdf.Cell(40, 10, "Transaction ID: "+transactionID)
	pdf.Ln(10)
	pdf.Cell(40, 10, "Date & Time: "+now)
	pdf.Ln(10)

	// Customer Info
	pdf.Cell(40, 10, "Customer: "+username)
	pdf.Ln(10)
	pdf.Cell(40, 10, "Email: "+email)
	pdf.Ln(10)

	// Cart Items
	pdf.Ln(5)
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 10, "Items Purchased:")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 12)

	items, ok := cartItems.([]interface{})
	if ok {
		for _, raw := range items {
			itemMap, _ := raw.(map[string]interface{})
			name, _ := itemMap["name"].(string)
			price, _ := itemMap["price"].(float64)
			qtyF, _ := itemMap["quantity"].(float64)
			qty := int(qtyF)

			line := fmt.Sprintf("%d x %s @ $%.2f each", qty, name, price)
			pdf.Cell(0, 8, line)
			pdf.Ln(8)
		}
	}

	pdf.Ln(5)
	pdf.SetFont("Arial", "B", 12)
	// Total Amount
	pdf.Cell(0, 10, fmt.Sprintf("Total Amount: $%.2f", totalAmount))
	pdf.Ln(10)

	// Payment Method
	pdf.Cell(0, 10, "Payment Method: Mock Credit Card (****-****-****-1234)")
	pdf.Ln(12)
	pdf.Cell(0, 10, "Thank you for your purchase!")
	pdf.Ln(12)

	// Save PDF to memory buffer
	var buf bytes.Buffer
	err := pdf.Output(&buf)
	if err != nil {
		log.Println("Error generating PDF:", err)
		return "", err
	}

	// Convert to Base64
	pdfBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	return pdfBase64, nil
}

// Send Email with PDF Attachment using gomail
func sendEmailWithAttachment(to, subject, message, filename, fileContent string) error {
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")

	if smtpHost == "" || smtpUser == "" || smtpPass == "" || smtpPort == "" {
		log.Println("SMTP credentials are missing in environment variables.")
		return fmt.Errorf("missing SMTP credentials")
	}

	port, err := strconv.Atoi(smtpPort)
	if err != nil {
		log.Println("Invalid SMTP_PORT value:", smtpPort)
		return fmt.Errorf("invalid SMTP port")
	}

	// Create a new email message
	m := gomail.NewMessage()
	m.SetHeader("From", smtpUser)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", message)

	// Attach PDF if available
	if filename != "" && fileContent != "" {
		pdfBytes, err := base64.StdEncoding.DecodeString(fileContent)
		if err != nil {
			log.Println("Failed to decode base64 PDF:", err)
			return fmt.Errorf("failed to decode PDF attachment")
		}
		m.Attach(filename, gomail.SetCopyFunc(func(w io.Writer) error {
			_, err := w.Write(pdfBytes)
			return err
		}))
	}

	// SMTP Dialer setup
	d := gomail.NewDialer(smtpHost, port, smtpUser, smtpPass)

	// Send Email
	if err := d.DialAndSend(m); err != nil {
		log.Println("Failed to send email:", err)
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Println("Email sent successfully to:", to)
	return nil
}

// Integrate into payment processing function
func generateAndSendReceiptPDF(req PaymentRequest) error {
	// Generate Base64-encoded PDF
	pdfBase64, err := generateInvoicePDF(req.TransactionID, req.Customer.Name, req.Customer.Email, req.CartItems, req.TotalAmount)
	if err != nil {
		return fmt.Errorf("failed to generate invoice PDF: %w", err)
	}

	// Send Email with PDF attachment
	err = sendEmailWithAttachment(
		req.Customer.Email,
		"Your Pullo Receipt",
		"Thank you for your purchase! Your invoice is attached.",
		"invoice.pdf",
		pdfBase64,
	)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	logrus.Info("Invoice email sent successfully.")
	return nil
}
