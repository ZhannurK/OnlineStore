package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lpernett/godotenv"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jung-kurt/gofpdf"
	gomail "gopkg.in/mail.v2"
)

type PaymentRequest struct {
	TransactionID string      `json:"transactionId"`
	CartItems     interface{} `json:"cartItems"`
	Customer      Customer    `json:"customer"`
	TotalAmount   float64     `json:"totalAmount"`
}

type Customer struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type PaymentResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Set up logrus to output to the terminal (stdout)
	logrus.SetOutput(os.Stdout)
	logrus.SetFormatter(&logrus.TextFormatter{})

	// Connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var db *mongo.Client

	db, err = mongo.Connect(ctx, options.Client().ApplyURI(os.Getenv("MONGO_CONNECT")))
	if err != nil {
		logrus.WithError(err).Fatal("Failed to connect to MongoDB")
	}
	if err = db.Ping(ctx, nil); err != nil {
		logrus.WithError(err).Fatal("Failed to ping MongoDB")
	}
	logrus.Info("Connected to MongoDB")
}

func main() {
	http.HandleFunc("/payment", paymentHandler)
	fmt.Println("Payment microservice listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func paymentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req PaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, false, "Invalid request")
		return
	}

	// 1. Validate or mock payment
	paymentOk := mockValidateCard() // always true in a test scenario

	if !paymentOk {
		respondJSON(w, http.StatusOK, false, "Payment declined (mock)")
		return
	}

	// 2. On success => generate receipt PDF + send email
	err := generateAndSendReceiptPDF(req)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, false, "Payment processed but receipt emailing failed")
		return
	}

	respondJSON(w, http.StatusOK, true, "Payment successful. Receipt sent.")
}

func respondJSON(w http.ResponseWriter, status int, success bool, msg string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(PaymentResponse{
		Success: success,
		Message: msg,
	})
}

// just returns true or false to simulate validation
func mockValidateCard() bool {
	return true
}

// generateAndSendReceiptPDF creates a PDF receipt file and emails it to the customer.
func generateAndSendReceiptPDF(req PaymentRequest) error {
	// 1) Generate the PDF in memory
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)

	// Header
	pdf.Cell(40, 10, "Receipt - Pullo Project")
	pdf.Ln(12)

	// Basic info
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(40, 10, fmt.Sprintf("Transaction ID: %s", req.TransactionID))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Customer Name: %s", req.Customer.Name))
	pdf.Ln(8)

	// Cart items (if you have a more detailed struct, adjust accordingly)
	pdf.Ln(5)
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 10, "Items Purchased:")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 12)

	var grandTotal float64
	// If req.CartItems is a list of custom struct, iterate to display each item
	// Example: for _, item := range req.CartItems {
	//   // ...
	// }
	// For demonstration, assume `req.CartItems` is something like []struct{Name, Price float64, Quantity int}.
	// Adjust the code below to match your real structure.

	// If you don't have an exact structure, demonstrate a placeholder:
	items, ok := req.CartItems.([]interface{})
	if ok {
		for _, raw := range items {
			// convert raw to your item struct or map
			itemMap, _ := raw.(map[string]interface{})
			name, _ := itemMap["name"].(string)
			price, _ := itemMap["price"].(float64)
			qty, _ := itemMap["quantity"].(float64) // or int

			line := fmt.Sprintf("%d x %s @ $%.2f each", int(qty), name, price)
			pdf.Cell(0, 8, line)
			pdf.Ln(8)

			grandTotal += price * qty
		}
	}

	pdf.Ln(5)
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 10, fmt.Sprintf("Total Amount: $%.2f", grandTotal))
	pdf.Ln(10)

	pdf.Cell(0, 10, fmt.Sprintf("Payment Method: %s", "Mock Credit Card (####-####-####-1234)"))
	pdf.Ln(12)

	pdf.Cell(0, 10, "Thank you for your purchase!")
	pdf.Ln(12)

	// 2) Save PDF to a file (you could also write directly to an in-memory buffer)
	pdfFilename := fmt.Sprintf("receipt_%s.pdf", req.TransactionID)
	err := pdf.OutputFileAndClose(pdfFilename)
	if err != nil {
		return fmt.Errorf("failed to create PDF file: %v", err)
	}

	// 3) Email the PDF receipt to the customer
	if err := sendEmailWithAttachment(
		req.Customer.Email,
		"Your Pullo Receipt",
		"<h3>Thank you for your purchase!</h3><p>Here is your receipt.</p>",
		pdfFilename,
	); err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	// 4) (Optional) Remove local PDF file after sending
	_ = os.Remove(pdfFilename)

	return nil
}

// sendEmailWithAttachment is a helper function to send an email with an attachment using Gomail.
func sendEmailWithAttachment(to, subject, body, attachmentPath string) error {
	// Example credentials - replace with your own or pull from environment variables
	smtpHost := "smtp.gmail.com"
	smtpPort := 587
	username := "your_gmail_username@gmail.com"
	password := "your_gmail_password"

	m := gomail.NewMessage()
	m.SetHeader("From", username)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	// Attach the PDF
	if attachmentPath != "" {
		m.Attach(attachmentPath)
	}

	d := gomail.NewDialer(smtpHost, smtpPort, username, password)

	return d.DialAndSend(m)
}
