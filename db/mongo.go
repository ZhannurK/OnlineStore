package db

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client
var userCollection *mongo.Collection

func ConnectMongoDB() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	client, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %v", err)
	}

	userCollection = client.Database("db").Collection("users")

	indexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}}, // Creates an ascending index on "email"
		Options: options.Index().SetUnique(true),  // Ensures uniqueness
	}

	if _, err := userCollection.Indexes().CreateOne(ctx, indexModel); err != nil {
		return fmt.Errorf("could not create unique index on email: %v", err)
	}

	fmt.Println("MongoDB connected, users collection initialized with unique index on email.")
	return nil
}

func DisconnectMongoDB() {
	if err := client.Disconnect(context.Background()); err != nil {
		fmt.Println("Error disconnecting MongoDB:", err)
	} else {
		fmt.Println("MongoDB disconnected successfully.")
	}
}
