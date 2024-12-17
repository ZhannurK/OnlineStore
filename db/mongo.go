package db

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

var client *mongo.Client

func ConnectMongoDB() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	client, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:8080"))
	return err
}

func DisconnectMongoDB() {
	err := client.Disconnect(context.Background())
	if err != nil {
		return
	}
}
