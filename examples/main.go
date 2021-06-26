package main

import (
	"context"
	"fmt"
	"githib.com/yarlson/mongostore"
	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"log"
	"net/http"
	"time"
)

func main() {

}

func initMongoClient(DSN string) (*mongo.Client, error) {
	client, err := mongo.NewClient(options.Client().ApplyURI(DSN))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		return nil, err
	}

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		return nil, err
	}

	return client, nil
}

func foo(rw http.ResponseWriter, req *http.Request) {
	// Fetch new store.
	db, err := initMongoClient("mongodb://127.0.0.1:27017")
	if err != nil {
		panic(err)
	}

	store, err := mongostore.NewMongoStore(
		req.Context(),
		db.Database("db").Collection("cookies"), 3600,
		true, []byte("secret-key"),
	)
	if err != nil {
		log.Println(err.Error())
		return
	}

	// Get a session.
	session, err := store.Get(req, "session-key")
	if err != nil {
		log.Println(err.Error())
		return
	}

	// Add a value.
	session.Values["foo"] = "bar"

	// Save.
	if err = sessions.Save(req, rw); err != nil {
		log.Printf("Error saving session: %v", err)
	}

	_, _ = fmt.Fprintln(rw, "ok")
}
