// Copyright 2012 The KidStuff Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mongostore

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

var (
	ErrInvalidId = errors.New("mongostore: invalid session id")
)

// Session object store in MongoDB
type Session struct {
	Id       primitive.ObjectID `bson:"_id,omitempty"`
	Data     string
	Modified time.Time
}

// MongoStore stores sessions in MongoDB
type MongoStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options
	Token   TokenGetSetter
	coll    *mongo.Collection
}

// NewMongoStore returns a new MongoStore.
// Set ensureTTL to true let the database auto-remove expired object by maxAge.
func NewMongoStore(ctx context.Context, c *mongo.Collection, maxAge int, ensureTTL bool, keyPairs ...[]byte) (*MongoStore, error) {
	store := &MongoStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: maxAge,
		},
		Token: &CookieToken{},
		coll:  c,
	}

	store.MaxAge(maxAge)

	if ensureTTL {
		mod := mongo.IndexModel{
			Keys: bson.M{
				"modified": 1,
			}, Options: options.Index().SetSparse(true).SetExpireAfterSeconds(int32(maxAge)),
		}
		_, err := c.Indexes().CreateOne(ctx, mod)
		if err != nil {
			return nil, err
		}
	}

	return store, nil
}

// Get registers and returns a session for the given name and session store.
// It returns a new session if there are no sessions registered for the name.
func (m *MongoStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(m, name)
}

// New returns a session for the given name without adding it to the registry.
func (m *MongoStore) New(r *http.Request, name string) (*sessions.Session, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	session := sessions.NewSession(m, name)
	session.Options = &sessions.Options{
		Path:     m.Options.Path,
		MaxAge:   m.Options.MaxAge,
		Domain:   m.Options.Domain,
		Secure:   m.Options.Secure,
		HttpOnly: m.Options.HttpOnly,
	}
	session.IsNew = true

	cook, err := m.Token.GetToken(r, name)
	if err != nil {
		return nil, err
	}

	err = securecookie.DecodeMulti(name, cook, &session.ID, m.Codecs...)
	if err != nil {
		return nil, err
	}

	err = m.load(ctx, session)
	if err == nil {
		session.IsNew = false
	}

	return session, nil
}

// Save saves all sessions registered for the current request.
func (m *MongoStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if session.Options.MaxAge < 0 {
		if err := m.delete(ctx, session); err != nil {
			return err
		}
		m.Token.SetToken(w, session.Name(), "", session.Options)
		return nil
	}

	if session.ID == "" {
		session.ID = primitive.NewObjectID().Hex()
	}

	if err := m.upsert(ctx, session); err != nil {
		return err
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, m.Codecs...)
	if err != nil {
		return err
	}

	m.Token.SetToken(w, session.Name(), encoded, session.Options)
	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (m *MongoStore) MaxAge(age int) {
	m.Options.MaxAge = age

	// Set the maxAge for each securecookie instance.
	for _, codec := range m.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

func (m *MongoStore) load(ctx context.Context, session *sessions.Session) error {
	id, err := primitive.ObjectIDFromHex(session.ID)
	if err != nil {
		return ErrInvalidId
	}

	s := Session{}
	filter := bson.M{"_id": id}
	err = m.coll.FindOne(ctx, filter).Decode(&s)
	if err != nil {
		return err
	}

	if err := securecookie.DecodeMulti(session.Name(), s.Data, &session.Values, m.Codecs...); err != nil {
		return err
	}

	return nil
}

func (m *MongoStore) upsert(ctx context.Context, session *sessions.Session) error {
	id, err := primitive.ObjectIDFromHex(session.ID)
	if err != nil {
		return ErrInvalidId
	}

	var modified time.Time
	if val, ok := session.Values["modified"]; ok {
		modified, ok = val.(time.Time)
		if !ok {
			return errors.New("mongostore: invalid modified value")
		}
	} else {
		modified = time.Now()
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, m.Codecs...)
	if err != nil {
		return err
	}

	s := Session{
		Id:       id,
		Data:     encoded,
		Modified: modified,
	}

	opts := options.Update().SetUpsert(true)
	filter := bson.M{"_id": id}
	_, err = m.coll.UpdateOne(ctx, filter, s, opts)
	if err != nil {
		return err
	}

	return nil
}

func (m *MongoStore) delete(ctx context.Context, session *sessions.Session) error {
	id, err := primitive.ObjectIDFromHex(session.ID)
	if err != nil {
		return ErrInvalidId
	}

	filter := bson.M{"_id": id}

	_, err = m.coll.DeleteOne(ctx, filter)

	return err
}
