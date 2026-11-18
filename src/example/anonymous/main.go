// Command anonymous runs goauth with the anonymous plugin: visitors get a real session without an email
// or password (POST /api/auth/sign-in/anonymous), and when they later sign up or sign in, the plugin calls
// OnLinkAccount so the app can move their data to the real account, then deletes the anonymous user.
//
//	go run ./src/example/anonymous            # http://localhost:8080/docs
//	go test ./src/example/anonymous           # runs the flow end to end
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/anonymous"
	anonconfig "github.com/better-go-auth/goauth/src/plugins/anonymous/config"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
	"github.com/danielgtaylor/huma/v2"
)

// notes is the app's own per-user data (think: a shopping cart). Anonymous users can create notes too;
// OnLinkAccount moves them to the real account. A real app keeps this in its database.
type notes struct {
	mu     sync.Mutex
	byUser map[string][]string
}

func (n *notes) add(userID, text string) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.byUser[userID] = append(n.byUser[userID], text)
	return append([]string(nil), n.byUser[userID]...)
}

func (n *notes) list(userID string) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string{}, n.byUser[userID]...)
}

// move hands every note of from to to (called when an anonymous user links an account).
func (n *notes) move(from, to string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.byUser[to] = append(n.byUser[to], n.byUser[from]...)
	delete(n.byUser, from)
}

type notesOutput struct {
	Body struct {
		Notes []string `json:"notes"`
	}
}

type addNoteInput struct {
	Body struct {
		Text string `json:"text" minLength:"1"`
	}
}

// addNotesRoutes registers GET/POST /api/example/notes, protected by goauth's session middleware: they
// work the same for anonymous and real users.
func addNotesRoutes(app *exkit.App, store *notes) {
	protect := huma.Middlewares{app.Auth.MiddlewareInt().Authenticate()}
	huma.Register(app.API, huma.Operation{
		OperationID: "Example_ListNotes", Method: http.MethodGet, Path: "/api/example/notes",
		Summary: "The signed-in user's notes", Tags: []string{"Example"}, Middlewares: protect,
	}, func(ctx context.Context, _ *struct{}) (*notesOutput, error) {
		s, ok := authenticator.SessionFromContext(ctx)
		if !ok {
			return nil, huma.Error401Unauthorized("not signed in")
		}
		out := &notesOutput{}
		out.Body.Notes = store.list(s.Session.UserID)
		return out, nil
	})
	huma.Register(app.API, huma.Operation{
		OperationID: "Example_AddNote", Method: http.MethodPost, Path: "/api/example/notes",
		Summary: "Add a note for the signed-in user", Tags: []string{"Example"}, Middlewares: protect,
	}, func(ctx context.Context, in *addNoteInput) (*notesOutput, error) {
		s, ok := authenticator.SessionFromContext(ctx)
		if !ok {
			return nil, huma.Error401Unauthorized("not signed in")
		}
		out := &notesOutput{}
		out.Body.Notes = store.add(s.Session.UserID, in.Body.Text)
		return out, nil
	})
}

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*exkit.App, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	// Step 2: the app's own data that anonymous users can create
	store := &notes{byUser: map[string][]string{}}
	// Step 3: configure the plugin; OnLinkAccount runs when a request carrying an anonymous session signs
	// up or signs in to a real account, before the anonymous user is deleted
	anonPlugin := anonymous.New(anonconfig.AnonymousConfig{
		EmailDomainName: "guest.example.com", // anonymous emails become temp-<id>@guest.example.com
		GenerateName:    func(context.Context, *http.Request) string { return "Guest" },
		OnLinkAccount: func(_ context.Context, data anonconfig.LinkAccountData) error {
			log.Printf("[anonymous] linking %s -> %s", data.AnonymousUser.User.ID, data.NewUser.User.ID)
			store.move(data.AnonymousUser.User.ID, data.NewUser.User.ID)
			return nil
		},
	})
	// Step 4: set goauth up with the plugin
	app, err := exkit.New(context.Background(), exkit.Options{
		DB:      db,
		Plugins: []plugin.Plugin{anonPlugin},
	})
	if err != nil {
		return nil, err
	}
	// Step 5: protected routes of your own
	app.AddMeRoute()
	addNotesRoutes(app, store)
	return app, nil
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "anonymous_example.db"
	}
	app, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
