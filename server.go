package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/duo-labs/webauthn.io/session"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gin-gonic/gin"
)

var webAuthn *webauthn.WebAuthn
var userDB *userdb
var sessionStore *session.Store

func main() {

	r := gin.New()

	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Foobar Corp.",     // Display Name for your site
		RPID:          "localhost",        // Generally the domain name for your site
		RPOrigin:      "http://localhost", // The origin URL for WebAuthn requests
		// RPIcon: "https://duo.com/logo.png", // Optional icon URL for your site
	})

	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}

	userDB = DB()

	sessionStore, err = session.NewStore()
	if err != nil {
		log.Fatal("failed to create session store:", err)
	}

	r.GET("/register/begin/:username", BeginRegistration)
	r.POST("/register/finish/:username", FinishRegistration)
	r.GET("/login/begin/:username", BeginLogin)
	r.POST("/login/finish/:username", FinishLogin)

	r.Any("/", Wrap(http.FileServer(http.Dir("./"))))

	if err := r.Run(":8080"); err != nil {
		fmt.Println("Failed to start server")
	}
}

func BeginRegistration(c *gin.Context) {

	// get username/friendly name
	username := c.Param("username")

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist, create new user
	if err != nil {
		displayName := strings.Split(username, "@")[0]
		user = NewUser(username, displayName)
		userDB.PutUser(user)
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
	}

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := webAuthn.BeginRegistration(user, registerOptions)

	if err != nil {
		log.Println(err)
		jsonResponse(c.Writer, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("registration", sessionData, c.Request, c.Writer)
	if err != nil {
		log.Println(err)
		jsonResponse(c.Writer, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(c.Writer, options, http.StatusOK)
}

func FinishRegistration(c *gin.Context) {

	// get username
	username := c.Param("username")

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(c.Writer, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("registration", c.Request)
	if err != nil {
		log.Println(err)
		jsonResponse(c.Writer, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, sessionData, c.Request)
	if err != nil {
		log.Println(err)
		jsonResponse(c.Writer, err.Error(), http.StatusBadRequest)
		return
	}

	user.AddCredential(*credential)

	jsonResponse(c.Writer, "Registration Success", http.StatusOK)
}

func BeginLogin(c *gin.Context) {

	// get username
	username := c.Param("username")

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(c.Writer, err.Error(), http.StatusBadRequest)
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		log.Println(err)
		jsonResponse(c.Writer, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("authentication", sessionData, c.Request, c.Writer)
	if err != nil {
		log.Println(err)
		jsonResponse(c.Writer, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(c.Writer, options, http.StatusOK)
}

func FinishLogin(c *gin.Context) {

	// get username
	username := c.Param("username")

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(c.Writer, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("authentication", c.Request)
	if err != nil {
		log.Println(err)
		jsonResponse(c.Writer, err.Error(), http.StatusBadRequest)
		return
	}

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	_, err = webAuthn.FinishLogin(user, sessionData, c.Request)
	if err != nil {
		log.Println(err)
		jsonResponse(c.Writer, err.Error(), http.StatusBadRequest)
		return
	}

	// handle successful login
	jsonResponse(c.Writer, "Login Success", http.StatusOK)
}

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

func Wrap(h http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}
