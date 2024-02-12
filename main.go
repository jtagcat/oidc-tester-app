package main

import (
	"context"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var options Options

var provider *oidc.Provider
var verifier *oidc.IDTokenVerifier
var store = sessions.NewCookieStore([]byte("secret-key"))

var oauth2Config oauth2.Config

var (
	rawTokens = make(map[string]string)
	acURLs    = make(map[string]*url.URL)
)

const ENV_PREFIX = "TESTER_"

func env(key, fallback string) string {
	if val, ok := os.LookupEnv(ENV_PREFIX + key); ok {
		return val
	}

	return fallback
}

func envInt(key string, fallback int) int {
	if valStr, ok := os.LookupEnv(ENV_PREFIX + key); ok {
		val, err := strconv.Atoi(valStr)
		if err == nil {
			return val
		}
	}

	return fallback
}

func dumbNotEmpty(cmd *cobra.Command, key string) error {
	val, err := cmd.Flags().GetString(key)
	if err == nil && val != "" {
		return nil
	}

	return cmd.MarkFlagRequired(key)
}

func main() {
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger().Level(zerolog.DebugLevel)

	gob.Register(Claims{})

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	rootCmd := &cobra.Command{Use: "oidc-tester-app", RunE: root}

	rootCmd.Flags().StringVar(&options.Host, "host", env("HOST", "0.0.0.0"), "Specifies the tcp host to listen on")
	rootCmd.Flags().IntVar(&options.Port, "port", envInt("PORT", 8080), "Specifies the port to listen on")
	rootCmd.Flags().StringVar(&options.PublicURL, "public-url", env("PUBLIC_URL", "http://localhost:8080/"), "Specifies the root URL to generate the redirect URI")
	rootCmd.Flags().StringVar(&options.ClientID, "id", env("CLIENT_ID", ""), "Specifies the OpenID Connect Client ID")
	rootCmd.Flags().StringVarP(&options.ClientSecret, "secret", "s", env("CLIENT_SECRET", ""), "Specifies the OpenID Connect Client Secret")
	rootCmd.Flags().StringVarP(&options.Issuer, "issuer", "i", env("ISSUER", ""), "Specifies the URL for the OpenID Connect OP")
	rootCmd.Flags().StringVar(&options.Scopes, "scopes", env("SCOPES", "openid,profile,email,groups"), "Specifies the OpenID Connect scopes to request")
	rootCmd.Flags().StringVar(&options.CookieName, "cookie-name", env("COOKIE_NAME", "oidc-client"), "Specifies the storage cookie name to use")
	rootCmd.Flags().StringSliceVar(&options.Filters, "filters", []string{}, "If specified filters the specified text from html output (not json) out of the email addresses, display names, audience, etc")
	rootCmd.Flags().StringSliceVar(&options.GroupsFilter, "groups-filter", []string{}, "If specified only shows the groups in this list")

	_ = dumbNotEmpty(rootCmd, "id")
	_ = dumbNotEmpty(rootCmd, "secret")
	_ = dumbNotEmpty(rootCmd, "issuer")

	if err := rootCmd.Execute(); err != nil {
		log.Logger.Fatal().Err(err).Msg("error in root process")
	}
}

func root(cmd *cobra.Command, args []string) (err error) {
	var (
		publicURL, redirectURL *url.URL
	)

	if publicURL, redirectURL, err = getURLs(options.PublicURL); err != nil {
		return fmt.Errorf("could not parse public url: %w", err)
	}

	log.Info().
		Str("provider_url", options.Issuer).
		Str("redirect_url", redirectURL.String()).
		Msg("configuring oidc provider")

	if provider, err = oidc.NewProvider(context.Background(), options.Issuer); err != nil {
		return fmt.Errorf("error initializing oidc provider: %w", err)
	}

	verifier = provider.Verifier(&oidc.Config{ClientID: options.ClientID})
	oauth2Config = oauth2.Config{
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
		RedirectURL:  redirectURL.String(),
		Endpoint:     provider.Endpoint(),
		Scopes:       strings.Split(options.Scopes, ","),
	}

	r := mux.NewRouter()
	r.HandleFunc("/", indexHandler)
	r.HandleFunc("/error", errorHandler)
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/logout", logoutHandler)
	r.HandleFunc("/oauth2/callback", oauthCallbackHandler)
	r.HandleFunc("/json", jsonHandler)
	r.HandleFunc("/jwt.json", jsonHandler)
	r.HandleFunc("/protected", protectedHandler(true))
	r.HandleFunc("/protected/{type:group|user}/{name}", protectedHandler(false))

	r.NotFoundHandler = &ErrorHandler{http.StatusNotFound}
	r.MethodNotAllowedHandler = &ErrorHandler{http.StatusMethodNotAllowed}

	log.Logger.Info().
		Str("host", options.Host).
		Int("port", options.Port).
		Str("address", publicURL.String()).
		Msg("listening for connections")

	if err = http.ListenAndServe(fmt.Sprintf("%s:%d", options.Host, options.Port), r); err != nil {
		return fmt.Errorf("error listening: %w", err)
	}

	return nil
}

type ErrorHandler struct {
	code int
}

func (h *ErrorHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	switch h.code {
	case http.StatusNotFound:
		fmt.Printf("404 Not Found: %s %s\n", r.Method, r.URL)
	case http.StatusMethodNotAllowed:
		fmt.Printf("405 Method Not Allowed: %s %s\n", r.Method, r.URL)
	}

	rw.WriteHeader(h.code)
}
