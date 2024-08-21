// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package plugin

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/conn"
	"github.com/cilium/cilium/hubble/cmd/common/template"
	"github.com/cilium/cilium/hubble/cmd/common/validate"
	"github.com/cilium/cilium/hubble/enterprise/plugins"
	"github.com/cilium/cilium/hubble/enterprise/plugins/hubble-login/oauth2params"
	"github.com/cilium/cilium/hubble/pkg/defaults"
	"github.com/cilium/cilium/hubble/pkg/logger"
	"github.com/cilium/cilium/pkg/safeio"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

var (
	oidcLoginFile       string
	oidcTokenFile       string
	errConfigDirMissing error
	_                   plugins.Instance    = New
	_                   plugins.AddCommands = &loginPlugin{}
	_                   plugins.AddFlags    = &loginPlugin{}
)

func init() {
	switch {
	case defaults.ConfigDir != "":
		oidcLoginFile = filepath.Join(defaults.ConfigDir, "login.json")
		oidcTokenFile = filepath.Join(defaults.ConfigDir, "oidc-token.jwt")
	case defaults.ConfigDirFallback != "":
		oidcLoginFile = filepath.Join(defaults.ConfigDirFallback, "login.json")
		oidcTokenFile = filepath.Join(defaults.ConfigDirFallback, "oidc-token.jwt")
	default:
		errConfigDirMissing = fmt.Errorf("Unable to create/read the configuration directory for hubble")
	}
}

type loginPlugin struct{}

// NewLoginPlugin returns the loginCommand
func New() (plugins.Instance, error) {
	p := &loginPlugin{}
	conn.GRPCOptionFuncs = append(conn.GRPCOptionFuncs, grpcOptionToken)
	validate.FlagFuncs = append(validate.FlagFuncs, validateTokenFlags)
	return p, nil
}

func (p *loginPlugin) AddCommands() []plugins.CommandInit {
	return []plugins.CommandInit{p.getLoginCMD, p.getLogoutCMD, p.getPrintTokenCMD}
}

func (p *loginPlugin) AddFlags() []plugins.FlagsInit {
	return []plugins.FlagsInit{
		p.tokenFlags,
	}
}

func (p *loginPlugin) tokenFlags() (fs *pflag.FlagSet, args []string, persistent bool, err error) {
	args = []string{"hubble"} // Add to observe commands
	persistent = true         // Flags are available to sub-commands
	fs = pflag.NewFlagSet("OIDC", pflag.ContinueOnError)
	// Flags here should not be added to the login command flags, otherwise we'll get duplicate flag registration errors
	fs.String("token-type", "Bearer", "Define the type of token that is expected in specified token file.")
	fs.String("token-file", "", "Path to a file that contains an authentication token to pass along when doing requests.")
	// Defined here because we need this flag to be shared between all sub-commands, including hubble login
	fs.String("issuer", "", "OIDC issuer url. Required for all grant-types.")
	fs.String("issuer-ca", "", "CA to validate OIDC issuer against.")
	return
}

func (p *loginPlugin) getLogoutCMD(vp *viper.Viper) (*cobra.Command, error) {
	logoutCmd := &cobra.Command{
		Use:   "logout",
		Short: "Logout from an OIDC provider",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return deleteCredentials()
		},
	}
	return logoutCmd, nil
}

func (p *loginPlugin) getLoginCMD(vp *viper.Viper) (*cobra.Command, error) {
	loginCmd := &cobra.Command{
		Use:                   "login",
		Short:                 "Login to an OIDC provider",
		Long:                  "Login to an OIDC provider.",
		DisableFlagsInUseLine: false,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if errConfigDirMissing != nil {
				return errConfigDirMissing
			}
			var dirPath string
			switch {
			case defaults.ConfigDir != "":
				dirPath = defaults.ConfigDir
			case defaults.ConfigDirFallback != "":
				dirPath = defaults.ConfigDirFallback
			}

			if err := os.MkdirAll(dirPath, 0750); err != nil {
				log.Printf("hubble login needs to be able to create the directory %q with a 0755 permission", dirPath)
				return err
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			issuer := vp.GetString("issuer")
			issuerCA := vp.GetString("issuer-ca")
			clientID := vp.GetString("client-id")
			clientSecret := vp.GetString("client-secret")
			user := vp.GetString("user")
			grantType := vp.GetString("grant-type")
			scopes := vp.GetStringSlice("scopes")
			refresh := vp.GetBool("refresh")
			tokenFile := vp.GetString("token-file")
			passwordFile := vp.GetString("password-file")
			localServerPort := vp.GetInt("local-server-port")

			switch {
			case issuer == "":
				return fmt.Errorf("must pass an issuer")
			case clientID == "":
				return fmt.Errorf("must pass a client-id")
			case clientSecret == "":
				return fmt.Errorf("must pass a client-secret")
			case grantType == "password" && user == "":
				return fmt.Errorf("must pass a username")
			}

			l := &Login{
				Issuer:       issuer,
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Username:     user,
			}

			ctx := cmd.Context()
			ctx, err := newOAuth2ClientContext(ctx, issuerCA)
			if err != nil {
				return err
			}
			logger.Logger.Debug("Getting OIDC provider metadata")
			provider, err := oidc.NewProvider(ctx, l.Issuer)
			if err != nil {
				return fmt.Errorf("error creating OIDC provider: %w", err)
			}
			oauth2Token, err := login(ctx, provider, l, loginParameters{
				grantType:        grantType,
				refresh:          refresh,
				additionalScopes: scopes,
				passwordFile:     passwordFile,
				localServerPort:  localServerPort,
			})
			if err != nil {
				return fmt.Errorf("failed to login: %w", err)
			}
			token, err := oauth2TokenToToken(ctx, provider, l, oauth2Token)
			if err != nil {
				return fmt.Errorf("failed to login: %w", err)
			}
			err = saveCredentials(l, token, tokenFile)
			if err != nil {
				return fmt.Errorf("failed to save credentials: %w", err)
			}
			return nil
		},
	}
	fs := pflag.NewFlagSet("login", pflag.ContinueOnError)
	fs.String("client-id", "", "OIDC application client ID. Required for all grant-types.")
	fs.String("client-secret", "", "OIDC application client secret. Required for all grant-types.")
	fs.String("user", "", "OIDC username. Used for password grant-type.")
	fs.String("grant-type", "auto", "One of: auto, authcode or password. Can be used to force authentication using a particular grant-type.")
	fs.StringSlice("scopes", []string{}, "Additional OAuth2 scopes to set when logging in.")
	fs.Bool("refresh", false, "Refresh existing tokens using a refresh token if possible. Set to true to refresh credentials manually and set to false to relogin (if scopes or user changed).")
	fs.String("password-file", "", "Path to a file that contains the users password.")
	fs.Int("local-server-port", 8080, "Specify the port to listen on for the local web server when doing redirect based OAuth2 flows.")
	loginCmd.Flags().AddFlagSet(fs)
	vp.BindPFlags(fs)
	template.RegisterFlagSets(loginCmd, fs)

	return loginCmd, nil
}

type Login struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	Username     string `json:"userName"`
}

func refresh(ctx context.Context, provider *oidc.Provider, l *Login, additionalScopes ...string) (*oauth2.Token, error) {
	oauth2Config := &oauth2.Config{
		ClientID:     l.ClientID,
		ClientSecret: l.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       append([]string{oidc.ScopeOpenID}, additionalScopes...),
		RedirectURL:  "",
	}

	savedToken, err := readToken(l.Issuer)
	if err != nil {
		return nil, err
	}
	logger.Logger.Debug("Making refresh token request")
	token, err := oauth2Config.TokenSource(ctx, &oauth2.Token{
		Expiry:       savedToken.Expiry,
		RefreshToken: savedToken.RefreshToken,
	}).Token()
	if err != nil {
		return nil, err
	}
	return token, nil
}

type loginParameters struct {
	grantType        string
	refresh          bool
	additionalScopes []string
	passwordFile     string
	localServerPort  int
}

func login(ctx context.Context, provider *oidc.Provider, l *Login, params loginParameters) (*oauth2.Token, error) {
	supportedGrants, err := GetSupportedGrants(provider)
	if err != nil {
		return nil, fmt.Errorf("unable to get supported grant types: %w", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     l.ClientID,
		ClientSecret: l.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       append([]string{oidc.ScopeOpenID}, params.additionalScopes...),
		RedirectURL:  "",
	}

	// Refresh token flow, only used if we have valid creds with a refresh token
	// and --refresh=true (default)
	if params.refresh {
		// Before logging in, check if we already have creds that we can just refresh
		logger.Logger.Debug("Checking if credentials already exist and can be refreshed")
		savedToken, err := readToken(l.Issuer)
		if err != nil {
			logger.Logger.Debug("Unable to get existing credentials", "error", err)
		} else if savedToken.RefreshToken != "" {
			if !supportedGrants.Refresh {
				logger.Logger.Warn("Found existing refresh token, but IDP does not list refresh_token as supported grant type")
			}
			logger.Logger.Debug("Found existing refresh token, attempting to refresh")
			token, err := oauth2Config.TokenSource(ctx, &oauth2.Token{
				RefreshToken: savedToken.RefreshToken,
			}).Token()
			if err != nil {
				logger.Logger.Warn("Unable to refresh existing credentials", "issuer", l.Issuer, "error", err)
			} else {
				fmt.Printf("You got a valid token until %s\n", token.Expiry.Local())
				return token, nil
			}
		}
	} else {
		logger.Logger.Debug("Skipping refresh because --refresh=false")
	}

	// Authorization code flow
	if (params.grantType == "auto" && supportedGrants.AuthorizationCode) || params.grantType == "authcode" {
		if !supportedGrants.AuthorizationCode {
			logger.Logger.Warn("specified --grant-type=authcode, but IDP does not list authorization_code as supported grant type")
		}
		pkce, err := oauth2params.NewPKCE()
		if err != nil {
			return nil, err
		}

		// ready will receive the URL to open in the browser once the local web server is up
		ready := make(chan string, 1)
		defer close(ready)
		cfg := ServerConfig{
			OAuth2Config:           *oauth2Config,
			AuthCodeOptions:        pkce.AuthCodeOptions(),
			TokenRequestOptions:    pkce.TokenRequestOptions(),
			LocalServerReadyChan:   ready,
			LocalServerBindAddress: []string{net.JoinHostPort("localhost", strconv.Itoa(params.localServerPort))},
			Logger:                 logger.Logger.With("component", "server"),
		}

		eg, ctx := errgroup.WithContext(ctx)

		// Start a go routine that's going to open the web-browser
		eg.Go(func() error {
			select {
			case url := <-ready:
				fmt.Printf("Open %s\n", url)
				if err := browser.OpenURL(url); err != nil {
					fmt.Printf("could not open the browser: %s\n", err)
				}
				return nil
			case <-ctx.Done():
				return fmt.Errorf("context done while waiting for authorization: %w", ctx.Err())
			}
		})

		// start a go routine that runs the local web server and initiates the login flow
		var token *oauth2.Token
		eg.Go(func() error {
			var err error
			token, err = AuthorizationCodeToken(ctx, cfg)
			if err != nil {
				return fmt.Errorf("could not get a token: %w", err)
			}
			fmt.Printf("You got a valid token until %s\n", token.Expiry)
			return nil
		})

		// Wait for the go routines to complete
		if err := eg.Wait(); err != nil {
			return nil, fmt.Errorf("authorization error: %w", err)
		}
		return token, nil
	}

	// Password flow
	if (params.grantType == "auto" && supportedGrants.Password) || params.grantType == "password" {
		if !supportedGrants.Password {
			logger.Logger.Warn("specified --grant-type=password, but IDP does not list password as supported grant type")
		}
		if params.grantType == "auto" && l.Username == "" {
			return nil, errors.New("specified --grant-type=auto, but --username was not specified, unable to do 'password' grant-type")
		}
		fmt.Println("Unable to reuse existing credentials, attempting login...")

		var password []byte
		if params.passwordFile == "" {
			fmt.Fprintf(os.Stderr, "Enter your Password for %q: ", l.Issuer)
			password, err = term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return nil, fmt.Errorf("unable to read password: %w", err)
			}
			fmt.Fprint(os.Stderr, "\n")
		} else {
			password, err = os.ReadFile(params.passwordFile)
			if err != nil {
				return nil, fmt.Errorf("unable to read password: %w", err)
			}
		}

		token, err := oauth2Config.PasswordCredentialsToken(ctx, l.Username, strings.TrimSpace(string(password)))
		if err != nil {
			return nil, fmt.Errorf("unable to exchange user credentials for oauth token: %w", err)
		}
		fmt.Printf("You got a valid token until %s\n", token.Expiry.Local())
		return token, nil
	}

	return nil, fmt.Errorf("unable to find a supported authentication grant type, grant-type: %q, supported grants: %s, try manually setting --grant-type", params.grantType, supportedGrants)
}

type SupportedGrants struct {
	Refresh           bool
	AuthorizationCode bool
	Password          bool

	grantTypesSupported []string
}

func (g SupportedGrants) String() string {
	return "[" + strings.Join(g.grantTypesSupported, ", ") + "]"

}

func GetSupportedGrants(provider *oidc.Provider) (SupportedGrants, error) {
	var grants SupportedGrants
	var providerMetadata struct {
		GrantTypesSupported []string `json:"grant_types_supported"`
	}
	err := provider.Claims(&providerMetadata)
	if err != nil {
		return grants, fmt.Errorf("unable to unmarshal OIDC well-known metadata: %w", err)
	}

	// preserve the original list so we can log the full list of supported grant
	// types, even the ones we don't use/support.
	grants.grantTypesSupported = providerMetadata.GrantTypesSupported
	for _, grantType := range providerMetadata.GrantTypesSupported {
		switch grantType {
		case "refresh_token":
			grants.Refresh = true
		case "authorization_code":
			grants.AuthorizationCode = true
		case "password":
			grants.Password = true
		}
	}
	return grants, nil
}

func readLoginCredentials() (map[string]Login, error) {
	loginBytes, err := os.ReadFile(filepath.Clean(oidcLoginFile))
	if err != nil {
		return nil, err
	}
	loginMap := make(map[string]Login)
	err = json.Unmarshal(loginBytes, &loginMap)
	if err != nil {
		return nil, fmt.Errorf("unable to parse existing login file %s: %w", oidcLoginFile, err)
	}
	return loginMap, nil
}

func oauth2TokenToToken(ctx context.Context, provider *oidc.Provider, l *Login, oauth2Token *oauth2.Token) (*Token, error) {
	oidcConfig := &oidc.Config{
		ClientID:                   l.ClientID,
		SupportedSigningAlgs:       nil,
		SkipClientIDCheck:          false,
		SkipExpiryCheck:            false,
		SkipIssuerCheck:            false,
		Now:                        nil,
		InsecureSkipSignatureCheck: false,
	}
	verifier := provider.Verifier(oidcConfig)

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no ID token found in response")
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}

	return &Token{
		TokenType:     "Bearer",
		RawIDToken:    rawIDToken,
		IDTokenExpiry: idToken.Expiry,
		RefreshToken:  oauth2Token.RefreshToken,
		AccessToken:   oauth2Token.AccessToken,
		Expiry:        oauth2Token.Expiry,
		idToken:       idToken,
	}, nil
}

func deleteCredentials() error {
	err := os.Remove(oidcTokenFile)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("unable to find existing credentials")
	}
	return err
}

func saveCredentials(l *Login, token *Token, idTokenOut string) error {
	loginMap := map[string]Login{
		l.Issuer: *l,
	}
	// Save login file
	loginBytes, err := json.Marshal(&loginMap)
	if err != nil {
		return fmt.Errorf("could not marshal login data structure into json: %w", err)
	}
	err = os.WriteFile(oidcLoginFile, loginBytes, 0600)
	if err != nil {
		log.Printf("unable to write the login file, %q: %s", oidcLoginFile, err)
	}

	// Store token in oidcTokenFile
	tokens := map[string]*Token{
		l.Issuer: token,
	}
	tokensJSON, err := json.Marshal(&tokens)
	if err != nil {
		return fmt.Errorf("failed to marshal the token into json to save to a file: %w", err)
	}
	err = os.WriteFile(oidcTokenFile, tokensJSON, 0600)
	if err != nil {
		return fmt.Errorf("unable to write the token file, %q: %w", oidcTokenFile, err)
	}

	if idTokenOut != "" {
		err := os.WriteFile(idTokenOut, []byte(token.RawIDToken), 0600)
		if err != nil {
			return fmt.Errorf("failed to save ID token: %w", err)
		}
	}
	return nil
}

func validateTokenFlags(cmd *cobra.Command, vp *viper.Viper) error {
	// Skip validating these options when doing login
	if cmd.Name() == "login" {
		return nil
	}
	target := vp.GetString(config.KeyServer)
	// To protect against token disclosure (e.g. by eavesdropping), TLS is mandatory.
	if vp.GetString("token-file") != "" && !(vp.GetBool(config.KeyTLS) || strings.HasPrefix(target, defaults.TargetTLSPrefix)) {
		return validate.ErrTLSRequired
	}

	if vp.GetString("token-file") != "" && vp.GetString("token-type") == "" {
		return errors.New("token type must be specified")
	}
	return nil
}

var ErrNoCredentials = errors.New("no credentials")

func readToken(issuer string) (*Token, error) {
	tokenFile, err := os.Open(filepath.Clean(oidcTokenFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, ErrNoCredentials
	case err != nil:
		return nil, err
	}
	st, err := tokenFile.Stat()
	if err != nil {
		return nil, err
	}
	// If the token file is gt 1MiB
	// then the file won't be read.
	if st.Size() > 1<<20 {
		return nil, fmt.Errorf("the token file is too big (greater than 1MiB) to open: %dB", st.Size())
	}

	tokensFileJSON, err := safeio.ReadAllLimit(tokenFile, safeio.MB)
	if err != nil {
		return nil, err
	}

	tokens := make(map[string]*Token)
	err = json.Unmarshal(tokensFileJSON, &tokens)
	if err != nil {
		return nil, err
	}

	switch len(tokens) {
	case 0:
		return nil, fmt.Errorf("no tokens in file %s", oidcTokenFile)
	case 1:
		// if there's only one token in the file, use it, even if issuer wasn't set
		for _, value := range tokens {
			return value, nil
		}
	default:
		if issuer == "" {
			return nil, fmt.Errorf("no issuer set, but OIDC hubble config has multiple tokens from different issusers, please specify --issuer.")
		}
	}

	token, ok := tokens[issuer]
	if !ok {
		return nil, fmt.Errorf("unable to find token for issuer %s", issuer)
	}
	return token, nil
}

func grpcOptionToken(vp *viper.Viper) (grpc.DialOption, error) {
	lazyTokenFetcher := &LazyCredentialsFetcher{vp: vp}
	return grpc.WithPerRPCCredentials(lazyTokenFetcher), nil
}

type LazyCredentialsFetcher struct {
	once        sync.Once
	credentials credentials.PerRPCCredentials
	err         error
	vp          *viper.Viper
}

func (f *LazyCredentialsFetcher) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	creds, err := f.getCredentials(ctx)
	if err != nil {
		return nil, err
	}
	return creds.GetRequestMetadata(ctx, uri...)
}

func (f *LazyCredentialsFetcher) RequireTransportSecurity() bool {
	creds, err := f.getCredentials(context.Background())
	if err != nil {
		return false
	}
	return creds.RequireTransportSecurity()
}

func (f *LazyCredentialsFetcher) getCredentials(ctx context.Context) (credentials.PerRPCCredentials, error) {
	f.once.Do(func() {
		f.credentials, f.err = getCredentials(ctx, f.vp)
		if errors.Is(f.err, ErrNoCredentials) {
			logger.Logger.Debug("No existing cached credentials, not configuring authentication")
			f.credentials = noopCredentials{}
			f.err = nil
		}
	})
	return f.credentials, f.err
}

func getCredentials(ctx context.Context, vp *viper.Viper) (credentials.PerRPCCredentials, error) {
	tokenType := vp.GetString("token-type")
	tokenFile := vp.GetString("token-file")

	if tokenFile != "" {
		tokenBytes, err := os.ReadFile(filepath.Clean(tokenFile))
		if err != nil {
			return nil, fmt.Errorf("error reading --token-file: %w", err)
		}
		tokenStr := string(bytes.TrimSpace(tokenBytes))
		logger.Logger.Debug("using token-file for auth", "token-type", tokenType, "token-file", tokenFile)

		token := &oauth2.Token{
			AccessToken: tokenStr,
			TokenType:   tokenType,
		}
		return oauth.NewOauthAccess(token), nil
	} else {
		issuer := vp.GetString("issuer")
		issuerCA := vp.GetString("issuer-ca")
		clientID := vp.GetString("client-id")
		clientSecret := vp.GetString("client-secret")
		user := vp.GetString("user")

		logger.Logger.Debug("Checking for cached credentials on disk")
		// Try to reuse existing token on disk if one exists.
		token, err := readToken(issuer)
		if err != nil {
			return nil, fmt.Errorf("error reading OIDC token %w", err)
		}

		logger.Logger.Debug("Found cached credentials")

		// Expired, refresh the token/re-login
		if time.Now().After(token.IDTokenExpiry) {
			logger.Logger.Debug("Cached credentials are expired")
			if token.RefreshToken == "" {
				return nil, errors.New("token is expired and no refresh token set, please re-run hubble login")
			}

			logger.Logger.Debug("Attemping to refresh cached credentials")
			loginCreds, err := readLoginCredentials()
			if err != nil {
				return nil, fmt.Errorf("unable to find existing login credentials: %w", err)
			}

			var l *Login
			// If the flags are all set, use them
			switch {
			case issuer != "" && clientID != "" && clientSecret != "" && user != "":
				l = &Login{
					Issuer:       issuer,
					ClientID:     clientID,
					ClientSecret: clientSecret,
					Username:     user,
				}
			case issuer != "": // if we only know the issuer, lookup that specific issuer's login creds.
				lv := loginCreds[issuer]
				l = &lv
			default:
				// We have no idea what issuer they want, so we just grab the first
				// login issuer's creds
				for _, lv := range loginCreds {
					lv := lv
					l = &lv
					break
				}
			}
			if l == nil {
				return nil, errors.New("unable to find existing login credentials")
			}

			// FIXME: Find a way to get the command's context into the GRPCOptionFuncs
			// so we can use it here instead of context.Background
			ctx, err := newOAuth2ClientContext(ctx, issuerCA)
			if err != nil {
				return nil, err
			}
			logger.Logger.Debug("Getting OIDC provider metadata")
			provider, err := oidc.NewProvider(ctx, l.Issuer)
			if err != nil {
				return nil, fmt.Errorf("error creating OIDC provider: %w", err)
			}
			oauth2Token, err := refresh(ctx, provider, l)
			if err != nil {
				return nil, fmt.Errorf("failed to refresh credentials: %w", err)
			}
			token, err = oauth2TokenToToken(ctx, provider, l, oauth2Token)
			if err != nil {
				return nil, fmt.Errorf("failed to login: %w", err)
			}

			logger.Logger.Debug("Successfully refreshed credentials", "expiry", token.IDTokenExpiry.Local())
			err = saveCredentials(l, token, "")
			if err != nil {
				return nil, fmt.Errorf("failed to save credentials: %w", err)
			}
		}
		logger.Logger.Debug("Found existing credentials", "token-type", token.TokenType)
		return token, nil
	}
}

// Token implements grpc.credentials.PerRPCCredentials interface.
type Token struct {
	TokenType     string    `json:"type"`
	AccessToken   string    `json:"access_token"`
	RefreshToken  string    `json:"refresh_token"`
	Expiry        time.Time `json:"expiry"`
	RawIDToken    string    `json:"id_token"`
	IDTokenExpiry time.Time `json:"id_token_expiry"`

	idToken *oidc.IDToken
}

func (t *Token) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": strings.Title(t.TokenType) + " " + t.RawIDToken,
	}, nil
}

func (t *Token) RequireTransportSecurity() bool {
	return true
}

type noopCredentials struct{}

func (c noopCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{}, nil
}

func (c noopCredentials) RequireTransportSecurity() bool {
	return false
}

func newOAuth2ClientContext(ctx context.Context, issuerCA string) (context.Context, error) {
	httpClient := &http.Client{}
	if issuerCA != "" {
		caCert, err := os.ReadFile(filepath.Clean(issuerCA))
		if err != nil {
			return nil, fmt.Errorf("error reading issuer-ca: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{ //nolint:gosec
				RootCAs: caCertPool,
			},
		}
	}
	return context.WithValue(ctx, oauth2.HTTPClient, httpClient), nil
}

func (p *loginPlugin) getPrintTokenCMD(vp *viper.Viper) (*cobra.Command, error) {
	printTokenCmd := &cobra.Command{
		Use:   "print-token",
		Short: "Print out the ID token for the current login.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			issuer := vp.GetString("issuer")
			printRaw := vp.GetBool("raw")
			token, err := readToken(issuer)
			if err != nil {
				return fmt.Errorf("error reading OIDC token %w", err)
			}
			return printToken(token, printRaw)
		},
	}

	fs := pflag.NewFlagSet("print-token", pflag.ContinueOnError)
	fs.Bool("raw", false, "Print the raw ID token instead of the parsed token")
	printTokenCmd.Flags().AddFlagSet(fs)
	vp.BindPFlags(fs)
	template.RegisterFlagSets(printTokenCmd, fs)
	return printTokenCmd, nil
}

// Copied from https://github.com/coreos/go-oidc/blob/v3/oidc/jose.go#L21-L32
// We aren't using an oidc.Provider here, so we need to hardcode the
// algorithms, since the token could be using one of many algorithms.
var allAlgs = []jose.SignatureAlgorithm{
	jose.RS256,
	jose.RS384,
	jose.RS512,
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.PS256,
	jose.PS384,
	jose.PS512,
	jose.EdDSA,
}

func printToken(token *Token, printRaw bool) error {
	if printRaw {
		fmt.Println(token.RawIDToken)
		return nil
	}

	tok, err := jwt.ParseSigned(token.RawIDToken, allAlgs)
	if err != nil {
		return err
	}
	var out map[string]any
	err = tok.UnsafeClaimsWithoutVerification(&out)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
