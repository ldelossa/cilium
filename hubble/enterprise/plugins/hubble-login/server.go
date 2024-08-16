// Copyright (C) Isovalent, Inc. - All Rights Reserved.
// Copyright 2018 Hidetake Iwata

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file is adapted from https://github.com/int128/oauth2cli/blob/d1b93b431e8429229b774c78b3259d29b304557b/server.go
// Changes include copying some referenced variables from oauth2cli.go into this file and config.go

package plugin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/int128/listener"
	"golang.org/x/sync/errgroup"
)

var noopMiddleware = func(h http.Handler) http.Handler { return h }

// DefaultLocalServerSuccessHTML is a default response body on authorization success.
const DefaultLocalServerSuccessHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Authorized</title>
	<script>
		window.close()
	</script>
	<style>
		body {
			background-color: #eee;
			margin: 0;
			padding: 0;
			font-family: sans-serif;
		}
		.placeholder {
			margin: 2em;
			padding: 2em;
			background-color: #fff;
			border-radius: 1em;
		}
	</style>
</head>
<body>
	<div class="placeholder">
		<h1>Authorized</h1>
		<p>You can close this window.</p>
	</div>
</body>
</html>
`

func receiveCodeViaLocalServer(ctx context.Context, c *ServerConfig) (string, error) {
	l, err := listener.New(c.LocalServerBindAddress)
	if err != nil {
		return "", fmt.Errorf("could not start a local server: %w", err)
	}
	defer l.Close()
	c.OAuth2Config.RedirectURL = computeRedirectURL(l, c)

	respCh := make(chan *authorizationResponse)
	//nolint:gosec
	server := http.Server{
		Handler: c.LocalServerMiddleware(&localServerHandler{
			config: c,
			respCh: respCh,
		}),
	}
	shutdownCh := make(chan struct{})
	var resp *authorizationResponse
	var eg errgroup.Group
	eg.Go(func() error {
		defer close(respCh)
		c.Logger.Debug("starting a server", "addr", l.Addr())
		defer c.Logger.Debug("stopped the server", "addr", l.Addr())
		if c.isLocalServerHTTPS() {
			if err := server.ServeTLS(l, c.LocalServerCertFile, c.LocalServerKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("could not start HTTPS server: %w", err)
			}
			return nil
		}
		if err := server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("could not start HTTP server: %w", err)
		}
		return nil
	})
	eg.Go(func() error {
		defer close(shutdownCh)
		select {
		case gotResp, ok := <-respCh:
			if ok {
				resp = gotResp
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	eg.Go(func() error {
		<-shutdownCh
		// Gracefully shutdown the server in the timeout.
		// If the server has not started, Shutdown returns nil and this returns immediately.
		// If Shutdown has failed, force-close the server.
		c.Logger.Debug("shutting down the server", "addr", l.Addr())
		ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			c.Logger.Error("force-closing the server: shutdown failed", "error", err)
			_ = server.Close()
			return nil
		}
		return nil
	})
	eg.Go(func() error {
		if c.LocalServerReadyChan == nil {
			return nil
		}
		select {
		case c.LocalServerReadyChan <- c.OAuth2Config.RedirectURL:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if err := eg.Wait(); err != nil {
		return "", fmt.Errorf("authorization error: %w", err)
	}
	if resp == nil {
		return "", errors.New("no authorization response")
	}
	return resp.code, resp.err
}

func computeRedirectURL(l net.Listener, c *ServerConfig) string {
	hostPort := fmt.Sprintf("%s:%d", c.RedirectURLHostname, l.Addr().(*net.TCPAddr).Port)
	if c.LocalServerCertFile != "" {
		return "https://" + hostPort
	}
	return "http://" + hostPort
}

type authorizationResponse struct {
	code string // non-empty if a valid code is received
	err  error  // non-nil if an error is received or any error occurs
}

type localServerHandler struct {
	config     *ServerConfig
	respCh     chan<- *authorizationResponse // channel to send a response to
	onceRespCh sync.Once                     // ensure send once
}

func (h *localServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch {
	case r.Method == "GET" && r.URL.Path == "/" && q.Get("error") != "":
		h.onceRespCh.Do(func() {
			h.respCh <- h.handleErrorResponse(w, r)
		})
	case r.Method == "GET" && r.URL.Path == "/" && q.Get("code") != "":
		h.onceRespCh.Do(func() {
			h.respCh <- h.handleCodeResponse(w, r)
		})
	case r.Method == "GET" && r.URL.Path == "/":
		h.handleIndex(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *localServerHandler) handleIndex(w http.ResponseWriter, r *http.Request) {
	authCodeURL := h.config.OAuth2Config.AuthCodeURL(h.config.State, h.config.AuthCodeOptions...)
	h.config.Logger.Debug("sending redirect", "url", authCodeURL)
	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

func (h *localServerHandler) handleCodeResponse(w http.ResponseWriter, r *http.Request) *authorizationResponse {
	q := r.URL.Query()
	code, state := q.Get("code"), q.Get("state")

	if state != h.config.State {
		h.authorizationError(w, r)
		return &authorizationResponse{err: fmt.Errorf("state does not match (wants %s but got %s)", h.config.State, state)}
	}

	if h.config.SuccessRedirectURL != "" {
		http.Redirect(w, r, h.config.SuccessRedirectURL, http.StatusFound)
	} else {
		w.Header().Add("Content-Type", "text/html")
		if _, err := fmt.Fprint(w, h.config.LocalServerSuccessHTML); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return &authorizationResponse{err: fmt.Errorf("write error: %w", err)}
		}
	}

	return &authorizationResponse{code: code}
}

func (h *localServerHandler) handleErrorResponse(w http.ResponseWriter, r *http.Request) *authorizationResponse {
	q := r.URL.Query()
	errorCode, errorDescription := q.Get("error"), q.Get("error_description")

	h.authorizationError(w, r)
	return &authorizationResponse{err: fmt.Errorf("authorization error from server: %s %s", errorCode, errorDescription)}
}

func (h *localServerHandler) authorizationError(w http.ResponseWriter, r *http.Request) {
	if h.config.FailureRedirectURL != "" {
		http.Redirect(w, r, h.config.FailureRedirectURL, http.StatusFound)
	} else {
		http.Error(w, "authorization error", http.StatusInternalServerError)
	}
}
