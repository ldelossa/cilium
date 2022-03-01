// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package responder

// this implementation is intentionally kept with minimal dependencies
// as this package typically runs in its own process
import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cilium/cilium/pkg/datapath"
)

// HealthStatus is an object returned by the /hello endpoint which provides
// additional information on the health state of the agent
type HealthStatus struct {
	BpfInitialized bool `json:"bpf_initialized"`
	BpfHostLoaded  bool `json:"bpf_host_loaded"`
}

// LoaderStatus is an interface used by the responder to probe the state of
// the datapath
type LoaderStatus interface {
	Status() *datapath.LoaderStatus
}

// defaultTimeout used for shutdown
var defaultTimeout = 30 * time.Second

// Server wraps a minimal http server for the /hello endpoint
type Server struct {
	httpServer http.Server
}

// NewServer creates a new server listening on the given port
func NewServer(port int, loaderStatus LoaderStatus) *Server {
	return &Server{
		http.Server{
			Addr: fmt.Sprintf(":%d", port),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				serverRequests(loaderStatus, w, r)
			}),
		},
	}
}

// Serve http requests until shut down
func (s *Server) Serve() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown server gracefully
func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return s.httpServer.Shutdown(ctx)
}

func serverRequests(loaderStatus LoaderStatus, w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/hello" {
		loaderStatus := loaderStatus.Status()
		loaderStatus.RLock()
		defer loaderStatus.RUnlock()

		json.NewEncoder(w).Encode(HealthStatus{
			BpfInitialized: loaderStatus.BpfInitialized,
			BpfHostLoaded:  loaderStatus.BpfHostLoaded,
		})
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}
