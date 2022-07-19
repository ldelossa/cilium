// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of Cilium

package healthcheck

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	healthResponder "github.com/cilium/cilium/pkg/health/probe/responder"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "egressgateway")
)

const (
	NodeHealthy = iota
	NodeUnhealthy
)

// Event represents a healthchecking event such as a node becoming healthy/unhealthy
type Event struct {
	NodeName string
	Status   int
}

// Healthchecker is the public interface exposed by the egress gateway healthchecker
type Healthchecker interface {
	UpdateNodeList(nodes map[string]nodeTypes.Node)
	NodeIsHealthy(nodeName string) bool
	Events() chan Event
}

type nodeStatus struct {
	// lastSuccessfulProbeTimestamp is timestamp of the last successful probe
	lastSuccessfulProbeTimestamp time.Time

	// healthcheckerTickerCh is the channel used to stop the healthcheck goroutine for the node
	healthcheckerTickerCh *time.Ticker
}

type healthchecker struct {
	lock.RWMutex

	nodes    map[string]nodeTypes.Node
	statuses map[string]*nodeStatus
	timeout  time.Duration
	events   chan Event
}

// NewHealthchecker returns a new Healthchecker
func NewHealthchecker() Healthchecker {
	return &healthchecker{
		nodes:    make(map[string]nodeTypes.Node),
		statuses: make(map[string]*nodeStatus),
		timeout:  option.Config.EgressGatewayHealthcheckTimeout,
		events:   make(chan Event),
	}
}

// UpdateNodeList updates the internal list of nodes that the healthchecker
// should periodically check
func (h *healthchecker) UpdateNodeList(nodes map[string]nodeTypes.Node) {
	h.Lock()
	defer h.Unlock()

	for _, oldNode := range h.nodes {
		if _, ok := nodes[oldNode.Name]; !ok {
			h.stopNodeHealthcheck(oldNode)
		}
	}

	for _, newNode := range nodes {
		if _, ok := h.nodes[newNode.Name]; !ok {
			h.startNodeHealthcheck(newNode)
		}
	}

	h.nodes = nodes
}

// NodeIsHealthy returns whether a node is healthy (i.e. last successful probe
// is no older than `h.timeout`) or not
func (h *healthchecker) NodeIsHealthy(nodeName string) bool {
	h.RLock()
	defer h.RUnlock()

	status, ok := h.statuses[nodeName]

	return ok && h.probeTimestampIsFresh(status.lastSuccessfulProbeTimestamp)
}

// Events returns the healthchecker events channel
func (h *healthchecker) Events() chan Event {
	return h.events
}

func (h *healthchecker) probeTimestampIsFresh(probeTimestamp time.Time) bool {
	return time.Now().Sub(probeTimestamp) < h.timeout
}

func runHealthcheckProbe(netClient *http.Client, url string) bool {
	r, err := netClient.Get(url)
	if err != nil {
		return false
	}

	healthStatus := healthResponder.HealthStatus{}
	if err = json.NewDecoder(r.Body).Decode(&healthStatus); err != nil {
		return false
	}

	return healthStatus.BpfInitialized && healthStatus.BpfHostLoaded
}

// Caller must hold h.RwMutex
func (h *healthchecker) startNodeHealthcheck(node nodeTypes.Node) {
	var (
		tickerCh  = time.NewTicker(h.timeout / 2)
		netClient = &http.Client{Timeout: h.timeout}
		url       = fmt.Sprintf("http://%s/hello",
			net.JoinHostPort(node.GetNodeIP(false).String(), strconv.Itoa(option.Config.ClusterHealthPort)))
		logger = log.WithField(logfields.NodeName, node.Name)
	)

	logger.Info("Starting health check for node")

	h.statuses[node.Name] = &nodeStatus{
		healthcheckerTickerCh: tickerCh,
	}

	go func() {
		for range tickerCh.C {
			var event *Event

			probeSuccessful := runHealthcheckProbe(netClient, url)

			h.Lock()
			nodeStatus, ok := h.statuses[node.Name]
			if !ok {
				h.Unlock()
				continue
			}

			if !probeSuccessful {
				if !h.probeTimestampIsFresh(nodeStatus.lastSuccessfulProbeTimestamp) &&
					!nodeStatus.lastSuccessfulProbeTimestamp.IsZero() {
					logger.Info("Node became unhealthy")

					// When a node becomes unhealthy, set its last successful probe TS to 0 so next
					// time we run this check we'll know the node was already unhealthy (allowing us
					// to skip logging and emitting the event multiple times)
					nodeStatus.lastSuccessfulProbeTimestamp = time.Time{}
					event = &Event{NodeName: node.Name, Status: NodeUnhealthy}
				}
			} else {
				if !h.probeTimestampIsFresh(nodeStatus.lastSuccessfulProbeTimestamp) {
					logger.Info("Node became healthy")
					event = &Event{NodeName: node.Name, Status: NodeHealthy}
				}

				nodeStatus.lastSuccessfulProbeTimestamp = time.Now()
			}

			h.Unlock()

			if event != nil {
				h.events <- *event
			}
		}
	}()
}

// Caller must hold h.RwMutex
func (h *healthchecker) stopNodeHealthcheck(node nodeTypes.Node) {
	log.WithField(logfields.NodeName, node.Name).
		Info("Stopping health check for node")

	h.statuses[node.Name].healthcheckerTickerCh.Stop()
	delete(h.statuses, node.Name)
}
