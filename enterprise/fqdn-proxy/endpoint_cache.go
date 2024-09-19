// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
)

// AgentDataCache is a cache which stores data retrieved from agent by
// DNS proxy so that proxy can function when agent is unavailable
type AgentDataCache struct {
	endpointByIP map[netip.Addr]*endpoint.Endpoint
	identityByIP map[netip.Addr]ipcache.Identity
	ipBySecID    map[identity.NumericIdentity][]string

	lock lock.RWMutex
}

func NewCache() AgentDataCache {
	return AgentDataCache{
		endpointByIP: make(map[netip.Addr]*endpoint.Endpoint),
		identityByIP: make(map[netip.Addr]ipcache.Identity),
		ipBySecID:    make(map[identity.NumericIdentity][]string),
	}
}
