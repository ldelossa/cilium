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
	"sync"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
)

// AgentDataCache is a cache which stores data retrieved from agent by
// DNS proxy so that proxy can function when agent is unavailable
type AgentDataCache struct {
	endpointByIP map[string]*endpoint.Endpoint
	identityByIP map[string]ipcache.Identity
	ipBySecID    map[identity.NumericIdentity][]string

	lock sync.RWMutex
}

func NewCache() AgentDataCache {
	return AgentDataCache{
		endpointByIP: make(map[string]*endpoint.Endpoint),
		identityByIP: make(map[string]ipcache.Identity),
		ipBySecID:    make(map[identity.NumericIdentity][]string),
	}
}
