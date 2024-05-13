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

// This file is copied from https://github.com/int128/oauth2cli/blob/d1b93b431e8429229b774c78b3259d29b304557b/oauth2params/params.go

package oauth2params

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_computeS256(t *testing.T) {
	// Testdata described at:
	// https://tools.ietf.org/html/rfc7636#appendix-B
	b := []byte{
		116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
		187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
		132, 141, 121,
	}
	got := computeS256(b)
	want := PKCE{
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		CodeVerifier:        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
