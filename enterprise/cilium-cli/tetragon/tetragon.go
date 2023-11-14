package tetragon

import (
	_ "github.com/isovalent/hubble-fgs/pkg/k8s/apis/cilium.io"
	_ "github.com/isovalent/hubble-fgs/pkg/k8s/apis/cilium.io/v1alpha1"
	_ "github.com/isovalent/hubble-fgs/pkg/k8s/client/clientset/versioned"
	_ "github.com/isovalent/hubble-fgs/pkg/k8s/client/clientset/versioned/scheme"
	_ "github.com/isovalent/hubble-fgs/pkg/k8s/client/clientset/versioned/typed/cilium.io/v1alpha1"
)
