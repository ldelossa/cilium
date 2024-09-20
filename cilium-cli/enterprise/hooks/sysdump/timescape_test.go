//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sysdump

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/safeio"
)

func TestRunTimescapeBugtool(t *testing.T) {
	t.Run("simple server", func(t *testing.T) {
		c := timescapeMockK8sClient{
			execFunc: func(_ context.Context, namespace string, pod string, container string, command []string) (bytes.Buffer, bytes.Buffer, error) {
				assert.Equal(t, "hubble-timescape", namespace)
				assert.Equal(t, "hubble-timescape-server-667b5d554c-mxnfb", pod)
				assert.Equal(t, "server", container)
				assert.Equal(t, []string{"/usr/bin/hubble-timescape", "bugtool", "--out", "-"}, command)
				out := bytes.NewBufferString("test1")
				return *out, bytes.Buffer{}, nil
			},
		}
		out, err := runTimescapeBugtool(context.TODO(), c, "hubble-timescape", "hubble-timescape-server-667b5d554c-mxnfb", "server", timescapeBugtoolTaskConfig{
			prefix: "timescape-bugtool",
		})
		require.NoError(t, err)
		data, err := safeio.ReadAllLimit(out, 1000)
		require.NoError(t, err)
		assert.Equal(t, "test1", string(data))
	})
	t.Run("extra flags", func(t *testing.T) {
		c := timescapeMockK8sClient{
			execFunc: func(_ context.Context, namespace string, pod string, container string, command []string) (bytes.Buffer, bytes.Buffer, error) {
				assert.Equal(t, "hubble-timescape", namespace)
				assert.Equal(t, "hubble-timescape-ingester-667b5d554c-mxnfb", pod)
				assert.Equal(t, "ingester", container)
				assert.Equal(t, []string{"/usr/bin/hubble-timescape", "bugtool", "--out", "-", "--foo", "bar", "--test", "true"}, command)
				out := bytes.NewBufferString("test2")
				return *out, bytes.Buffer{}, nil
			},
		}
		out, err := runTimescapeBugtool(context.TODO(), c, "hubble-timescape", "hubble-timescape-ingester-667b5d554c-mxnfb", "ingester", timescapeBugtoolTaskConfig{
			prefix: "timescape-bugtool",
			extraFlags: []string{
				"--foo",
				"bar",
				"--test",
				"true",
			},
		})
		require.NoError(t, err)
		data, err := safeio.ReadAllLimit(out, 1000)
		require.NoError(t, err)
		assert.Equal(t, "test2", string(data))
	})
	t.Run("fail, still capture output", func(t *testing.T) {
		c := timescapeMockK8sClient{
			execFunc: func(_ context.Context, _ string, _ string, _ string, _ []string) (bytes.Buffer, bytes.Buffer, error) {
				out := bytes.NewBufferString("partial-failure")
				return *out, bytes.Buffer{}, errors.New("something went wrong")
			},
		}
		out, err := runTimescapeBugtool(context.TODO(), c, "hubble-timescape", "hubble-timescape-server-667b5d554c-mxnfb", "server", timescapeBugtoolTaskConfig{
			prefix: "timescape-bugtool",
		})
		require.Error(t, err)
		data, err := safeio.ReadAllLimit(out, 1000)
		require.NoError(t, err)
		assert.Equal(t, "partial-failure", string(data))
	})

}

var _ timescapeBugtoolKubernetesClient = timescapeMockK8sClient{}

type timescapeMockK8sClient struct {
	execFunc func(ctx context.Context, namespace string, pod string, container string, command []string) (bytes.Buffer, bytes.Buffer, error)
}

// ExecInPodWithStderr implements timescapeBugtoolKubernetesClient.
func (t timescapeMockK8sClient) ExecInPodWithStderr(ctx context.Context, namespace string, pod string, container string, command []string) (bytes.Buffer, bytes.Buffer, error) {
	return t.execFunc(ctx, namespace, pod, container, command)
}
