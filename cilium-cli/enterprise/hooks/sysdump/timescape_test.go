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
	"fmt"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
	t.Run("collect ClickHouse", func(t *testing.T) {
		c := timescapeMockK8sClient{
			execFunc: func(_ context.Context, namespace string, pod string, container string, command []string) (bytes.Buffer, bytes.Buffer, error) {
				assert.Equal(t, "hubble-timescape", namespace)
				assert.Equal(t, "hubble-timescape-server-667b5d554c-mxnfb", pod)
				assert.Equal(t, "server", container)

				switch command[1] {
				case "bugtool":
					assert.Equal(t, []string{"/usr/bin/hubble-timescape", "bugtool", "--out", "-", "--collect-clickhouse-stats"}, command)
					out := bytes.NewBufferString("clickhouse")
					return *out, bytes.Buffer{}, nil
				case "version":
					assert.Equal(t, []string{"/usr/bin/hubble-timescape", "version"}, command)
					out := bytes.NewBufferString("hubble-timescape 1.5.2 compiled with go1.22.6 on linux/amd64")
					return *out, bytes.Buffer{}, nil
				}
				return bytes.Buffer{}, bytes.Buffer{}, fmt.Errorf("unexpected command %v", command)
			},
		}
		out, err := runTimescapeBugtool(context.TODO(), c, "hubble-timescape", "hubble-timescape-server-667b5d554c-mxnfb", "server", timescapeBugtoolTaskConfig{
			prefix:            "timescape-bugtool",
			collectClickhouse: true,
		})
		require.NoError(t, err)
		data, err := safeio.ReadAllLimit(out, 1000)
		require.NoError(t, err)
		assert.Equal(t, "clickhouse", string(data))
	})
	t.Run("don't collect ClickHouse pre v1.5.0", func(t *testing.T) {
		c := timescapeMockK8sClient{
			execFunc: func(_ context.Context, namespace string, pod string, container string, command []string) (bytes.Buffer, bytes.Buffer, error) {
				assert.Equal(t, "hubble-timescape", namespace)
				assert.Equal(t, "hubble-timescape-server-667b5d554c-mxnfb", pod)
				assert.Equal(t, "server", container)

				switch command[1] {
				case "bugtool":
					assert.Equal(t, []string{"/usr/bin/hubble-timescape", "bugtool", "--out", "-"}, command)
					out := bytes.NewBufferString("no clickhouse")
					return *out, bytes.Buffer{}, nil
				case "version":
					assert.Equal(t, []string{"/usr/bin/hubble-timescape", "version"}, command)
					out := bytes.NewBufferString("hubble-timescape 1.4.2 compiled with go1.22.6 on linux/amd64")
					return *out, bytes.Buffer{}, nil
				}
				return bytes.Buffer{}, bytes.Buffer{}, fmt.Errorf("unexpected command %v", command)
			},
		}
		out, err := runTimescapeBugtool(context.TODO(), c, "hubble-timescape", "hubble-timescape-server-667b5d554c-mxnfb", "server", timescapeBugtoolTaskConfig{
			prefix:            "timescape-bugtool",
			collectClickhouse: true,
		})
		require.NoError(t, err)
		data, err := safeio.ReadAllLimit(out, 1000)
		require.NoError(t, err)
		assert.Equal(t, "no clickhouse", string(data))
	})
	t.Run("collect ClickHouse with migrate credentials", func(t *testing.T) {
		c := timescapeMockK8sClient{
			execFunc: func(_ context.Context, namespace string, pod string, container string, command []string) (bytes.Buffer, bytes.Buffer, error) {
				assert.Equal(t, "hubble-timescape", namespace)
				assert.Equal(t, "hubble-timescape-server-667b5d554c-mxnfb", pod)
				assert.Equal(t, "server", container)
				switch command[1] {
				case "bugtool":
					assert.Equal(t, []string{"/usr/bin/hubble-timescape", "bugtool", "--out", "-", "--collect-clickhouse-stats", "--clickhouse-username=migrate", "--clickhouse-password=password1337"}, command)
					out := bytes.NewBufferString("clickhouse")
					return *out, bytes.Buffer{}, nil
				case "version":
					assert.Equal(t, []string{"/usr/bin/hubble-timescape", "version"}, command)
					out := bytes.NewBufferString("hubble-timescape 1.5.2 compiled with go1.22.6 on linux/amd64")
					return *out, bytes.Buffer{}, nil
				}
				return bytes.Buffer{}, bytes.Buffer{}, fmt.Errorf("unexpected command %v", command)
			},
			getSecret: func(_ context.Context, namespace string, name string, _ metav1.GetOptions) (*corev1.Secret, error) {
				assert.Equal(t, "hubble-timescape", namespace)
				assert.Equal(t, "migrate-custom-cred", name)
				return &corev1.Secret{
					Data: map[string][]byte{
						"CLICKHOUSE_PASSWORD": []byte("password1337"),
					},
				}, nil
			},
		}
		out, err := runTimescapeBugtool(context.TODO(), c, "hubble-timescape", "hubble-timescape-server-667b5d554c-mxnfb", "server", timescapeBugtoolTaskConfig{
			prefix:             "timescape-bugtool",
			collectClickhouse:  true,
			clickhouseUsername: "migrate",
			clickhousePwSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "migrate-custom-cred",
				},
				Key: "CLICKHOUSE_PASSWORD",
			},
		})
		require.NoError(t, err)
		data, err := safeio.ReadAllLimit(out, 1000)
		require.NoError(t, err)
		assert.Equal(t, "clickhouse", string(data))
	})
	t.Run("collect ClickHouse with missing migrate credentials", func(t *testing.T) {
		c := timescapeMockK8sClient{
			execFunc: func(_ context.Context, namespace string, pod string, container string, command []string) (bytes.Buffer, bytes.Buffer, error) {
				assert.Equal(t, "hubble-timescape", namespace)
				assert.Equal(t, "hubble-timescape-server-667b5d554c-mxnfb", pod)
				assert.Equal(t, "server", container)
				switch command[1] {
				case "bugtool":
					assert.Equal(t, []string{"/usr/bin/hubble-timescape", "bugtool", "--out", "-", "--collect-clickhouse-stats"}, command)
					out := bytes.NewBufferString("clickhouse")
					return *out, bytes.Buffer{}, nil
				case "version":
					assert.Equal(t, []string{"/usr/bin/hubble-timescape", "version"}, command)
					out := bytes.NewBufferString("hubble-timescape 1.5.2 compiled with go1.22.6 on linux/amd64")
					return *out, bytes.Buffer{}, nil
				}
				return bytes.Buffer{}, bytes.Buffer{}, fmt.Errorf("unexpected command %v", command)
			},
			getSecret: func(_ context.Context, namespace string, name string, _ metav1.GetOptions) (*corev1.Secret, error) {
				assert.Equal(t, "hubble-timescape", namespace)
				assert.Equal(t, "migrate-custom-cred", name)
				return nil, errors.New("not found")
			},
		}
		out, err := runTimescapeBugtool(context.TODO(), c, "hubble-timescape", "hubble-timescape-server-667b5d554c-mxnfb", "server", timescapeBugtoolTaskConfig{
			prefix:             "timescape-bugtool",
			collectClickhouse:  true,
			clickhouseUsername: "migrate",
			clickhousePwSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "migrate-custom-cred",
				},
				Key: "CLICKHOUSE_PASSWORD",
			},
		})
		require.Error(t, err)
		data, err := safeio.ReadAllLimit(out, 1000)
		require.NoError(t, err)
		assert.Equal(t, "clickhouse", string(data))
	})
}

func TestGetTimescapeVersion(t *testing.T) {
	tcs := map[string]struct {
		output        string
		expectErr     bool
		expectVersion semver.Version
	}{
		"simple": {
			output:    "hubble-timescape 1.4.0 compiled with go1.22.6 on linux/amd64",
			expectErr: false,
			expectVersion: semver.Version{
				Major: 1,
				Minor: 4,
				Patch: 0,
			},
		},
		"with patch": {
			output:    "hubble-timescape 1.5.2 compiled with go1.22.6 on linux/amd64",
			expectErr: false,
			expectVersion: semver.Version{
				Major: 1,
				Minor: 5,
				Patch: 2,
			},
		},
		"drop pre-release": {
			output:    "hubble-timescape 1.2.6-rc.1 compiled with go1.22.6 on linux/amd64",
			expectErr: false,
			expectVersion: semver.Version{
				Major: 1,
				Minor: 2,
				Patch: 6,
			},
		},
		"missing build info": {
			output:    "hubble-timescape 2.1.6",
			expectErr: false,
			expectVersion: semver.Version{
				Major: 2,
				Minor: 1,
				Patch: 6,
			},
		},
		"unknown": {
			output:    "unknown",
			expectErr: true,
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			c := timescapeMockK8sClient{
				execFunc: func(_ context.Context, namespace string, pod string, container string, command []string) (bytes.Buffer, bytes.Buffer, error) {
					assert.Equal(t, "hubble-timescape", namespace)
					assert.Equal(t, "hubble-timescape-ingester-667b5d554c-mxnfb", pod)
					assert.Equal(t, "ingester", container)
					assert.Equal(t, []string{"/usr/bin/hubble-timescape", "version"}, command)
					out := bytes.NewBufferString(tc.output)
					return *out, bytes.Buffer{}, nil
				},
			}
			v, err := getTimescapeVersion(context.TODO(), c, "hubble-timescape", "hubble-timescape-ingester-667b5d554c-mxnfb", "ingester")
			if tc.expectErr {
				require.Error(t, err)
				require.Nil(t, v)
			} else {
				require.NoError(t, err)
				require.NotNil(t, v)
				assert.Equal(t, tc.expectVersion, *v)
			}
		})
	}
}

func TestExtractMigrateCredentials(t *testing.T) {
	tcs := map[string]struct {
		pod       corev1.Pod
		expectErr bool
		user      string
		secretRef corev1.SecretKeySelector
	}{
		"simple": {
			pod: corev1.Pod{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name: "migrate",
							Env: []corev1.EnvVar{
								{
									Name:  "HUBBLE_TIMESCAPE_CLICKHOUSE_USERNAME",
									Value: "migrate",
								},
								{
									Name: "HUBBLE_TIMESCAPE_CLICKHOUSE_PASSWORD",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "migrate-credentials",
											},
											Key: "CLICKHOUSE_PASSWORD",
										},
									},
								},
							},
						},
					},
				},
			},
			user: "migrate",
			secretRef: corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "migrate-credentials",
				},
				Key: "CLICKHOUSE_PASSWORD",
			},
		},
		"no username": {
			pod: corev1.Pod{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name: "migrate",
							Env: []corev1.EnvVar{
								{
									Name: "HUBBLE_TIMESCAPE_CLICKHOUSE_PASSWORD",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "migrate-credentials",
											},
											Key: "CLICKHOUSE_PASSWORD",
										},
									},
								},
							},
						},
					},
				},
			},
			expectErr: true,
		},
		"no password": {
			pod: corev1.Pod{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name: "migrate",
							Env: []corev1.EnvVar{
								{
									Name:  "HUBBLE_TIMESCAPE_CLICKHOUSE_USERNAME",
									Value: "migrate",
								},
							},
						},
					},
				},
			},
			expectErr: true,
		},
		"unexpected container name": {
			pod: corev1.Pod{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name: "other",
							Env: []corev1.EnvVar{
								{
									Name:  "HUBBLE_TIMESCAPE_CLICKHOUSE_USERNAME",
									Value: "migrate",
								},
								{
									Name: "HUBBLE_TIMESCAPE_CLICKHOUSE_PASSWORD",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "migrate-credentials",
											},
											Key: "CLICKHOUSE_PASSWORD",
										},
									},
								},
							},
						},
					},
				},
			},
			expectErr: true,
		},
		"no container": {
			pod: corev1.Pod{
				Spec: corev1.PodSpec{},
			},
			expectErr: true,
		},
	}
	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			user, ref, err := extractMigrateCredentials(&tc.pod)
			if tc.expectErr {
				require.Error(t, err)
				assert.Empty(t, user)
				assert.Nil(t, ref)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.user, user)
				require.NotNil(t, ref)
				assert.Equal(t, tc.secretRef, *ref)
			}
		})
	}
}

var _ timescapeBugtoolKubernetesClient = timescapeMockK8sClient{}

type timescapeMockK8sClient struct {
	execFunc  func(ctx context.Context, namespace string, pod string, container string, command []string) (bytes.Buffer, bytes.Buffer, error)
	getSecret func(ctx context.Context, namespace string, name string, opts metav1.GetOptions) (*corev1.Secret, error)
}

// GetSecret implements timescapeBugtoolKubernetesClient.
func (t timescapeMockK8sClient) GetSecret(ctx context.Context, namespace string, name string, opts metav1.GetOptions) (*corev1.Secret, error) {
	if t.getSecret == nil {
		return nil, errors.New("unexpected GetSecret call")
	}
	return t.getSecret(ctx, namespace, name, opts)
}

// ExecInPodWithStderr implements timescapeBugtoolKubernetesClient.
func (t timescapeMockK8sClient) ExecInPodWithStderr(ctx context.Context, namespace string, pod string, container string, command []string) (bytes.Buffer, bytes.Buffer, error) {
	return t.execFunc(ctx, namespace, pod, container, command)
}
