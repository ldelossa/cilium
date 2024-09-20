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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/blang/semver/v4"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/cilium-cli/sysdump"
	"github.com/cilium/cilium/pkg/versioncheck"
)

// SubmitTimescapeBugtoolTasks takes a list of timescape pods and will submit tasks to collect bugtool output for them
func SubmitTimescapeBugtoolTasks(c *sysdump.Collector, pods []*corev1.Pod, timescapeBugtoolPrefix string, bugtoolFlags []string) error {
	var submitErrors []error
	for _, p := range pods {
		switch p.GetLabels()["app.kubernetes.io/component"] {
		case "server":
			err := submitTimescapeBugtoolTaskForContainer(c, p, "server", timescapeBugtoolTaskConfig{
				prefix:     timescapeBugtoolPrefix,
				extraFlags: bugtoolFlags,
			})
			if err != nil {
				submitErrors = append(submitErrors, err)
			}
		case "ingester":
			err := submitTimescapeBugtoolTaskForContainer(c, p, "ingester", timescapeBugtoolTaskConfig{
				prefix:            timescapeBugtoolPrefix,
				extraFlags:        bugtoolFlags,
				collectClickhouse: true,
			})
			if err != nil {
				submitErrors = append(submitErrors, err)
			}
		case "lite":
			err := submitTimescapeBugtoolTaskForContainer(c, p, "timescape", timescapeBugtoolTaskConfig{
				prefix:            timescapeBugtoolPrefix,
				extraFlags:        bugtoolFlags,
				collectClickhouse: true,
			})
			if err != nil {
				submitErrors = append(submitErrors, err)
			}
		case "trimmer", "database":
			// The trimmer is a job and can't give us bugtool output
			// The database pod is ClickHouse, we can't get bugtool output either
		default:
			// Unknown component
			submitErrors = append(submitErrors, fmt.Errorf("unexpected timescape pod %s/%s, skipping", p.GetNamespace(), p.GetName()))
		}
	}
	return errors.Join(submitErrors...)
}

type timescapeBugtoolTaskConfig struct {
	prefix     string
	extraFlags []string

	collectClickhouse bool
}

func submitTimescapeBugtoolTaskForContainer(c *sysdump.Collector, p *corev1.Pod, containerName string, cfg timescapeBugtoolTaskConfig) error {
	workerID := fmt.Sprintf("%s-%s-%s-%s", cfg.prefix, p.Namespace, p.Name, containerName)
	if err := c.Pool.Submit(workerID, func(ctx context.Context) error {
		var errs error

		out, err := runTimescapeBugtool(ctx, c.Client, p.Namespace, p.Name, containerName, cfg)
		if err != nil {
			// Even if the bugtool run failed, there might be valid partial output,
			// let's still try to capture it
			errs = errors.Join(errs, err)
		}

		// Extract content
		dir := c.AbsoluteTempPath(fmt.Sprintf("%s-<ts>", workerID))
		if err := untarTo(out, dir); err != nil {
			errs = errors.Join(errs, err)
		}

		if errs != nil {
			return fmt.Errorf("failure collecting 'timescape-bugtool' output for %q in namespace %q, the output might be missing or incomplete:\n %w", p.Name, p.Namespace, errs)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to submit 'timescape-bugtool' task for %q: %w", p.Name, err)
	}
	return nil
}

type timescapeBugtoolKubernetesClient interface {
	ExecInPodWithStderr(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, bytes.Buffer, error)
}

func runTimescapeBugtool(ctx context.Context, c timescapeBugtoolKubernetesClient, namespace string, name string, containerName string, cfg timescapeBugtoolTaskConfig) (io.Reader, error) {
	var errs error
	command := []string{"/usr/bin/hubble-timescape", "bugtool", "--out", "-"}

	if cfg.collectClickhouse {
		// Only available since v1.5.0
		// Check timescape version to decide what flags are valid
		v, err := getTimescapeVersion(ctx, c, namespace, name, containerName)
		if err != nil {
			// If there is an error collect it and treat it as the most recent version
			errs = errors.Join(errs, fmt.Errorf("failed to get timescape version, continuing with most recent version: %w", err))
		}
		if v == nil || versioncheck.MustCompile(">=1.5.0")(*v) {
			command = append(command, "--collect-clickhouse-stats")
		}
	}

	command = append(command, cfg.extraFlags...)
	// Run 'hubble-timescape bugtool' in the pod and collect stdout
	out, e, err := c.ExecInPodWithStderr(ctx, namespace, name, containerName, command)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed run 'timescape bugtool': %w:\n%s", err, e.String()))
	}
	return &out, errs
}

func getTimescapeVersion(ctx context.Context, c timescapeBugtoolKubernetesClient, namespace string, name string, containerName string) (*semver.Version, error) {
	o, _, err := c.ExecInPodWithStderr(
		ctx,
		namespace,
		name,
		containerName,
		[]string{"/usr/bin/hubble-timescape", "version"},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch timescape version of pod %q: %w", name, err)
	}

	// The version string is of the form
	// hubble-timescape 1.x.x compiled with go1.xx.x on linux/amd64
	// Take the second field and try to parse it
	fields := strings.Fields(strings.TrimSpace(o.String()))
	if len(fields) < 2 {
		return nil, fmt.Errorf("unable to parse timescape version %q of pod %q: %w", o, name, err)
	}
	v, _, _ := strings.Cut(strings.TrimSpace(fields[1]), "-") // strips proprietary -releaseX suffix
	podVersion, err := semver.ParseTolerant(v)
	if err != nil {
		return nil, fmt.Errorf("unable to parse timescape version %q of pod %q: %w", o, name, err)
	}

	return &podVersion, nil
}

func untarTo(in io.Reader, dst string) error {
	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		// Bugtool tar files don't contain headers for
		// directories, so create a directory for each file instead.
		if header.Typeflag != tar.TypeReg {
			continue
		}
		name, err := removeTopDirectory(header.Name)
		if err != nil {
			return nil
		}
		filename := filepath.Join(dst, name)
		directory := filepath.Dir(filename)
		if err := os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		f, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
		if err != nil {
			return err
		}
		if err = copyN(f, tr, 1024); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
}

func removeTopDirectory(path string) (string, error) {
	// file separator hardcoded because sysdump always created on Linux OS
	index := strings.IndexByte(path, '/')
	if index < 0 {
		return "", fmt.Errorf("invalid path %q", path)
	}
	return path[index+1:], nil
}

// copyN copies from src to dst n bytes at a time to avoid this lint error:
// G110: Potential DoS vulnerability via decompression bomb (gosec)
func copyN(dst io.Writer, src io.Reader, n int64) error {
	for {
		_, err := io.CopyN(dst, src, n)
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
	}
}
