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
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/cilium-cli/sysdump"

	corev1 "k8s.io/api/core/v1"
)

// SubmitTimescapeBugtoolTasks takes a list of timescape pods and will submit tasks to collect bugtool output for them
func SubmitTimescapeBugtoolTasks(c *sysdump.Collector, pods []*corev1.Pod, timescapeBugtoolPrefix string, bugtoolFlags []string) error {
	var submitErrors []error
	for _, p := range pods {
		switch p.GetLabels()["app.kubernetes.io/component"] {
		case "server":
			err := submitTimescapeBugtoolTaskForContainer(c, p, "server", timescapeBugtoolPrefix, bugtoolFlags)
			if err != nil {
				submitErrors = append(submitErrors, err)
			}
		case "ingester":
			err := submitTimescapeBugtoolTaskForContainer(c, p, "ingester", timescapeBugtoolPrefix, bugtoolFlags)
			if err != nil {
				submitErrors = append(submitErrors, err)
			}
		case "lite":
			err := submitTimescapeBugtoolTaskForContainer(c, p, "timescape", timescapeBugtoolPrefix, bugtoolFlags)
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
func submitTimescapeBugtoolTaskForContainer(c *sysdump.Collector, p *corev1.Pod, containerName string, timescapeBugtoolPrefix string, bugtoolFlags []string) error {
	workerID := fmt.Sprintf("%s-%s-%s-%s", timescapeBugtoolPrefix, p.Namespace, p.Name, containerName)
	if err := c.Pool.Submit(workerID, func(ctx context.Context) error {

		// Run 'hubble-timescape bugtool' in the pod and collect stdout
		command := append([]string{"/usr/bin/hubble-timescape", "bugtool", "--out", "-"}, bugtoolFlags...)

		out, e, err := c.Client.ExecInPodWithStderr(ctx, p.Namespace, p.Name, containerName, command)
		if err != nil {
			return fmt.Errorf("failed to collect 'timescape-bugtool' output for %q in namespace %q: %w:\n%s", p.Name, p.Namespace, err, e.String())
		}

		// Extract content
		dir := c.AbsoluteTempPath(fmt.Sprintf("%s-<ts>", workerID))
		if err := untarTo(&out, dir); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to submit 'timescape-bugtool' task for %q: %w", p.Name, err)
	}
	return nil
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
