// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	enterpriseK8s "github.com/cilium/cilium/cilium-cli/enterprise/hooks/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/wait"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/time"
)

const (
	MulticastLabelKey = "multicast"
	SourceLabel       = "source"
	SubscriberLabel   = "subscriber"
)

var (
	testOutputFile       = "/tmp/group_%s_test"
	testMulticastUDPPort = 6789
	testTimeout          = 30 * time.Second
)

var (
	sourceLabelSelector     = fmt.Sprintf("%s=%s", MulticastLabelKey, SourceLabel)
	subscriberLabelSelector = fmt.Sprintf("%s=%s", MulticastLabelKey, SubscriberLabel)
)

func MulticastConnectivity(clients []*enterpriseK8s.EnterpriseClient, numMsg int) check.Scenario {
	return &multicastConnectivity{
		entClients:  clients,
		numMessages: numMsg,
	}
}

type multicastConnectivity struct {
	entClients  []*enterpriseK8s.EnterpriseClient
	numMessages int
}

func (m *multicastConnectivity) Name() string {
	return "multicast-connectivity"
}

func (m *multicastConnectivity) Run(ctx context.Context, t *check.Test) {
	t.Logf("Running multicast connectivity test")
	defer t.Logf("Finished multicast connectivity test")

	// get multicast groups from configured IsovlanetMulticastGroup resource
	groups, err := getMulticastGroups(ctx, t, m.entClients)
	if err != nil {
		t.Fatalf("Failed to get multicast groups: %v", err)
	}
	t.Debugf("Number of configured groups %d", len(groups))

	// validate BPF group map, groups should already be populated based on the IsovalentMulticastGroup resource
	t.Debugf("Validating multicast group map entries...")
	err = waitForBpfEntries(ctx, func() error {
		return validateBpfGroupEntries(ctx, t, groups)
	})
	if err != nil {
		t.Fatalf("Failed to validate multicast groups: %v", err)
	}

	// get subscriber multicast pods, these are identified by subscriberLabelSelector
	subscriberPods, err := getMulticastPods(ctx, t, subscriberLabelSelector)
	if err != nil {
		t.Fatalf("Failed to get multicast subscriber pods: %v", err)
	}
	t.Debugf("Number of subscriber pods %d", len(subscriberPods))

	// Start multicast listeners, they join the groups by sending out IGMP join message and any traffic sent to the
	// multicast group will be received by these pods.
	killCtx, cancel := context.WithCancel(ctx)
	defer func() {
		// cancel the context to stop the socat listeners
		t.Debugf("Closing socat listeners")
		cancel()
	}()

	t.Debugf("Subscribers joining multicast groups...")
	err = startMulticastListeners(ctx, killCtx, t, subscriberPods, groups)
	if err != nil {
		t.Fatalf("Failed to send multicast joins: %v", err)
	}

	// Check Cilium datapath, since pods would have sent out IGMP join messages, we should see the multicast BPF map
	// entries being populated with the subscribers.
	t.Debugf("Validating multicast subscriber map entries...")
	err = waitForBpfEntries(ctx, func() error {
		return validateBpfSubscriberEntries(ctx, t, subscriberPods, groups)
	})
	if err != nil {
		t.Fatalf("Failed to validate multicast subscribers: %v", err)
	}

	// get multicast source pods, these are identified by sourceLabelSelector
	sourcePods, err := getMulticastPods(ctx, t, sourceLabelSelector)
	if err != nil {
		t.Fatalf("Failed to get multicast source pods: %v", err)
	}
	t.Debugf("Number of source pods %d", len(sourcePods))

	// send multicast traffic from source pods to the multicast groups
	t.Debugf("Sending multicast traffic...")
	err = sendMulticastTraffic(ctx, t, sourcePods, groups, m.numMessages)
	if err != nil {
		t.Fatalf("Failed to send multicast traffic: %v", err)
	}

	t.Debugf("Validating multicast messages on subscriber pods...")
	err = validateMulticastMessages(ctx, t, sourcePods, subscriberPods, groups, m.numMessages)
	if err != nil {
		t.Fatalf("Failed multicast message validation: %v", err)
	}
}

// Group check test only validates groups are created and BPF map entries are populated, it does not send multicast traffic.

type multicastGroupCheck struct {
	entClients []*enterpriseK8s.EnterpriseClient
}

func (m *multicastGroupCheck) Name() string {
	return "multicast-group-check"
}

func MulticastGroupCheck(entClients []*enterpriseK8s.EnterpriseClient) check.Scenario {
	return &multicastGroupCheck{
		entClients: entClients,
	}
}

func (m *multicastGroupCheck) Run(ctx context.Context, t *check.Test) {
	t.Logf("Running multicast group test")
	defer t.Logf("Finished multicast group test")

	// get multicast groups from configured IsovlanetMulticastGroup resource
	groups, err := getMulticastGroups(ctx, t, m.entClients)
	if err != nil {
		t.Fatalf("Failed to get multicast groups: %v", err)
	}
	t.Debugf("Number of configured groups %d", len(groups))

	// validate BPF group map, groups should already be populated based on the IsovalentMulticastGroup resource
	t.Debugf("Validating multicast group map entries...")
	err = waitForBpfEntries(ctx, func() error {
		return validateBpfGroupEntries(ctx, t, groups)
	})
	if err != nil {
		t.Fatalf("Failed to validate multicast groups: %v", err)
	}

	// get subscriber multicast pods, these are identified by subscriberLabelSelector
	subscriberPods, err := getMulticastPods(ctx, t, subscriberLabelSelector)
	if err != nil {
		t.Fatalf("Failed to get multicast subscriber pods: %v", err)
	}
	t.Debugf("Number of subscriber pods %d", len(subscriberPods))

	// Start multicast listeners, they join the groups by sending out IGMP join message and any traffic sent to the
	// multicast group will be received by these pods.
	killCtx, cancel := context.WithCancel(ctx)
	defer func() {
		// cancel the context to stop the socat listeners
		t.Debugf("Closing socat listeners")
		cancel()
	}()

	t.Debugf("Subscribers joining multicast groups...")
	err = startMulticastListeners(ctx, killCtx, t, subscriberPods, groups)
	if err != nil {
		t.Fatalf("Failed to send multicast joins: %v", err)
	}

	// Check Cilium datapath, since pods would have sent out IGMP join messages, we should see the multicast BPF map
	// entries being populated with the subscribers.
	t.Debugf("Validating multicast subscriber map entries...")
	err = waitForBpfEntries(ctx, func() error {
		return validateBpfSubscriberEntries(ctx, t, subscriberPods, groups)
	})
	if err != nil {
		t.Fatalf("Failed to validate multicast subscribers: %v", err)
	}
}

func getMulticastGroups(ctx context.Context, t *check.Test, entClients []*enterpriseK8s.EnterpriseClient) ([]string, error) {
	var result []string

	for _, client := range entClients {
		groups, err := client.ListIsovalentMulticastGroups(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list multicast groups: %v", err)
		}

		for _, groupResource := range groups.Items {
			for _, groupAddr := range groupResource.Spec.GroupAddrs {
				result = append(result, string(groupAddr))
			}
		}
	}

	return result, nil
}

func getMulticastPods(ctx context.Context, t *check.Test, selector string) (map[string]check.Pod, error) {
	ct := t.Context()
	allPods := make(map[string]check.Pod)

	for _, client := range ct.Clients() {
		pods, err := client.ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return nil, fmt.Errorf("failed to list pods: %v", err)
		}

		for _, pod := range pods.Items {
			allPods[pod.Name] = check.Pod{
				K8sClient: client,
				Pod:       pod.DeepCopy(),
			}
		}
	}

	return allPods, nil
}

func startMulticastListeners(ctx, killCtx context.Context, t *check.Test, subscriberPods map[string]check.Pod, groupAddrs []string) error {
	// create ip route to join multicast groups
	for _, pod := range subscriberPods {
		for i, group := range groupAddrs {
			pod := pod
			group := group
			groupUDPPort := testMulticastUDPPort + i
			go func() {
				testFile := fmt.Sprintf(testOutputFile, group)
				cmd := strings.Split(fmt.Sprintf("socat UDP4-RECVFROM:%d,ip-add-membership=%s:0.0.0.0,fork OPEN:%s,creat,append", groupUDPPort, group, testFile), " ")

				// start socat to listen on multicast group in background
				err := pod.K8sClient.ExecInPodWithWriters(ctx, killCtx, pod.Pod.Namespace, pod.Pod.Name, "", cmd, io.Discard, io.Discard)
				if err != nil {
					// if killCtx is canceled, we can return
					if killCtx.Err() != nil && killCtx.Err() == context.Canceled {
						return
					}
					t.Fatalf("Failed to start socat in pod %s: %v", pod.Name(), err)
				}
			}()
		}
	}
	return nil
}

func sendMulticastTraffic(ctx context.Context, t *check.Test, sourcePods map[string]check.Pod, groupAddrs []string, numOfMessages int) error {
	var wg sync.WaitGroup
	errCh := make(chan error)

	// number of concurrent senders
	wg.Add(len(sourcePods))

	for _, sourcePod := range sourcePods {
		pod := sourcePod
		groupAddrs := groupAddrs

		go func() {
			defer wg.Done()
			for i, group := range groupAddrs {
				groupUDPPort := testMulticastUDPPort + i
				for i := 0; i < numOfMessages; i++ {
					message := fmt.Sprintf("%s_%s_%d", pod.Pod.Name, group, i)
					socatSend := fmt.Sprintf(`echo %s | socat -u - UDP4-DATAGRAM:%s:%d`, message, group, groupUDPPort)
					actualCmd := []string{"bash", "-c", socatSend}

					_, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name, "", actualCmd)
					if err != nil {
						errCh <- err
						return
					}
				}
			}
			errCh <- nil
		}()
	}

	// close errCh when all pods are done sending
	go func() {
		wg.Wait()
		close(errCh)
	}()

	for err := range errCh {
		if err != nil {
			return err
		}
	}

	return nil
}

type Subscriber struct {
	// Source address of subscriber in big endian format
	SAddr netip.Addr
	// Interface ID of subscriber, may be a tunnel interface if subscriber
	// is remote.
	Ifindex uint32
	// Specifies if the subscriber is remote or local
	IsRemote bool
}

// multicast BPF data will be in this format
type subscriberData struct {
	GroupAddr   netip.Addr   `json:"group_address"`
	Subscribers []Subscriber `json:"subscribers"`
}

func waitForBpfEntries(ctx context.Context, f func() error) error {
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: testTimeout})
	defer w.Cancel()

	for {
		if err := f(); err != nil {
			if err := w.Retry(err); err != nil {
				return fmt.Errorf("Failed to validate BPF map entries: %v", err)
			}
			continue
		}
		return nil
	}
}

func validateBpfGroupEntries(ctx context.Context, t *check.Test, groupAddrs []string) error {
	ct := t.Context()

	// per cilium pod
	for _, ciliumPod := range ct.CiliumPods() {
		runningEntries, err := getGroupMapEntries(ctx, t, ciliumPod)
		if err != nil {
			return fmt.Errorf("failed to get running multicast BPF map entries: %v", err)
		}

		expectedEntries := make([]string, len(groupAddrs))
		for i, group := range groupAddrs {
			expectedEntries[i] = group
		}

		// check if the expected entries are present
		runningEntriesSet := sets.New[string]()
		expectedEntriesSet := sets.New[string]()

		for _, group := range runningEntries {
			runningEntriesSet.Insert(group)
		}
		for _, group := range expectedEntries {
			expectedEntriesSet.Insert(group)
		}

		if !runningEntriesSet.Equal(expectedEntriesSet) {
			return fmt.Errorf("mismatch in BPF multicast group map: expected %v, got %v", expectedEntriesSet, runningEntriesSet)
		}
	}

	return nil
}

func validateBpfSubscriberEntries(ctx context.Context, t *check.Test, subscriberPods map[string]check.Pod, groupAddrs []string) error {
	ct := t.Context()

	// per cilium pod
	for _, ciliumPod := range ct.CiliumPods() {
		runningEntries, err := getSubscriberMapEntries(ctx, t, ciliumPod)
		if err != nil {
			return fmt.Errorf("failed to get running multicast BPF map entries: %v", err)
		}

		expectedEntries, err := expectedEntries(ctx, t, ciliumPod, subscriberPods, groupAddrs)
		if err != nil {
			return fmt.Errorf("failed to get expected multicast BPF map entries: %v", err)
		}

		// check if the expected entries are present
		err = validateMulticastEntries(t, ciliumPod, runningEntries, expectedEntries)
		if err != nil {
			return fmt.Errorf("mismatch in multicast BPF map entries: %w", err)
		}
	}

	return nil
}

func getGroupMapEntries(ctx context.Context, t *check.Test, ciliumPod check.Pod) ([]string, error) {
	cmd := strings.Split("cilium bpf multicast group list -o json", " ")
	stdout, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, cmd)
	if err != nil {
		t.Fatal("failed to run cilium bpf multicast group list command: %w", err)
	}

	var entries []string
	if err := json.Unmarshal(stdout.Bytes(), &entries); err != nil {
		t.Fatalf("failed to unmarshal cilium bpf multicast group list output: %w", err)
	}

	return entries, nil
}

func getSubscriberMapEntries(ctx context.Context, t *check.Test, ciliumPod check.Pod) ([]subscriberData, error) {
	cmd := strings.Split("cilium bpf multicast subscriber list all -o json", " ")
	stdout, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, cmd)
	if err != nil {
		t.Fatal("failed to run cilium bpf multicast subscriber list all command: %w", err)
	}

	var entries []subscriberData
	if err := json.Unmarshal(stdout.Bytes(), &entries); err != nil {
		t.Fatalf("failed to unmarshal cilium bpf multicast subscriber list all output: %w", err)
	}

	return entries, nil
}

func expectedEntries(ctx context.Context, t *check.Test, ciliumPod check.Pod, subscriberPods map[string]check.Pod, groupAddrs []string) ([]subscriberData, error) {
	ct := t.Context()

	var expectedEntries []subscriberData
	for _, group := range groupAddrs {
		addr, err := netip.ParseAddr(group)
		if err != nil {
			return nil, fmt.Errorf("failed to parse group address: %v", err)
		}

		expectedEntries = append(expectedEntries, subscriberData{
			GroupAddr: addr,
		})
	}

	for _, subPod := range subscriberPods {
		for i := range expectedEntries {
			isRemote := subPod.NodeName() != ciliumPod.NodeName()
			sAddr, err := netip.ParseAddr(subPod.Pod.Status.PodIP)
			if err != nil {
				return nil, fmt.Errorf("failed to parse subscriber pod IP: %v", err)
			}

			if isRemote {
				// sAddr will be the remote node's IP. Remote node is node on which the subscriber pod is running.
				remoteNode, ok := ct.CiliumNodes()[check.NodeIdentity{ct.K8sClient().ClusterName(), subPod.NodeName()}]
				if !ok {
					return nil, fmt.Errorf("failed to get node %s", subPod.NodeName())
				}
				sAddr, err = netip.ParseAddr(remoteNode.GetIP(false).String())
				if err != nil {
					return nil, fmt.Errorf("failed to parse remote node IP: %v", err)
				}
			}

			expectedEntries[i].Subscribers = append(expectedEntries[i].Subscribers, Subscriber{
				SAddr:    sAddr,
				IsRemote: isRemote,
			})
		}
	}

	return expectedEntries, nil
}

func validateMulticastEntries(t *check.Test, ciliumPod check.Pod, runningGroups, expectedGroups []subscriberData) error {
	if len(runningGroups) != len(expectedGroups) {
		return fmt.Errorf("mismatch in number of multicast groups: expected %d, got %d", len(expectedGroups), len(runningGroups))
	}

	// validate groups are equal
	runningGroupsSet := sets.New[netip.Addr]()
	expectedGroupsSet := sets.New[netip.Addr]()

	for _, group := range runningGroups {
		runningGroupsSet.Insert(group.GroupAddr)
	}
	for _, group := range expectedGroups {
		expectedGroupsSet.Insert(group.GroupAddr)
	}

	if !runningGroupsSet.Equal(expectedGroupsSet) {
		return fmt.Errorf("mismatch in multicast groups: expected %v, got %v", expectedGroupsSet, runningGroups)
	}

	// validate subscribers are equal for each group
nextGroup:
	for _, runningGroup := range runningGroups {
		for _, expectedGroup := range expectedGroups {
			if runningGroup.GroupAddr == expectedGroup.GroupAddr {
				// we only need to match on subset of data from BPF map, ignoring ifindex.
				type matchData struct {
					SAddr    netip.Addr
					IsRemote bool
				}

				runningSubscribersSet := sets.New[matchData]()
				expectedSubscribersSet := sets.New[matchData]()

				for _, subscriber := range runningGroup.Subscribers {
					runningSubscribersSet.Insert(matchData{
						SAddr:    subscriber.SAddr,
						IsRemote: subscriber.IsRemote,
					})
				}
				for _, subscriber := range expectedGroup.Subscribers {
					expectedSubscribersSet.Insert(matchData{
						SAddr:    subscriber.SAddr,
						IsRemote: subscriber.IsRemote,
					})
				}

				if !runningSubscribersSet.Equal(expectedSubscribersSet) {
					return fmt.Errorf("mismatch in multicast subscribers in %s for group %s: expected %v, got %v", ciliumPod.NodeName(), expectedGroup.GroupAddr, expectedSubscribersSet, runningSubscribersSet)
				}
				continue nextGroup
			}
		}
	}

	return nil
}

// validateMulticastMessages validates the multicast messages received by subscriber pods. It validates the following:
// 1. Each subscriber pod should receive all messages from each source pod.
//   - Each source pod sends numOfMessages messages to each multicast group.
//   - Each subscriber pod should receive numOfMessages messages from each source pod for each multicast group.
//
// 2. The order of messages received from each source pod.
//   - Each source pod sends messages sequentially.
//   - Message contains the source pod name, group IP and messageID, separated by '_'.
//   - Order of messages from each source pod should be preserved. However, messages between different source pods can be interleaved.
func validateMulticastMessages(ctx context.Context, t *check.Test, sourcePods, subscriberPods map[string]check.Pod, groupAddrs []string, numOfMessages int) error {
	// validate group files present in subscriber pods
	subscriberPodMessages, err := getMulticastMessageFiles(ctx, t, subscriberPods, groupAddrs)
	if err != nil {
		return fmt.Errorf("failed to get multicast message files: %v", err)
	}

	// validate each group file contains messages from source pods ( number of messages from each source pod and order of messages)
	err = validateMulticastMessageFile(t, sourcePods, subscriberPodMessages, groupAddrs, numOfMessages)
	if err != nil {
		return fmt.Errorf("multicast message file validation failed: %v", err)
	}

	return nil
}

type multicastMessage struct {
	SourcePodName string
	Group         string
	MessageID     int
}

func (m multicastMessage) String() string {
	return fmt.Sprintf("(s,g) (%s,%s), MessageID: %d", m.SourcePodName, m.Group, m.MessageID)
}

func getMulticastMessageFiles(ctx context.Context, t *check.Test, subscriberPods map[string]check.Pod, groupAddrs []string) (map[string][]multicastMessage, error) {
	subscriberPodMessages := make(map[string][]multicastMessage) // key is subscriber pod name

	for _, pod := range subscriberPods {
		for _, group := range groupAddrs {
			testFile := fmt.Sprintf(testOutputFile, group)
			cmd := strings.Split(fmt.Sprintf("cat %s", testFile), " ")
			stdout, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name, "", cmd)
			if err != nil {
				// if the file is not present, log files which are present
				if strings.Contains(err.Error(), "No such file or directory") {
					filesCmd := strings.Split("ls -la /tmp", " ")
					files, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name, "", filesCmd)
					if err != nil {
						return nil, fmt.Errorf("failed to list files in pod %s: %v", pod.Name(), err)
					}
					t.Logf("Multicast log files in pod %s: %s", pod.Name(), files.String())
				}

				return nil, fmt.Errorf("failed to read multicast file %s from pod %s: %v", testFile, pod.Name(), err)
			}

			lines := strings.Split(string(stdout.Bytes()), "\n")
			for _, line := range lines {
				if line == "" {
					continue
				}
				parts := strings.Split(line, "_")
				if len(parts) != 3 {
					return nil, fmt.Errorf("invalid multicast message format: %s", line)
				}
				podNameFromMsg := parts[0]
				groupFromMsg := parts[1]
				if groupFromMsg != group {
					return nil, fmt.Errorf("invalid multicast message, expected group %s, got %s", group, groupFromMsg)
				}

				messageID, err := strconv.Atoi(parts[2])
				if err != nil {
					return nil, fmt.Errorf("invalid multicast messageID format: %s", line)
				}

				subscriberPodMessages[pod.Name()] = append(subscriberPodMessages[pod.Name()], multicastMessage{
					SourcePodName: podNameFromMsg,
					Group:         group,
					MessageID:     messageID,
				})
			}
		}
	}

	return subscriberPodMessages, nil
}

func validateMulticastMessageFile(t *check.Test, sourcePods map[string]check.Pod, subscriberPods map[string][]multicastMessage, groupAddrs []string, numOfMessages int) error {
	// validate each group file contains messages from source pods ( number of messages from each source pod and order of messages)
	for _, subscriberPodMsgs := range subscriberPods {
		expectedSourceMsgs := make(map[string]map[string]int) // key is source pod name, value is map of group to current messageID

		// initialize expectedSourceMsgs
		for sourcePodName := range sourcePods {
			expectedSourceMsgs[sourcePodName] = make(map[string]int)
			for _, group := range groupAddrs {
				expectedSourceMsgs[sourcePodName][group] = 0 // initial messageID
			}
		}

		// validate messages received in correct order from each source pod.
		for _, msg := range subscriberPodMsgs {
			// validate message from source pod
			expectedGroupMsg, ok := expectedSourceMsgs[msg.SourcePodName]
			if !ok {
				return fmt.Errorf("invalid multicast message from unknown source pod %s", msg.SourcePodName)
			}

			expectedMsgID, ok := expectedGroupMsg[msg.Group]
			if !ok {
				return fmt.Errorf("invalid multicast message from %s, unknown group %s", msg.SourcePodName, msg.Group)
			}

			if msg.MessageID != expectedMsgID {
				return fmt.Errorf("invalid multicast message order from (s,g) (%s,%s), expected messageID %d, got %d", msg.SourcePodName, msg.Group, expectedSourceMsgs[msg.SourcePodName][msg.Group], msg.MessageID)
			}

			expectedSourceMsgs[msg.SourcePodName][msg.Group] = expectedMsgID + 1 // increment expected messageID
		}

		// validate all messages received from each source
		for sourcePodName, groupMsgs := range expectedSourceMsgs {
			for group, msgID := range groupMsgs {
				if msgID != numOfMessages {
					return fmt.Errorf("subscriber pod %s did not receive all messages from (s,g) (%s,%s), expected %d, got %d", sourcePodName, group, numOfMessages, msgID)
				}
			}
		}
	}

	return nil
}

func GenerateMulticastGroups(prefix string, groups int) []isovalentv1alpha1.MulticastGroupAddr {
	var groupAddrs []isovalentv1alpha1.MulticastGroupAddr
	addr := netip.MustParseAddr(prefix)

	for i := 0; i < groups; i++ {
		next := addr.Next()
		if next.Is4() && next.IsMulticast() {
			addr = next
			groupAddrs = append(groupAddrs, isovalentv1alpha1.MulticastGroupAddr(addr.String()))
		}
	}

	return groupAddrs
}
