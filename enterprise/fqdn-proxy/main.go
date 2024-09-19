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
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/cilium/dns"
	"github.com/cilium/workerpool"
	gops "github.com/google/gops/agent"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	_ "github.com/cilium/cilium/enterprise/fips"
	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/cilium/pkg/version"
)

const (
	metricsNamespace  = "isovalent"
	clientConnRetries = 24
)

var (
	debug                      = flag.Bool("debug", false, "")
	gopsPort                   = flag.Int("gops-port", 8910, "Port for gops server to listen on")
	enablePprof                = flag.Bool("pprof", false, "Enable serving the pprof debugging API")
	pprofPort                  = flag.Int("pprof-port", 8920, "Port that the pprof listens on")
	pprofAddress               = flag.String("pprof-address", "localhost", "Address that pprof listens on")
	enableIPV6                 = flag.Bool("enable-ipv6", true, "")
	enableIPV4                 = flag.Bool("enable-ipv4", true, "")
	enableDNSCompression       = flag.Bool("enable-dns-compression", true, "Allow the DNS proxy to compress responses to endpoints that are larger than 512 Bytes or the EDNS0 option, if present")
	exposePrometheusMetrics    = flag.Bool("expose-metrics", false, "")
	prometheusPort             = flag.Int("prometheus-port", 9967, "")
	DNSNotificationSendWorkers = flag.Int("dns-notification-retry-workers", 128, "")
	DNSNotificationChannelSize = flag.Int("dns-notification-channel-size", 16384, "This is the number of DNS messages that will generate a notification in Cilium Agent after it restarts. All DNS messages above this limit will be handled by proxy, but not generate notification after Cilium Agent restarts.")
	FQDNProxyResponseMaxDelay  = flag.Duration("tofqdns-proxy-response-max-delay", 150*time.Millisecond, "The maximum time the DNS proxy holds an allowed DNS response before sending it along. Responses are sent as soon as the datapath is updated with the new IP information.")
	concurrencyLimit           = flag.Int("concurrency-limit", 0, "concurrency limit for dns proxy (0 for infinite)")
	concurrencyGracePeriod     = flag.Duration("concurrency-processing-grace-period", 0, "Grace time to wait when DNS proxy concurrent limit has been reached during DNS message processing")
	FQDNRegexCompileLRUSize    = flag.Int("fqdn-regex-compile-lru-size", 1024, "Size of the FQDN regex compilation LRU. Useful for heavy but repeated DNS L7 rules with MatchName or MatchPattern")
	ToFQDNSRejectResponseCode  = flag.String("tofqdns-dns-reject-response-code", "refused", "DNS response code for rejecting DNS requests, available options are '[nameError refused]' (default \"refused\")")

	DNSProxyEnableTransparentMode = flag.Bool("dnsproxy-enable-transparent-mode", false, "")
	DNSProxySocketLingerTimeout   = flag.Int("dnsproxy-socket-linger-timeout", defaults.DNSProxySocketLingerTimeout, "Timeout (in seconds) when closing the connection between the DNS proxy and the upstream server."+
		"If set to 0, the connection is closed immediately (with TCP RST). If set to -1, the connection is closed asynchronously in the background")

	proxy     *dnsproxy.DNSProxy
	clientPtr atomic.Pointer[fqdnAgentClient]
	client    = clientPtr.Load
	cache     AgentDataCache

	DNSNotificationQueue             chan *pb.DNSNotification
	DNSNotificationSendRetryInterval = 10 * time.Second
	DNSNotificationSendTimeout       = 5 * time.Second

	// Metrics
	defaultSummaryObjectives = map[float64]float64{
		0.5:  0.05,
		0.9:  0.01,
		0.99: 0.001,
	}
	ProxyUpdateErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "update_errors_total",
		Namespace: metricsNamespace,
		Subsystem: "external_dns_proxy",
		Help:      "Number of total cilium DNS notification errors during FQDN IP updates",
	}, []string{"error"})
	ProxyUpdateQueueLen = promauto.NewGauge(prometheus.GaugeOpts{
		Name:      "update_queue_size",
		Namespace: metricsNamespace,
		Subsystem: "external_dns_proxy",
		Help:      "Size of the queue for deferred DNS notifications to the cilium-agent",
	})
	ProcessingTime = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name:       "processing_duration_seconds",
		Namespace:  metricsNamespace,
		Subsystem:  "external_dns_proxy",
		Help:       "Seconds spent processing DNS transactions",
		Objectives: defaultSummaryObjectives,
	}, []string{"error"})
	UpstreamTime = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name:       "upstream_duration_seconds",
		Namespace:  metricsNamespace,
		Subsystem:  "external_dns_proxy",
		Help:       "Seconds waited to get a reply from a upstream server",
		Objectives: defaultSummaryObjectives,
	}, []string{"error"})
	PolicyTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "policy_l7_total",
		Namespace: metricsNamespace,
		Subsystem: "external_dns_proxy",
		Help:      "Number of total proxy requests handled",
	}, []string{"rule"})
	Version = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "version",
		Help:      "FQDN Proxy version",
	}, []string{"version"})

	// Metrics labels
	metricErrorTimeout  = "timeout"
	metricErrorProxy    = "proxyErr"
	metricErrorPacking  = "serialization failed"
	metricErrorNoEP     = "noEndpoint"
	metricErrorOverflow = "queueOverflow"
	metricErrorAllow    = "allow"
	LogInfoTrigger      *trigger.Trigger
	LogWarningTrigger   *trigger.Trigger
	LogAgentDownTrigger *trigger.Trigger
	LogDebugTrigger     *trigger.Trigger
)

// Encapsulates the FQDNProxyAgentClient behavior but provides
// a concrete type to allow correct usage of atomic.Swap for
// client resets.
type fqdnAgentClient struct {
	pb.FQDNProxyAgentClient
	conn *grpc.ClientConn
}

func init() {
	var err error
	if LogWarningTrigger, err = trigger.NewTrigger(trigger.Parameters{
		MinInterval: time.Minute,
		TriggerFunc: logTriggerFunc(log.Warning),
		Name:        "ProxyLogWarning",
	}); err != nil {
		log.WithError(err).Error("failed to create proxylogwarning trigger")
	}
	if LogAgentDownTrigger, err = trigger.NewTrigger(trigger.Parameters{
		MinInterval: time.Minute,
		TriggerFunc: logTriggerFunc(log.Warning),
		Name:        "AgentDownLogWarning",
	}); err != nil {
		log.WithError(err).Error("failed to create agentdownlogwarning trigger")
	}
	if LogDebugTrigger, err = trigger.NewTrigger(trigger.Parameters{
		MinInterval: time.Minute,
		TriggerFunc: logTriggerFunc(log.Debug),
		Name:        "DebugLog",
	}); err != nil {
		log.WithError(err).Error("failed to create debuglog trigger")
	}
	if LogInfoTrigger, err = trigger.NewTrigger(trigger.Parameters{
		MinInterval: time.Minute,
		TriggerFunc: logTriggerFunc(log.Info),
		Name:        "InfoLog",
	}); err != nil {
		log.WithError(err).Error("failed to create infolog trigger")
	}
}

func logTriggerFunc(log func(args ...interface{})) func([]string) {
	return func(msgs []string) {
		for _, msg := range msgs {
			log(msg)
		}
	}
}

func main() {
	flag.Parse()

	log.Info("     _ _ _")
	log.Info(" ___|_| |_|_ _ _____")
	log.Info("|  _| | | | | |     |")
	log.Info("|___|_|_|_|___|_|_|_|")
	log.Infof("Cilium DNS Proxy %s", version.Version)

	if debug != nil && *debug {
		log.Logger.SetLevel(logrus.DebugLevel)
		log.Debug("enabling debug logging")
	}

	// emulate viper's env var parsing
	if val, ok := os.LookupEnv("CILIUM_ENABLE_IPV4"); ok {
		if val == "true" {
			*enableIPV4 = true
		} else if val == "false" {
			*enableIPV4 = false
		}
	}
	if val, ok := os.LookupEnv("CILIUM_ENABLE_IPV6"); ok {
		if val == "true" {
			*enableIPV6 = true
		} else if val == "false" {
			*enableIPV6 = false
		}
	}

	if val, ok := os.LookupEnv("CILIUM_DNSPROXY_ENABLE_TRANSPARENT_MODE"); ok {
		if val == "true" {
			*DNSProxyEnableTransparentMode = true
		} else if val == "false" {
			*DNSProxyEnableTransparentMode = false
		}
	}

	if val, ok := os.LookupEnv("CILIUM_DNSPROXY_SOCKET_LINGER_TIMEOUT"); ok {
		linger, err := strconv.Atoi(val)
		if err != nil {
			log.WithField("env", "CILIUM_DNSPROXY_SOCKET_LINGER_TIMEOUT").
				WithError(err).
				Fatal("Invalid value for configuration option")
		}
		*DNSProxySocketLingerTimeout = linger
	}

	option.Config.EnableIPv4 = *enableIPV4
	option.Config.EnableIPv6 = *enableIPV6
	option.Config.DNSProxyEnableTransparentMode = *DNSProxyEnableTransparentMode

	addr := fmt.Sprintf("127.0.0.1:%d", *gopsPort)
	if err := gops.Listen(gops.Options{
		Addr:                   addr,
		ReuseSocketAddrAndPort: true,
	}); err != nil {
		log.Fatalf("Cannot start gops server on addr %s: %v", addr, err)
	}
	defer gops.Close()
	log.Infof("Started gops server on addr %s", addr)

	if *enablePprof {
		pprof.Enable(*pprofAddress, *pprofPort)
	}

	cache = NewCache()

	if *exposePrometheusMetrics {
		go exposeMetrics()
		Version.WithLabelValues(version.GetCiliumVersion().Version)
	}

	DNSNotificationQueue = make(chan *pb.DNSNotification, *DNSNotificationChannelSize)
	for i := 0; i < clientConnRetries; i++ {
		if err := resetClient(); err != nil {
			if i == clientConnRetries-1 {
				log.WithError(err).Fatal("timed out trying to init connection to agent grpc api")
			}
			log.WithError(err).Error("could not init connection to agent grpc api, will retry")
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}
	go manageConnection()
	go manageNotifyOnDNSMsg()
	log.Info("starting cilium dns proxy server")
	var err error
	if err := re.InitRegexCompileLRU(*FQDNRegexCompileLRUSize); err != nil {
		log.WithError(err).Fatal("failed to start DNS proxy: failed to init regex LRU cache")
	}
	dnsProxyConfig := dnsproxy.DNSProxyConfig{
		Address:                "",
		Port:                   10001,
		IPv4:                   *enableIPV4,
		IPv6:                   *enableIPV6,
		EnableDNSCompression:   *enableDNSCompression,
		MaxRestoreDNSIPs:       0,
		ConcurrencyLimit:       *concurrencyLimit,
		ConcurrencyGracePeriod: *concurrencyGracePeriod,
	}
	proxy, err = dnsproxy.StartDNSProxy(
		dnsProxyConfig,
		LookupEndpointIDByIP,
		LookupSecIDByIP,
		LookupIPsBySecID,
		NotifyOnDNSMsg,
	)

	if err != nil {
		log.Fatalf("Failed to start dns proxy: %v", err)
	}
	log.Info("started dns proxy")

	// TODO: Refactor upstream proxy.SetRejectReply function to return an error to
	// avoid duplicating deny response validation code.
	switch strings.ToLower(*ToFQDNSRejectResponseCode) {
	case strings.ToLower(option.FQDNProxyDenyWithNameError), strings.ToLower(option.FQDNProxyDenyWithRefused):
		log.WithField("code", *ToFQDNSRejectResponseCode).
			Debug("setting to fqdn ns reject response code")
		proxy.SetRejectReply(*ToFQDNSRejectResponseCode)
	default:
		log.WithField("code", *ToFQDNSRejectResponseCode).Fatalf("invalid fqdn reject response code, must be one of %v", option.FQDNRejectOptions)
	}

	go RestoreRules()
	go RunServer(proxy)
	log.Info("fqdn proxy is now ready")

	exitSignal := make(chan os.Signal, 1)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal
}

func manageNotifyOnDNSMsg() {
	wp := workerpool.New(*DNSNotificationSendWorkers)
	for msg := range DNSNotificationQueue {
		msg := msg
		if *exposePrometheusMetrics {
			ProxyUpdateQueueLen.Dec()
		}
		err := wp.Submit("", func(ctx context.Context) error {
			sendDNSNotification(ctx, msg)
			return nil
		})
		if err != nil {
			log.WithError(err).Error("Error queueing DNS notification")
		}
	}
}

func sendDNSNotification(ctx context.Context, msg *pb.DNSNotification) {
	for {
		// We are purposefully not backing off exponentially because we want to
		// constantly retry to reach the Agent in case it is down in order to
		// not artificially delay DNS msgs.
		requestCtx, cancel := context.WithTimeout(ctx, DNSNotificationSendTimeout)
		_, err := client().NotifyOnDNSMessage(requestCtx, msg)
		cancel()
		var errDNSRequestNoEndpoint dnsproxy.ErrDNSRequestNoEndpoint
		switch {
		case err == nil:
			LogDebugTrigger.TriggerWithReason("Queued DNS Notification was successful")
			return
		case strings.Contains(err.Error(), errDNSRequestNoEndpoint.Error()):
			log.WithFields(logrus.Fields{
				"error": err,
				"addr":  msg.EpIPPort,
			}).Debug("Dropping DNS notification due to endpoint no longer existing")
			return
		default:
			LogAgentDownTrigger.TriggerWithReason(fmt.Sprintf("Failed to notify agent about DNS msg, retrying in %v: %s", DNSNotificationSendRetryInterval, err))
			time.Sleep(DNSNotificationSendRetryInterval)
		}
	}
}

func exposeMetrics() {
	log.WithField("port", *prometheusPort).Info("Enabling Prometheus metrics")
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(fmt.Sprintf(":%d", *prometheusPort), nil)
	if err != nil {
		log.WithError(err).Error("Failed to enable Prometheus metrics")
	}
}

// manageConnection periodically resets/re-dials the Agent GRPC Client connection.
func manageConnection() {
	log.Debug("starting agent fqdn grpc client connection manager")
	for {
		prevConnStatus := client().conn.GetState()

		client().conn.WaitForStateChange(context.Background(), connectivity.Ready)
		if err := resetClient(); err != nil {
			log.WithError(err).Error("failed to reset connection")
			continue
		}

		// Add an entry to the log only if the connection status
		// has really changed after resetting the client
		curConnStatus := client().conn.GetState()
		if curConnStatus != prevConnStatus {
			log.Infof("new grpc client connection status: %v", curConnStatus)
		}
		time.Sleep(30 * time.Second)
	}
}

func resetClient() error {
	if client() != nil && client().conn != nil {
		err := client().conn.Close()
		if err != nil {
			log.Infof("Failed to close agent connection: %v", err)
		}
	}

	var err error
	newConn, err := grpc.Dial("unix:///var/run/cilium/proxy-agent.sock",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		log.Errorf("failed to reset grpc client: %v", err)
		return err
	}
	clientPtr.Swap(&fqdnAgentClient{pb.NewFQDNProxyAgentClient(newConn), newConn})
	return nil
}

// RestoreRules runs on startup and tries to restore rules from Cilium agent
func RestoreRules() {
	log.Info("Restoring DNS rules from Cilium Agent")
	var err error
	var rules *pb.RestoredRulesMap
	for {
		rules, err = client().GetAllRules(context.Background(), &pb.Empty{})
		if err == nil {
			break
		}
		log.WithError(err).Info("failed to get rules, will retry")
		time.Sleep(time.Second)
		continue
	}
	log.Info("got rules from agent api, restoring.")

	for endpointID, rules := range rules.Rules {
		restoredRules := make(restore.DNSRules)
		for portProto, msgIPRules := range rules.Rules {
			ipRules := make(restore.IPRules, 0, len(msgIPRules.List))

			for _, ipRule := range msgIPRules.List {
				translatedRule := restore.IPRule{Re: restore.RuleRegex{Pattern: &ipRule.Regex}}
				translatedRule.IPs = make(map[restore.RuleIPOrCIDR]struct{}, len(ipRule.Ips))
				for _, IP := range ipRule.Ips {
					parsedIP, err := restore.ParseRuleIPOrCIDR(IP)
					if err != nil {
						log.WithError(err).WithField("ip", IP).Warning("failed to parse IP")
						continue
					}
					translatedRule.IPs[parsedIP] = struct{}{}
				}
				ipRules = append(ipRules, translatedRule)
			}
			restoredRules[restore.PortProto(portProto)] = ipRules
		}
		endpoint := &endpoint.Endpoint{ID: uint16(endpointID), DNSRules: restoredRules}

		proxy.RestoreRules(endpoint)
	}
	log.Debug("Rules restored")
}

// LookupEndpointIDByIP wraps logic to lookup an endpoint with any backend.
func LookupEndpointIDByIP(ip netip.Addr) (*endpoint.Endpoint, bool, error) {
	// Make sure to send IPv4 addresses as [4]byte instead of [16]byte over gRPC, so they aren't
	// mistakenly treated as IPv6-mapped IPv4 addresses anywhere in the Cilium agent.
	var bs []byte

	if ip.Is4In6() {
		b := ip.As4()
		bs = b[:]
	} else {
		bs = ip.AsSlice()
	}

	ep, err := client().LookupEndpointByIP(context.TODO(), &pb.FQDN_IP{IP: bs})
	if err != nil {
		cache.lock.RLock()
		endpoint, ok := cache.endpointByIP[ip]
		cache.lock.RUnlock()
		if !ok {
			return nil, false, fmt.Errorf("could not lookup endpoint for ip %s: %w", ip, err)
		}
		LogWarningTrigger.TriggerWithReason(fmt.Sprintf("endpoint retrieved from cache: %s", err))
		return endpoint, false, nil
	}
	endpoint := &endpoint.Endpoint{
		ID: uint16(ep.ID),
		SecurityIdentity: &identity.Identity{
			ID: identity.NumericIdentity(ep.Identity),
		},
		K8sNamespace: ep.Namespace,
		K8sPodName:   ep.PodName,
	}
	cache.lock.Lock()
	cache.endpointByIP[ip] = endpoint
	cache.lock.Unlock()
	return endpoint, false, nil
}

// LookupSecIDByIP wraps logic to lookup an IP's security ID from the
// ipcache.
func LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool) {
	id, err := client().LookupSecurityIdentityByIP(context.TODO(), &pb.FQDN_IP{IP: ip.AsSlice()})
	if err != nil {
		cache.lock.RLock()
		cachedID, ok := cache.identityByIP[ip]
		cache.lock.RUnlock()
		if !ok {
			log.Errorf("could not lookup security identity for ip %s: %v", ip, err)
			return ipcache.Identity{}, false
		}
		//TODO: check if this assumption is correct
		// we assume that the identity exists if it's in the cache
		log.WithError(err).Warning("security ID retrieved from cache")
		return cachedID, true
	}

	identity := ipcache.Identity{
		ID:     identity.NumericIdentity(id.ID),
		Source: source.Source(id.Source),
	}

	cache.lock.Lock()
	cache.identityByIP[ip] = identity
	cache.lock.Unlock()

	return identity, id.Exists
}

// LookupIPsBySecID wraps logic to lookup an IPs by security ID from the
// ipcache.
func LookupIPsBySecID(nid identity.NumericIdentity) []string {
	ips, err := client().LookupIPsBySecurityIdentity(context.TODO(), &pb.Identity{ID: uint32(nid)})
	if err != nil {
		cache.lock.RLock()
		cachedIPs, ok := cache.ipBySecID[nid]
		cache.lock.RUnlock()
		if !ok {
			log.Errorf("could not lookup ips for id %v: %v", nid, err)
			return nil
		}
		log.WithError(err).Warning("IPs retrieved from cache")
		return cachedIPs
	}

	result := make([]string, 0, len(ips.IPs))
	for _, ip := range ips.IPs {
		result = append(result, net.IP(ip).String())
	}

	cache.lock.Lock()
	cache.ipBySecID[nid] = result
	cache.lock.Unlock()
	return result
}

// NotifyOnDNSMsghandles propagating DNS response data
func NotifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, agentAddr string, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	stat.ProcessingTime.Start()
	metricError := metricErrorAllow
	endMetric := func() {
		if *exposePrometheusMetrics {
			success := metricError == metricErrorAllow
			stat.ProcessingTime.End(success)
			UpstreamTime.WithLabelValues(metricError).Observe(
				stat.UpstreamTime.Total().Seconds())
			ProcessingTime.WithLabelValues(metricError).Observe(
				stat.ProcessingTime.Total().Seconds())
		}
	}
	switch {
	case stat.IsTimeout():
		metricError = metricErrorTimeout
		endMetric()
		return nil
	case stat.Err != nil:
		metricError = metricErrorProxy
	case allowed, !allowed:
		break
	}

	if *exposePrometheusMetrics {
		PolicyTotal.WithLabelValues("received").Inc()
	}

	if ep == nil {
		metricError = metricErrorNoEP
		endMetric()
		log.Errorf("Endpoint is nil")
		return errors.New("Endpoint not found")
	}

	endpoint := &pb.Endpoint{
		ID:        uint32(ep.ID),
		Identity:  uint32(ep.SecurityIdentity.ID),
		Namespace: ep.K8sNamespace,
		PodName:   ep.K8sPodName,
	}

	dnsMsg, err := msg.Pack()
	if err != nil {
		metricError = metricErrorPacking
		endMetric()
		log.Errorf("Could not pack dns msg: %s", err)
		return err
	}

	notification := &pb.DNSNotification{
		Time:       timestamppb.New(lookupTime),
		Endpoint:   endpoint,
		EpIPPort:   epIPPort,
		ServerAddr: agentAddr,
		Msg:        dnsMsg,
		Protocol:   protocol,
		Allowed:    allowed,
		ServerID:   uint32(serverID),
	}

	// First, try a synchronous policy set up via cilium-agent. If this is
	// successful, we can return and let the DNS socket code handle another
	// request/response.
	ctx, cancel := context.WithTimeout(context.TODO(), time.Duration(DNSNotificationSendTimeout))
	defer cancel()
	if _, err = client().NotifyOnDNSMessage(ctx, notification); err != nil {
		LogInfoTrigger.TriggerWithReason(fmt.Sprintf("Cilium agent gRPC call failed during DNS response handling: %s", err))
		if *exposePrometheusMetrics {
			if s := status.Convert(err); s != nil {
				metricError = s.Code().String()
				ProxyUpdateErrors.WithLabelValues(metricError).Inc()
			} else {
				log.WithError(err).Warning("BUG: Unexpected error during DNS notification to cilium-agent")
			}
		}

		// Cilium-agent is down or unable to successfully plumb the policy
		// right now, so queue this DNSNotification until cilium is able to
		// handle the message.
		if *exposePrometheusMetrics {
			ProxyUpdateQueueLen.Inc()
		}
		select {
		case DNSNotificationQueue <- notification:
		default:
			if *exposePrometheusMetrics {
				ProxyUpdateQueueLen.Dec()
				metricError = metricErrorOverflow
				ProxyUpdateErrors.WithLabelValues(metricErrorOverflow).Inc()
			}
			LogWarningTrigger.TriggerWithReason("Cilium agent is down and notification channel is full. Skipping notification.")
		}
	}

	// Release the DNS response back to the user application. If Cilium
	// previously plumbed the policy for this IP / Name, then the app will
	// successfully connect, regardless of whether Cilium is down or not.
	if *exposePrometheusMetrics {
		PolicyTotal.WithLabelValues("forwarded").Inc()
	}
	if msg.Response && msg.Rcode == dns.RcodeSuccess {
		endMetric()
	}
	stat.ProcessingTime.End(true)
	return nil
}

type FQDNProxyServer struct {
	pb.UnimplementedFQDNProxyServer

	proxy *dnsproxy.DNSProxy
}

func (s *FQDNProxyServer) UpdateAllowed(ctx context.Context, rules *pb.FQDNRules) (*pb.Empty, error) {
	cachedSelectorREEntry := make(dnsproxy.CachedSelectorREEntry)

	for key, rule := range rules.Rules.SelectorRegexMapping {
		regex, err := regexp.Compile(rule)
		if err != nil {
			return &pb.Empty{}, err
		}

		ids, ok := rules.Rules.SelectorIdentitiesMapping[key]
		if !ok {
			return &pb.Empty{}, fmt.Errorf("malformed message: key %s not found in identities mapping", key)
		}

		nids := make([]identity.NumericIdentity, len(ids.List))

		for i, id := range ids.List {
			nids[i] = identity.NumericIdentity(id)
		}

		selector := SimpleSelector{
			identities: nids,
			name:       key,
		}

		cachedSelectorREEntry[&selector] = regex
	}

	var portProto restore.PortProto
	if rules.DestProto == 0 {
		portProto = restore.PortProto(rules.DestPort)
	} else {
		portProto = restore.MakeV2PortProto(uint16(rules.DestPort), u8proto.U8proto(rules.DestProto))
	}
	s.proxy.UpdateAllowedFromSelectorRegexes(rules.EndpointID, portProto, cachedSelectorREEntry)
	return &pb.Empty{}, nil
}

func (s *FQDNProxyServer) RemoveRestoredRules(ctx context.Context, endpointIDMsg *pb.EndpointID) (*pb.Empty, error) {
	s.proxy.RemoveRestoredRules(uint16(endpointIDMsg.EndpointID))

	return &pb.Empty{}, nil
}

func (s *FQDNProxyServer) GetRules(ctx context.Context, endpointIDMsg *pb.EndpointID) (*pb.RestoredRules, error) {
	rules, err := s.proxy.GetRules(uint16(endpointIDMsg.EndpointID))
	if err != nil {
		return nil, fmt.Errorf("failed to get rules for endpoint: %w", err)
	}

	msg := &pb.RestoredRules{Rules: make(map[uint32]*pb.IPRules, len(rules))}

	for port, ipRules := range rules {
		msgRules := &pb.IPRules{
			List: make([]*pb.IPRule, 0, len(ipRules)),
		}
		for _, ipRule := range ipRules {
			pattern := ""
			if ipRule.Re.Pattern != nil {
				pattern = *ipRule.Re.Pattern
			}
			msgRule := &pb.IPRule{
				Regex: pattern,
				Ips:   make([]string, 0, len(ipRule.IPs)),
			}
			for ip := range ipRule.IPs {
				msgRule.Ips = append(msgRule.Ips, ip.String())
			}

			msgRules.List = append(msgRules.List, msgRule)
		}

		msg.Rules[uint32(port)] = msgRules
	}

	return msg, nil
}

func newServer(proxy *dnsproxy.DNSProxy) *FQDNProxyServer {
	return &FQDNProxyServer{proxy: proxy}
}

func RunServer(proxy *dnsproxy.DNSProxy) {
	socket := "/var/run/cilium/proxy.sock"
	os.Remove(socket)
	lis, err := net.Listen("unix", socket)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterFQDNProxyServer(grpcServer, newServer(proxy))
	grpcServer.Serve(lis)
}

var _ policy.CachedSelector = &SimpleSelector{}

type SimpleSelector struct {
	identities []identity.NumericIdentity
	name       string
}

func (s *SimpleSelector) GetSelections() identity.NumericIdentitySlice {
	return s.identities
}

func (s *SimpleSelector) Selects(nid identity.NumericIdentity) bool {
	for _, id := range s.identities {
		if id == nid {
			return true
		}
	}
	return false
}

func (s *SimpleSelector) IsWildcard() bool {
	return false
}

func (s *SimpleSelector) IsNone() bool {
	return len(s.identities) == 0
}

func (s *SimpleSelector) String() string {
	return s.name
}

func (s *SimpleSelector) GetMetadataLabels() labels.LabelArray {
	return nil
}
