// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mattermost/logr"
	"github.com/mattermost/mattermost-server/v5/einterfaces"
	"github.com/mattermost/mattermost-server/v5/mlog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	custom_metrics_lock = &sync.Mutex{}
	custom_metrics      einterfaces.MetricsInterface

	totalPostCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "post",
		Name:      "total",
	})

	totalWebhookPostCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "post",
		Name:      "webhook_total",
	})

	totalPostSentEmailCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "post",
		Name:      "emails_sent_total",
	})

	totalPostSentPushCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "post",
		Name:      "pushes_sent_total",
	})

	totalPostBroadcastPushCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "post",
		Name:      "post_broadcasts_total",
	})

	totalPostFileAttachmentCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "post",
		Name:      "file_attachments_total",
	})

	totalPostsSearchCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "post",
		Name:      "search_total",
	})

	totalHttpRequestCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "http",
		Name:      "requests_total",
	})

	totalHttpErrorCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "http",
		Name:      "errors_total",
	})

	totalClusterRequestCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "cluster",
		Name:      "cluster_requests_total",
	})

	totalClusterRequestDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "mattermost",
		Subsystem: "cluster",
		Name:      "cluster_request_duration_seconds",
	})

	totalClusterEventTypesCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "cluster",
		Name:      "event_type_totals",
	}, []string{"event_type"})

	totalLoginsCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "login",
		Name:      "logins_total",
	})

	totalLoginsFailCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "login",
		Name:      "logins_fail_total",
	})

	totalCacheEtagHitCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "cache",
		Name:      "etag_hit_total",
	}, []string{"route"})

	totalCacheEtagMissCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "cache",
		Name:      "etag_miss_total",
	}, []string{"route"})

	totalCacheMemHitCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "cache",
		Name:      "mem_hit_total",
	}, []string{"cacheName"})

	totalCacheMemMissCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "cache",
		Name:      "mem_miss_total",
	}, []string{"cacheName"})

	totalCacheMemInvalidationCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "cache",
		Name:      "mem_invalidation_total",
	}, []string{"cacheName"})

	totalCacheMemMissSessionCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "cache",
		Name:      "mem_miss_session_total",
	})

	totalCacheMemHitSessionCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "cache",
		Name:      "mem_hit_session_total",
	})

	totalCacheMemInvalidationSessionCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "cache",
		Name:      "mem_invalidation_session_total",
	})

	totalWebsocketEventCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "websocket",
		Name:      "events_total",
	}, []string{"eventType"})

	totalWebsocketBroadcastEventCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "websocket",
		Name:      "broadcasts_total",
	}, []string{"eventType"})

	websocketBroadcastBufferSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "mattermost",
		Subsystem: "websocket",
		Name:      "broadcasts_buffer_total",
	}, []string{"hub"})

	websocketBroadcastUsersRegisteredSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "mattermost",
		Subsystem: "websocket",
		Name:      "broadcasts_users_registered_total",
	}, []string{"hub"})

	totalPostsSearchDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "mattermost",
		Subsystem: "websocket",
		Name:      "posts_searches_duration_seconds",
	})

	totalStoreMethodDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "mattermost",
		Subsystem: "db",
		Name:      "store_time",
	}, []string{"method", "success"})

	totalUserIndexCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "db",
		Name:      "user_index_total",
	})

	totalPostsIndexCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "db",
		Name:      "post_index_total",
	})

	totalChannelIndexCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "db",
		Name:      "channel_index_total",
	})

	totalApiEndPointDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "mattermost",
		Subsystem: "api",
		Name:      "endpoint_time",
	}, []string{"endpoint", "method", "statusCode"})

	totalPluginApiDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "mattermost",
		Subsystem: "api",
		Name:      "plugin_time",
	}, []string{"pluginID", "apiName", "success"})

	totalPluginHookDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "mattermost",
		Subsystem: "plugin",
		Name:      "hook_time",
	}, []string{"pluginID", "hookName"})

	totalPluginMultiHookIterationDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "mattermost",
		Subsystem: "plugin",
		Name:      "multihook_iteration_time",
	}, []string{"pluginID"})

	totalPluginMultiHookDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "mattermost",
		Subsystem: "plugin",
		Name:      "multihook_time",
	})

	residentMemoryBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "mattermost",
		Subsystem: "process",
		Name:      "resident_memory_bytes",
	})

	openFileDescriptors = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "mattermost",
		Subsystem: "process",
		Name:      "open_fds",
	})

	maxFileDescriptors = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "mattermost",
		Subsystem: "process",
		Name:      "max_fds",
	})

	jobActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "mattermost",
		Subsystem: "jobs",
		Name:      "active",
	}, []string{"jobType"})

	fileIndexCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "file",
		Name:      "index_count",
	})

	fileSearchCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "mattermost",
		Subsystem: "file",
		Name:      "search_count",
	})

	fileSearchDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "mattermost",
		Subsystem: "file",
		Name:      "search_duration",
	})
)

type CustomMetricsAdapter struct {
	server *Server

	http_server *http.Server

	started bool
}

// mattermost_db_master_connections_total
// mattermost_db_read_replica_connections_total
// mattermost_db_search_replica_connections_total
// mattermost_http_request_duration_seconds
// mattermost_http_websockets_total
// mattermost_process_cpu_seconds_total
// mattermost_process_start_time_seconds
// mattermost_process_virtual_memory_bytes
// logger_queue_used
// logger_logged_total
// logger_error_total
// logger_dropped_total
// logger_blocked_total

func init() {
	RegisterMetricsInterface(newCustomMetricsAdapter)
}

func newCustomMetricsAdapter(s *Server) einterfaces.MetricsInterface {
	custom_metrics_lock.Lock()
	defer custom_metrics_lock.Unlock()

	if custom_metrics != nil {
		return custom_metrics
	}

	custom_metrics := &CustomMetricsAdapter{
		server: s,
	}

	return custom_metrics
}

func (m *CustomMetricsAdapter) ObserveEnabledUsers(users int64) {

}

func (m *CustomMetricsAdapter) GetLoggerMetricsCollector() logr.MetricsCollector {
	return nil
}

func (m *CustomMetricsAdapter) StartServer() {
	fmt.Println("------ app/custom_metrics_adapter.go:: func (m *CustomMetricsAdapter) StartServer()")

	if m.started {
		fmt.Println("Custom Metrics server already restarted. Skipping.")
		return
	}

	custom_metrics_lock.Lock()
	defer custom_metrics_lock.Unlock()

	// register with the prometheus collector
	prometheus.MustRegister(
		totalPostCounter,
		totalWebhookPostCounter,
		totalPostSentEmailCounter,
		totalPostSentPushCounter,
		totalPostBroadcastPushCounter,
		totalPostFileAttachmentCounter,
		totalHttpRequestCounter,
		totalHttpErrorCounter,
		totalClusterRequestDuration,
		totalClusterEventTypesCounter,
		totalLoginsCounter,
		totalLoginsFailCounter,
		totalCacheEtagHitCounter,
		totalCacheEtagMissCounter,
		totalCacheMemHitCounter,
		totalCacheMemMissCounter,
		totalCacheMemInvalidationCounter,
		totalCacheMemMissSessionCounter,
		totalCacheMemHitSessionCounter,
		totalCacheMemInvalidationSessionCounter,
		totalWebsocketEventCounter,
		totalWebsocketBroadcastEventCounter,
		websocketBroadcastBufferSize,
		websocketBroadcastUsersRegisteredSize,
		totalPostsSearchCounter,
		totalPostsSearchDuration,
		totalStoreMethodDuration,
		totalApiEndPointDuration,
		totalPostsIndexCounter,
		totalUserIndexCounter,
		totalChannelIndexCounter,
		totalPluginHookDuration,
		totalPluginMultiHookIterationDuration,
		totalPluginMultiHookDuration,
		totalPluginApiDuration,
		residentMemoryBytes,
		openFileDescriptors,
		maxFileDescriptors,
		jobActive,
		fileSearchCounter,
		fileSearchDuration,
	)

	totalClusterEventTypesCounter.WithLabelValues("my_test").Inc()

	handler := http.NewServeMux()

	m.started = true

	m.StartEnvironmentStats()

	go func() {
		fmt.Println("*m.server.Config().MetricsSettings.ListenAddress:", *m.server.Config().MetricsSettings.ListenAddress)

		handler.Handle("/metrics", promhttp.Handler())

		m.http_server = &http.Server{
			Addr:     *m.server.Config().MetricsSettings.ListenAddress,
			Handler:  handler,
			ErrorLog: m.server.Log.StdLog(mlog.String("source", "le_forwarder_server")),
		}
		err := m.http_server.ListenAndServe()

		if err != nil {
			fmt.Println("error while starting the metrics server", err)
		}
	}()
}

func (m *CustomMetricsAdapter) StopServer() {
	fmt.Println("------ app/custom_metrics_adapter.go:: func (m *CustomMetricsAdapter) StopServer()")

	if m.http_server != nil {
		err := m.http_server.Close()

		m.started = false

		if err != nil {
			fmt.Println("error while starting the metrics server", err)
		}
	}
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func (m *CustomMetricsAdapter) StartEnvironmentStats() {
	go func() {
		for m.started {
			var mem runtime.MemStats

			runtime.ReadMemStats(&mem)

			// For info on each, see: https://golang.org/pkg/runtime/#MemStats
			fmt.Printf("Alloc = %v MiB", bToMb(mem.Alloc))
			fmt.Printf("\tTotalAlloc = %v MiB", bToMb(mem.TotalAlloc))
			fmt.Printf("\tSys = %v MiB", bToMb(mem.Sys))
			fmt.Printf("\tNumGC = %v\n", mem.NumGC)

			residentMemoryBytes.Set(float64(mem.Alloc))

			open_files := countOpenFiles()

			openFileDescriptors.Set(float64(open_files))

			maxFileDescriptors.Set(float64(GetUlimit()))

			time.Sleep(5 * time.Second)
		}
	}()
}

func countOpenFiles() int64 {
	out, err := exec.Command("/bin/sh", "-c", fmt.Sprintf("lsof -p %v", os.Getpid())).Output()
	if err != nil {
		fmt.Println(err.Error())
	}
	lines := strings.Split(string(out), "\n")
	return int64(len(lines) - 1)
}

func (m *CustomMetricsAdapter) IncrementPostCreate() {
	totalPostCounter.Inc()
}

func (m *CustomMetricsAdapter) IncrementWebhookPost() {
	totalWebhookPostCounter.Inc()
}

func (m *CustomMetricsAdapter) IncrementPostSentEmail() {
	totalPostSentEmailCounter.Inc()
}

func (m *CustomMetricsAdapter) IncrementPostSentPush() {
	totalPostSentPushCounter.Inc()
}

func (m *CustomMetricsAdapter) IncrementPostBroadcast() {
	totalPostBroadcastPushCounter.Inc()
}

func (m *CustomMetricsAdapter) IncrementPostFileAttachment(count int) {
	totalPostFileAttachmentCounter.Inc()
}

func (m *CustomMetricsAdapter) IncrementHttpRequest() {
}

func (m *CustomMetricsAdapter) IncrementHttpError() {
}

func (m *CustomMetricsAdapter) IncrementClusterRequest() {
}

func (m *CustomMetricsAdapter) ObserveClusterRequestDuration(elapsed float64) {
	totalClusterRequestDuration.Observe(elapsed)
}

func (m *CustomMetricsAdapter) IncrementClusterEventType(eventType string) {
	totalClusterEventTypesCounter.WithLabelValues(eventType).Inc()
}

func (m *CustomMetricsAdapter) IncrementLogin() {
	totalLoginsCounter.Inc()
}

func (m *CustomMetricsAdapter) IncrementLoginFail() {
	totalLoginsFailCounter.Inc()
}

func (m *CustomMetricsAdapter) IncrementEtagHitCounter(route string) {
	totalCacheEtagHitCounter.WithLabelValues(route).Inc()
}

func (m *CustomMetricsAdapter) IncrementEtagMissCounter(route string) {
	totalCacheEtagMissCounter.WithLabelValues(route).Inc()
}

func (m *CustomMetricsAdapter) IncrementMemCacheHitCounter(cacheName string) {
}

func (m *CustomMetricsAdapter) IncrementMemCacheMissCounter(cacheName string) {
}

func (m *CustomMetricsAdapter) IncrementMemCacheInvalidationCounter(cacheName string) {
}

func (m *CustomMetricsAdapter) IncrementMemCacheMissCounterSession() {
}

func (m *CustomMetricsAdapter) IncrementMemCacheHitCounterSession() {
	totalCacheMemHitSessionCounter.Inc()
}

func (m *CustomMetricsAdapter) IncrementMemCacheInvalidationCounterSession() {
	totalCacheMemInvalidationSessionCounter.Inc()
}

func (m *CustomMetricsAdapter) IncrementWebsocketEvent(eventType string) {
	totalWebsocketEventCounter.WithLabelValues(eventType).Inc()
}

func (m *CustomMetricsAdapter) IncrementWebSocketBroadcast(eventType string) {
	totalWebsocketBroadcastEventCounter.WithLabelValues(eventType).Inc()
}

func (m *CustomMetricsAdapter) IncrementWebSocketBroadcastBufferSize(hub string, amount float64) {
	websocketBroadcastBufferSize.WithLabelValues(hub).Add(amount)
}

func (m *CustomMetricsAdapter) DecrementWebSocketBroadcastBufferSize(hub string, amount float64) {
	websocketBroadcastBufferSize.WithLabelValues(hub).Sub(amount)
}

func (m *CustomMetricsAdapter) IncrementWebSocketBroadcastUsersRegistered(hub string, amount float64) {
	websocketBroadcastUsersRegisteredSize.WithLabelValues(hub).Add(amount)
}

func (m *CustomMetricsAdapter) DecrementWebSocketBroadcastUsersRegistered(hub string, amount float64) {
	websocketBroadcastUsersRegisteredSize.WithLabelValues(hub).Sub(amount)
}

func (m *CustomMetricsAdapter) AddMemCacheHitCounter(cacheName string, amount float64) {
	totalCacheMemHitCounter.WithLabelValues(cacheName).Add(amount)
}

func (m *CustomMetricsAdapter) AddMemCacheMissCounter(cacheName string, amount float64) {
	totalCacheMemMissCounter.WithLabelValues(cacheName).Add(amount)
}

func (m *CustomMetricsAdapter) IncrementPostsSearchCounter() {
	totalPostsSearchCounter.Inc()
}

func (m *CustomMetricsAdapter) ObservePostsSearchDuration(elapsed float64) {
	totalPostsSearchDuration.Observe(elapsed)
}

func (m *CustomMetricsAdapter) ObserveStoreMethodDuration(method, success string, elapsed float64) {
	totalStoreMethodDuration.WithLabelValues(method, success).Observe(elapsed)
}

func (m *CustomMetricsAdapter) ObserveApiEndpointDuration(endpoint, method, statusCode string, elapsed float64) {
	totalApiEndPointDuration.WithLabelValues(endpoint, method, statusCode).Observe(elapsed)
}

func (m *CustomMetricsAdapter) IncrementPostIndexCounter() {
	totalPostsIndexCounter.Inc()
}

func (m *CustomMetricsAdapter) IncrementUserIndexCounter() {
	totalUserIndexCounter.Inc()
}

func (m *CustomMetricsAdapter) IncrementChannelIndexCounter() {
	totalChannelIndexCounter.Inc()
}

func (m *CustomMetricsAdapter) ObservePluginHookDuration(pluginID, hookName string, success bool, elapsed float64) {
	totalPluginHookDuration.WithLabelValues(pluginID, hookName).Observe(elapsed)
}

func (m *CustomMetricsAdapter) ObservePluginMultiHookIterationDuration(pluginID string, elapsed float64) {
	totalPluginMultiHookIterationDuration.WithLabelValues(pluginID).Observe(elapsed)
}

func (m *CustomMetricsAdapter) ObservePluginMultiHookDuration(elapsed float64) {
	totalPluginMultiHookDuration.Observe(elapsed)
}

func (m *CustomMetricsAdapter) ObserveFilesSearchDuration(elapsed float64) {
	fileSearchDuration.Observe(elapsed)
}

func (m *CustomMetricsAdapter) ObservePluginApiDuration(pluginID, apiName string, success bool, elapsed float64) {
	totalPluginApiDuration.WithLabelValues(pluginID, apiName, fmt.Sprintf("%v", success)).Observe(elapsed)
}

func (m *CustomMetricsAdapter) IncrementJobActive(jobType string) {
	jobActive.WithLabelValues(jobType).Add(1)
}

func (m *CustomMetricsAdapter) DecrementJobActive(jobType string) {
	jobActive.WithLabelValues(jobType).Sub(1)
}

func (m *CustomMetricsAdapter) IncrementFileIndexCounter() {
	fileIndexCounter.Add(1)
}

func (m *CustomMetricsAdapter) IncrementFilesSearchCounter() {
	fileSearchCounter.Add(1)
}
