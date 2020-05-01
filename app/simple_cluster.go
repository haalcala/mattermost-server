package app

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/mattermost/mattermost-server/v5/einterfaces"
	"github.com/mattermost/mattermost-server/v5/model"

	redis "github.com/go-redis/redis/v7"
)

type SimpleCluster struct {
	messageHandlers map[string]*einterfaces.ClusterMessageHandler

	redisClient *redis.Client

	server *Server

	clusterDomain string

	clusterInfo *model.ClusterInfo

	clusterInfos map[string]*model.ClusterInfo
}

func (s *SimpleCluster) handleClusterMessage(msg *model.ClusterMessage) {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) handleClusterMessage(msg *model.ClusterMessage) {")

	fmt.Println("Handle Cluster Message!!!!")

	if msg.Data == "" {
		return
	}

	data_as_json := model.ClusterMessageFromJson(strings.NewReader(msg.Data))

	fmt.Println("data_as_json:", data_as_json)

	switch data_as_json.Event {
	case model.CLUSTER_EVENT_CLUSTER_INFO:
		fmt.Println("Processing ClusterInfo!!!! data_as_json.Data:", data_as_json.Data)

		cluster_info := model.ClusterInfoFromJson(strings.NewReader(data_as_json.Data))

		s.clusterInfos[cluster_info.Id] = cluster_info

		fmt.Println("s.clusterInfos:", s.clusterInfos)
	}
}

func NewSimpleCluster(server *Server) *SimpleCluster {
	fmt.Println("------ app/simple_cluster.go:: func NewSimpleCluster(s *Server) *SimpleCluster {")

	s := &SimpleCluster{server: server, messageHandlers: map[string]*einterfaces.ClusterMessageHandler{}}

	c := s.Server().FakeApp().Config()

	fmt.Println("c:", c, "os.Environ():", os.Environ())

	hostname, err := os.Hostname()

	if err != nil {
		panic(err)
	}

	s.clusterDomain = hostname

	clusterInfo := &model.ClusterInfo{
		Hostname:  hostname,
		Id:        hostname,
		IpAddress: s.Server().FakeApp().IpAddress(),
		Version:   model.CurrentVersion,
	}

	s.clusterInfo = clusterInfo
	s.clusterInfos = map[string]*model.ClusterInfo{}

	if c.ClusterSettings.ClusterName != nil {
		s.clusterDomain = *c.ClusterSettings.ClusterName
	}

	// create a shared/generic redisClient
	redisClient, err := s.newClient()

	if err != nil {
		panic(err)
	}

	s.redisClient = redisClient

	// create a pubsub redisClient
	redisClient, err = s.newClient()

	if err != nil {
		panic(err)
	}

	pong, err := redisClient.Ping().Result()

	fmt.Println(pong, err)
	// Output: PONG <nil>

	if err != nil {
		panic(err)
	}

	pubsub := redisClient.Subscribe(s.clusterDomain)

	_, err = pubsub.Receive()

	if err != nil {
		panic(err)
	}

	// Go channel which receives messages.
	ch := pubsub.Channel()

	s.RegisterClusterMessageHandler(model.CLUSTER_EVENT_CLUSTER_MESSAGE, s.handleClusterMessage)

	s.server.Go(func() {
		// Consume messages.
		for msg := range ch {
			fmt.Println(msg.Channel, msg.Payload)

			payload := model.ClusterMessageFromJson(strings.NewReader(msg.Payload))

			// if payload.Origin == s.server.serverNodeId {
			// 	fmt.Println("------------------------------------   Ignoning own message!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
			// 	fmt.Println("------------------------------------   Ignoning own message!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
			// 	fmt.Println("------------------------------------   Ignoning own message!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
			// 	continue
			// }

			// fmt.Println("payload.Data:", payload.Data)
			fmt.Println("reflect.TypeOf(payload.Data):", reflect.TypeOf(payload.Data))

			data_as_json := model.ClusterMessageFromJson(strings.NewReader(payload.Data))

			fmt.Println("**** data_as_json:", data_as_json)

			if data_as_json != nil && data_as_json.Event == "config_changed" {
				// server.FakeApp().regenerateClientConfig()
				// server.FakeApp().SaveConfig()

				server.FakeApp().ReloadConfig()
			}

			handler := s.messageHandlers[payload.Event]

			// *handler(payload)

			fmt.Println("handler:", handler, "reflect.TypeOf(handler):", reflect.TypeOf(handler), "payload:", payload)

			if handler != nil {
				(*handler)(payload)
			}
		}
	})

	return s
}

func (s *SimpleCluster) Server() *Server {
	return s.server
}

func (s *SimpleCluster) newClient() (*redis.Client, error) {
	redisHost, redisPort, redisPass := "", "", ""

	c := s.Server().FakeApp().Config()

	if c.ClusterSettings.ClusterRedisHost != nil {
		redisHost = *c.ClusterSettings.ClusterRedisHost
	}
	if c.ClusterSettings.ClusterRedisPort != nil {
		redisPort = *c.ClusterSettings.ClusterRedisPort
	}
	if c.ClusterSettings.ClusterRedisPass != nil {
		redisPass = *c.ClusterSettings.ClusterRedisPass
	}

	fmt.Printf("redisHost: %v, redisPort: %v, redisPass: %v\n", redisHost, redisPort, redisPass)

	return redis.NewClient(&redis.Options{
		Addr:     redisHost + ":" + redisPort,
		Password: redisPass, // no password set
		DB:       0,         // use default DB
	}), nil
}

func (s *SimpleCluster) StartInterNodeCommunication() {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) StartInterNodeCommunication() { os.Getenv(\"MM_REDIS_CLUSTER_ROLE\"):", os.Getenv("MM_REDIS_CLUSTER_ROLE"))

	time.Sleep(time.Second * 5)

	fmt.Println("StartInterNodeCommunication:: s.redisClient:", s.redisClient)

	// Notify cluster about this node
	s.Server().FakeApp().notifyClusterEvent(model.CLUSTER_EVENT_CLUSTER_INFO, s.clusterInfo)

	fmt.Println("-------------------******************************========================================== StartInterNodeCommunication. Exiting.")
}

func (s *SimpleCluster) StopInterNodeCommunication() {

}

func (s *SimpleCluster) RegisterClusterMessageHandler(event string, crm einterfaces.ClusterMessageHandler) {

	fmt.Printf("event: %v, crm: %v\n", event, crm)

	s.messageHandlers[event] = &crm
}

func (s *SimpleCluster) GetClusterId() string {
	hostname, err := os.Hostname()

	if err != nil {
		panic(err)
	}

	return hostname
}

func (s *SimpleCluster) IsLeader() bool {
	return os.Getenv("MM_REDIS_CLUSTER_ROLE") == "master"
}

func (s *SimpleCluster) GetMyClusterInfo() *model.ClusterInfo {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) GetMyClusterInfo() *model.ClusterInfo {")
	return s.clusterInfo
}

func (s *SimpleCluster) GetClusterInfos() []*model.ClusterInfo {
	return []*model.ClusterInfo{}
}

func (s *SimpleCluster) SendClusterMessage(msg *model.ClusterMessage) {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) SendClusterMessage(msg *model.ClusterMessage) {")

	fmt.Println("<<<<<<======------ msg:", msg.ToJson())

	s.redisClient.Publish(s.clusterDomain, msg.ToJson())
}

func (s *SimpleCluster) NotifyMsg(buf []byte) {

}

func (s *SimpleCluster) GetClusterStats() ([]*model.ClusterStats, *model.AppError) {
	return nil, nil
}

func (s *SimpleCluster) GetLogs(page, perPage int) ([]string, *model.AppError) {
	return []string{}, nil
}

func (s *SimpleCluster) GetPluginStatuses() (model.PluginStatuses, *model.AppError) {
	return model.PluginStatuses{}, nil
}

func (s *SimpleCluster) ConfigChanged(previousConfig *model.Config, newConfig *model.Config, sendToOtherServer bool) *model.AppError {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) ConfigChanged(previousConfig *model.Config, newConfig *model.Config, sendToOtherServer bool) *model.AppError {")

	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_CONFIG_CHANGED, "", "", "", nil)

	message.Add("config", s.Server().FakeApp().ClientConfigWithComputed())

	s.Server().Go(func() {
		s.Server().FakeApp().Publish(message)
	})

	return nil
}

// notifyClusterEvent publishes `event` to other clusters.
func (a *App) notifyClusterEvent(event string, data *model.ClusterInfo) {
	if a.Cluster() != nil {
		_event := &model.ClusterMessage{
			Event: event,
			Data:  data.ToJson(),
		}
		a.Cluster().SendClusterMessage(&model.ClusterMessage{
			Event:            model.CLUSTER_EVENT_CLUSTER_MESSAGE,
			SendType:         model.CLUSTER_SEND_RELIABLE,
			WaitForAllToSend: true,
			Data:             _event.ToJson(),
		})
	}
}
