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

	s.server.Go(func() {
		// Consume messages.
		for msg := range ch {
			fmt.Println("------>>> app/simple_cluster.go:: msg.Channel:", msg.Channel, "msg.Payload:", msg.Payload)

			payload := model.ClusterMessageFromJson(strings.NewReader(msg.Payload))

			fmt.Println("payload.Data:", payload.Data)
			fmt.Println("reflect.TypeOf(payload.Data):", reflect.TypeOf(payload.Data))

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

	fmt.Println("-------------------******************************========================================== StartInterNodeCommunication. Exiting.")
}

func (s *SimpleCluster) StopInterNodeCommunication() {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) StopInterNodeCommunication() {")

}

func (s *SimpleCluster) RegisterClusterMessageHandler(event string, crm einterfaces.ClusterMessageHandler) {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) RegisterClusterMessageHandler(event string, crm ClusterMessageHandler) {")

	fmt.Printf("event: %v, crm: %v\n", event, crm)

	s.messageHandlers[event] = &crm
}

func (s *SimpleCluster) GetClusterId() string {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) GetClusterId() string {")

	hostname, err := os.Hostname()

	if err != nil {
		panic(err)
	}

	return hostname
}

func (s *SimpleCluster) IsLeader() bool {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) IsLeader() bool {")

	return os.Getenv("MM_REDIS_CLUSTER_ROLE") == "master"
}

func (s *SimpleCluster) GetMyClusterInfo() *model.ClusterInfo {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) GetMyClusterInfo() *model.ClusterInfo {")
	return nil
}

func (s *SimpleCluster) GetClusterInfos() []*model.ClusterInfo {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) GetClusterInfos() []*model.ClusterInfo {")
	return []*model.ClusterInfo{}
}

func (s *SimpleCluster) SendClusterMessage(msg *model.ClusterMessage) {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) SendClusterMessage(msg *model.ClusterMessage) { msg:", msg.ToJson())
	s.redisClient.Publish(s.clusterDomain, msg.ToJson())
}

func (s *SimpleCluster) NotifyMsg(buf []byte) {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) NotifyMsg(buf []byte) {")

}

func (s *SimpleCluster) GetClusterStats() ([]*model.ClusterStats, *model.AppError) {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) GetClusterStats() ([]*model.ClusterStats, *model.AppError) {")
	return nil, nil
}

func (s *SimpleCluster) GetLogs(page, perPage int) ([]string, *model.AppError) {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) GetLogs(page, perPage int) ([]string, *model.AppError) {")
	return []string{}, nil
}

func (s *SimpleCluster) GetPluginStatuses() (model.PluginStatuses, *model.AppError) {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) GetPluginStatuses() (model.PluginStatuses, *model.AppError) {")
	return model.PluginStatuses{}, nil
}

func (s *SimpleCluster) ConfigChanged(previousConfig *model.Config, newConfig *model.Config, sendToOtherServer bool) *model.AppError {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) ConfigChanged(previousConfig *model.Config, newConfig *model.Config, sendToOtherServer bool) *model.AppError {")
	return nil
}
