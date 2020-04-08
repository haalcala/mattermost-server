package app

import (
	"fmt"

	"github.com/mattermost/mattermost-server/v5/einterfaces"
	"github.com/mattermost/mattermost-server/v5/model"

	redis "github.com/go-redis/redis/v7"
)

type SimpleCluster struct {
	messageHandlers map[string]*einterfaces.ClusterMessageHandler

	redisClient *redis.Client

	server *Server
}

func NewSimpleCluster(s *Server) *SimpleCluster {
	simpleCluster := &SimpleCluster{server: s, messageHandlers: map[string]*einterfaces.ClusterMessageHandler{}}

	return simpleCluster
}

func (s *SimpleCluster) Server() *Server {
	return s.server
}

func (s *SimpleCluster) StartInterNodeCommunication() {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) StartInterNodeCommunication() {")

	c := s.Server().FakeApp().Config()

	fmt.Println("c:", c)

	redisClient := s.redisClient

	// just a comment
	redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	pong, err := redisClient.Ping().Result()

	fmt.Println(pong, err)
	// Output: PONG <nil>

	if err == nil {
		channels := []string{}

		for messageHandler_key, _ := range s.messageHandlers {
			channels = append(channels, messageHandler_key)
		}

		sub := redisClient.Subscribe(channels...)

		iface, err := sub.Receive()

		fmt.Println("iface:", iface, "err:", err)

		if err == nil {

		}
	}
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
	return ""
}

func (s *SimpleCluster) IsLeader() bool {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) IsLeader() bool {")
	return true
}

func (s *SimpleCluster) GetMyClusterInfo() *model.ClusterInfo {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) GetMyClusterInfo() *model.ClusterInfo {")
	return nil
}

func (s *SimpleCluster) GetClusterInfos() []*model.ClusterInfo {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) GetClusterInfos() []*model.ClusterInfo {")
	return []*model.ClusterInfo{}
}

func (s *SimpleCluster) SendClusterMessage(cluster *model.ClusterMessage) {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) SendClusterMessage(cluster *model.ClusterMessage) {")

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
