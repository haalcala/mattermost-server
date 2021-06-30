// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"bitbucket.org/v-cube/mattermost-server/v5/einterfaces"
	"bitbucket.org/v-cube/mattermost-server/v5/model"

	redis "github.com/go-redis/redis/v8"
)

func init() {
	RegisterClusterInterface(func(s *Server) einterfaces.ClusterInterface {
		fmt.Println("Registering custom cluster interface ...")
		fmt.Println("Registering custom cluster interface ...")
		fmt.Println("Registering custom cluster interface ...")
		fmt.Println("Registering custom cluster interface ...")
		return NewSimpleCluster(s)
	})
}

type SimpleCluster struct {
	messageHandlers map[string]*einterfaces.ClusterMessageHandler

	redisClient *redis.Client

	server *Server

	clusterDomain string

	clusterInfo *model.ClusterInfo

	clusterInfos map[string]*model.ClusterInfo
}

func (s *SimpleCluster) HealthScore() int {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) HealthScore(msg *model.ClusterMessage)")

	return 0
}

// func (s *SimpleCluster) handleClusterMessage(msg *model.ClusterMessage) {
// 	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) handleClusterMessage(msg *model.ClusterMessage)")

// 	fmt.Println("Handle Cluster Message!!!!")

// 	if msg.Data == "" {
// 		return
// 	}

// 	data_as_json := model.ClusterMessageFromJson(strings.NewReader(msg.Data))

// 	fmt.Println("data_as_json:", data_as_json)

// 	// switch data_as_json.Event {
// 	// case model.CLUSTER_EVENT_CLUSTER_INFO:
// 	// 	fmt.Println("Processing ClusterInfo!!!! data_as_json.Data:", data_as_json.Data)

// 	// 	cluster_info := model.ClusterInfoFromJson(strings.NewReader(data_as_json.Data))

// 	// 	s.clusterInfos[cluster_info.Id] = cluster_info

// 	// 	fmt.Println("s.clusterInfos:", s.clusterInfos)
// 	// }
// }

func NewSimpleCluster(server *Server) *SimpleCluster {
	fmt.Println("------ app/simple_cluster.go:: func NewSimpleCluster(s *Server) *SimpleCluster")

	s := &SimpleCluster{server: server, messageHandlers: map[string]*einterfaces.ClusterMessageHandler{}}

	c := s.Server().Config()

	fmt.Println("c:", c, "os.Environ():", os.Environ())

	hostname, err := os.Hostname()

	if err != nil {
		panic(err)
	}

	s.clusterDomain = hostname

	var ip net.IP
	ifaces, err := net.Interfaces()
	// handle err
	for _, i := range ifaces {
		addrs, err := i.Addrs()

		if err != nil {
			panic(err)
		}

		// handle err
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			// process IP address
		}
	}

	clusterInfo := &model.ClusterInfo{
		Hostname:  hostname,
		Id:        hostname,
		IpAddress: ip.String(),
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

	pong, err := redisClient.Ping(context.TODO()).Result()

	fmt.Println(pong, err)
	// Output: PONG <nil>

	if err != nil {
		panic(err)
	}

	pubsub := redisClient.Subscribe(context.TODO(), s.clusterDomain)

	_, err = pubsub.Receive(context.TODO())

	if err != nil {
		panic(err)
	}

	// Go channel which receives messages.
	ch := pubsub.Channel()

	// s.RegisterClusterMessageHandler(model.CLUSTER_EVENT_CLUSTER_MESSAGE, s.handleClusterMessage)

	go func() {
		// Consume messages.
		for msg := range ch {
			fmt.Println("<<<<<<======------ app/simple_cluster.go:: msg.Channel:", msg.Channel, "msg.Payload:", msg.Payload)

			payload := model.ClusterMessageFromJson(strings.NewReader(msg.Payload))

			if payload.Origin == s.clusterInfo.Id {
				// fmt.Println("------------------------------------   Ignoning own message!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
				// fmt.Println("------------------------------------   Ignoning own message!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
				// fmt.Println("------------------------------------   Ignoning own message!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
				continue
			}

			// fmt.Println("payload.Data:", payload.Data)
			// fmt.Println("reflect.TypeOf(payload.Data):", reflect.TypeOf(payload.Data))

			data_as_json := model.ClusterMessageFromJson(strings.NewReader(payload.Data))

			// fmt.Println("**** data_as_json:", data_as_json)

			if data_as_json != nil && data_as_json.Event == "config_changed" {
				// server.regenerateClientConfig()
				// server.SaveConfig()

				server.ReloadConfig()
			}

			handler := s.messageHandlers[payload.Event]

			// *handler(payload)

			// fmt.Println("handler:", handler, "reflect.TypeOf(handler):", reflect.TypeOf(handler), "payload:", payload)

			if handler != nil {
				(*handler)(payload)
			}
		}
	}()

	return s
}

func (s *SimpleCluster) Server() *Server {
	return s.server
}

func (s *SimpleCluster) newClient() (*redis.Client, error) {
	redisHost, redisPort, redisPass, clusterDriver := "", "", "", ""

	c := s.Server().Config()

	if c.ClusterSettings.ClusterDriver != nil {
		clusterDriver = *c.ClusterSettings.ClusterDriver
	}
	if clusterDriver == "" {
		clusterDriver = os.Getenv("MM_REDIS_CLUSTER_DRIVER")
	}
	if clusterDriver != "redis" {
		panic("Cluster driver must be set to 'redis' in order to use redis as the clustering back-end")
	}

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

	if redisHost == "" {
		panic("Cluster redis host config cannot be empty")
	}

	if redisHost == "" {
		panic("Cluster redis port config cannot be empty")
	}

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

	// // Notify cluster about this node
	// s.notifyClusterEvent(model.CLUSTER_EVENT_CLUSTER_INFO, s.clusterInfo)

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

	if s.Server().Config().ClusterSettings.OverrideHostname != nil && *s.Server().Config().ClusterSettings.OverrideHostname != "" {
		hostname = *s.Server().Config().ClusterSettings.OverrideHostname
	}

	return hostname
}

func (s *SimpleCluster) IsLeader() bool {
	return os.Getenv("MM_REDIS_CLUSTER_ROLE") == "master"
}

func (s *SimpleCluster) GetMyClusterInfo() *model.ClusterInfo {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) GetMyClusterInfo() *model.ClusterInfo")

	return s.clusterInfo
}

func (s *SimpleCluster) GetClusterInfos() []*model.ClusterInfo {
	clusterInfos := []*model.ClusterInfo{}

	for key := range s.clusterInfos {
		clusterInfos = append(clusterInfos, s.clusterInfos[key])
	}

	return clusterInfos
}

func (s *SimpleCluster) SendClusterMessage(msg *model.ClusterMessage) {
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) SendClusterMessage(msg *model.ClusterMessage)")

	msg.Origin = s.clusterInfo.Id

	fmt.Println("------======>>>>>> msg:", msg.ToJson())

	s.redisClient.Publish(context.TODO(), s.clusterDomain, msg.ToJson())
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
	fmt.Println("------ app/simple_cluster.go:: func (s *SimpleCluster) ConfigChanged(previousConfig *model.Config, newConfig *model.Config, sendToOtherServer bool) *model.AppError")

	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_CONFIG_CHANGED, "", "", "", nil)

	message.Add("config", s.Server().ClientConfigWithComputed())

	s.Server().Go(func() {
		s.Server().Publish(message)
	})

	return nil
}

// notifyClusterEvent publishes `event` to other clusters.
func (a *App) notifyClusterEvent(event string, data *model.ClusterInfo) {
	if a.Cluster() != nil {
		a.Cluster().SendClusterMessage(&model.ClusterMessage{
			Event:            event,
			SendType:         model.CLUSTER_SEND_RELIABLE,
			WaitForAllToSend: true,
			Data:             data.ToJson(),
		})
	}
}

// just another commit
