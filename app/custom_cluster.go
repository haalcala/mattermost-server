package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mattermost/mattermost-server/v5/einterfaces"
	"github.com/mattermost/mattermost-server/v5/model"

	redis "github.com/go-redis/redis/v8"

	"github.com/hashicorp/memberlist"
	uuid "github.com/pborman/uuid"
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

	mtx        sync.RWMutex
	items      map[string]string
	broadcasts *memberlist.TransmitLimitedQueue

	this_node *memberlist.Node

	start_time int64

	eventDelegate *eventDelegate

	isMaster bool
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
type eventDelegate struct {
	nodes    []string
	items    *map[string]string
	delegate *delegate
}

type broadcast struct {
	msg    []byte
	notify chan<- struct{}
}

type delegate struct {
	mtx        *sync.RWMutex
	items      *map[string]string
	broadcasts *memberlist.TransmitLimitedQueue
}

type update struct {
	Action string // add, del
	Data   map[string]string
}

func (b *broadcast) Invalidates(other memberlist.Broadcast) bool {
	fmt.Println("------ func (b *broadcast) Invalidates(other memberlist.Broadcast) bool")

	return false
}

func (b *broadcast) Message() []byte {
	fmt.Println("------ func (b *broadcast) Message() []byte")

	return b.msg
}

func (b *broadcast) Finished() {
	fmt.Println("------ func (b *broadcast) Finished()")

	if b.notify != nil {
		close(b.notify)
	}
}

func (d *delegate) NodeMeta(limit int) []byte {
	fmt.Println("------ func (d *delegate) NodeMeta(limit int) []byte")

	return []byte{}
}

func (d *delegate) NotifyMsg(b []byte) {
	// fmt.Println("------ func (d *delegate) NotifyMsg(b []byte)")

	if len(b) == 0 {
		return
	}

	fmt.Println("------ func (d *delegate) NotifyMsg:: b:", string(b))

	switch b[0] {
	case 'd': // data
		var updates []*update
		if err := json.Unmarshal(b[1:], &updates); err != nil {
			return
		}
		d.mtx.Lock()
		for _, u := range updates {
			for k, v := range u.Data {
				switch u.Action {
				case "add":
					(*d.items)[k] = v
				case "del":
					delete(*d.items, k)
				}
			}
		}
		d.mtx.Unlock()
	}
}

func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte {
	// fmt.Println("------ func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte")

	ret := d.broadcasts.GetBroadcasts(overhead, limit)

	// fmt.Println("ret:", ret)

	return ret
}

func (d *delegate) LocalState(join bool) []byte {
	fmt.Println("------ func (d *delegate) LocalState(join bool) []byte: join:", join)

	d.mtx.RLock()
	m := d.items
	d.mtx.RUnlock()
	b, _ := json.Marshal(m)
	return b
}

func (d *delegate) MergeRemoteState(buf []byte, join bool) {
	fmt.Println("------ func (d *delegate) MergeRemoteState(buf []byte, join bool)")

	if len(buf) == 0 {
		return
	}
	if !join {
		return
	}
	var m map[string]string
	if err := json.Unmarshal(buf, &m); err != nil {
		return
	}
	d.mtx.Lock()
	for k, v := range m {
		(*d.items)[k] = v
	}
	d.mtx.Unlock()
}

func (ed *eventDelegate) NotifyJoin(node *memberlist.Node) {
	fmt.Println("------ func (ed *eventDelegate) NotifyJoin(node *memberlist.Node)")

	fmt.Println("A node has joined: "+node.String(), "node.FullAddress().Addr:", node.FullAddress().Addr)

	ed.nodes = append(ed.nodes, node.FullAddress().Addr)

	fmt.Println("ed.nodes:", ed.nodes)
}

func remove(slice []string, s int) []string {
	fmt.Println("------ func remove(slice []string, s int) []string")

	return append(slice[:s], slice[s+1:]...)
}

func (ed *eventDelegate) NotifyLeave(node *memberlist.Node) {
	fmt.Println("------ func (ed *eventDelegate) NotifyLeave(node *memberlist.Node)")

	fmt.Println("A node has left: "+node.String(), node.FullAddress().Addr)

	index := -1

	for ni, n := range ed.nodes {
		if n == node.FullAddress().Addr {
			index = ni
		}
	}

	if index >= 0 {
		ed.nodes = remove(ed.nodes, index)
	}

	fmt.Println("ed.nodes:", ed.nodes)

	for i := range *ed.items {
		fmt.Println("i:", i)

		if i == node.FullAddress().Addr {
			fmt.Println("Removing", node.FullAddress().Addr, "from list")
			delete(*ed.items, i)
		}
	}
}

func (ed *eventDelegate) NotifyUpdate(node *memberlist.Node) {
	fmt.Println("------ func (ed *eventDelegate) NotifyUpdate(node *memberlist.Node)")

	fmt.Println("A node was updated: " + node.String())
}

func (s *SimpleCluster) startWithPort(port int) (*eventDelegate, *memberlist.Memberlist, error) {
	fmt.Println("------ func startWithPort(port int) (*eventDelegate, *memberlist.Memberlist, error)")

	_delegate := &delegate{
		mtx:   &s.mtx,
		items: &s.items,
	}

	_eventDelegate := &eventDelegate{
		nodes:    []string{},
		items:    &s.items,
		delegate: _delegate,
	}

	hostname, _ := os.Hostname()
	c := memberlist.DefaultLocalConfig()
	c.Events = _eventDelegate
	c.Delegate = _delegate
	// c.BindPort = 0
	c.Name = hostname + "-" + uuid.NewUUID().String()
	c.BindPort = port

	m, err := memberlist.Create(c)

	return _eventDelegate, m, err
}

func NewSimpleCluster(server *Server) *SimpleCluster {
	fmt.Println("------ app/simple_cluster.go:: func NewSimpleCluster(s *Server) *SimpleCluster")

	items := map[string]string{}
	start_time := time.Now().Unix()

	s := &SimpleCluster{
		server:          server,
		messageHandlers: map[string]*einterfaces.ClusterMessageHandler{},

		mtx:   sync.RWMutex{},
		items: items,

		start_time: start_time,
	}

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

	eventDelegate, m, err := s.startWithPort(0)

	s.eventDelegate = eventDelegate

	this_node := m.LocalNode()
	s.this_node = this_node

	go func() {
		for {
			redisClient.SetEX(context.TODO(), "some-key-"+this_node.Address(), s.start_time, time.Second*60)

			time.Sleep(time.Second * 30)
		}
	}()

	go func() {
		for {
			master_node := ""
			oldest_time := int64(0)

			for k, v := range s.items {
				_v, _ := strconv.ParseInt(v, 10, 64)

				fmt.Println("k:", k, "_v:", _v, "oldest_time:", oldest_time, "oldest_time <= _v:", oldest_time <= _v)

				if oldest_time == 0 || oldest_time >= _v {
					master_node = k
					oldest_time = _v
				}
			}

			fmt.Println("s.this_node.Address()", this_node.Address())

			if master_node == this_node.Address() {
				fmt.Println("------------------------->>>> I'm the master!")

				s.isMaster = true
			} else {
				s.isMaster = false
			}

			fmt.Println("s.items:", s.items)

			time.Sleep(time.Second * 10)
		}
	}()

	ret := redisClient.Keys(context.TODO(), s.clusterDomain+"-*")

	keys, err := ret.Result()

	fmt.Println("ret:", ret, "keys:", keys)

	_keys := []string{}

	for _, key := range keys {
		_keys = append(_keys, strings.Split(key, s.clusterDomain+"-")[1])
	}

	fmt.Println("_keys:", _keys)

	m.Join(_keys)

	broadcasts := &memberlist.TransmitLimitedQueue{
		NumNodes: func() int {
			return m.NumMembers()
		},
		RetransmitMult: 3,
	}

	s.broadcasts = broadcasts
	eventDelegate.delegate.broadcasts = broadcasts

	fmt.Println("s.broadcasts:", s.broadcasts)

	items[this_node.Address()] = fmt.Sprintf("%v", start_time)

	u := &update{
		Action: "add",
		Data:   map[string]string{},
	}

	u.Data[this_node.Address()] = fmt.Sprintf("%v", start_time)

	b, err := json.Marshal([]*update{u})

	if err != nil {
		return nil
	}

	broadcasts.QueueBroadcast(&broadcast{
		msg:    append([]byte("d"), b...),
		notify: nil,
	})

	go func() {
		for {
			redisClient.SetEX(context.TODO(), s.clusterDomain+"-"+this_node.Address(), start_time, time.Second*60)

			time.Sleep(time.Second * 30)
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
	return s.isMaster
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
