// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"fmt"
	"strings"

	"github.com/mattermost/mattermost-server/v5/model"
)

// RegisterAllClusterMessageHandlers registers the cluster message handlers that are handled by the App layer.
//
// The cluster event handlers are spread across this function and
// NewLocalCacheLayer. Be careful to not have duplicated handlers here and
// there.
func (a *App) registerAllClusterMessageHandlers() {
	fmt.Println("------ app/cluster_handlers.go:: func (a *App) registerAllClusterMessageHandlers() {")
	a.Cluster().RegisterClusterMessageHandler(model.CLUSTER_EVENT_PUBLISH, a.clusterPublishHandler)
	a.Cluster().RegisterClusterMessageHandler(model.CLUSTER_EVENT_UPDATE_STATUS, a.clusterUpdateStatusHandler)
	a.Cluster().RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_ALL_CACHES, a.clusterInvalidateAllCachesHandler)
	a.Cluster().RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_CHANNEL_MEMBERS_NOTIFY_PROPS, a.clusterInvalidateCacheForChannelMembersNotifyPropHandler)
	a.Cluster().RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_CHANNEL_BY_NAME, a.clusterInvalidateCacheForChannelByNameHandler)
	a.Cluster().RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_USER, a.clusterInvalidateCacheForUserHandler)
	a.Cluster().RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_USER_TEAMS, a.clusterInvalidateCacheForUserTeamsHandler)
	a.Cluster().RegisterClusterMessageHandler(model.CLUSTER_EVENT_CLEAR_SESSION_CACHE_FOR_USER, a.clusterClearSessionCacheForUserHandler)
	a.Cluster().RegisterClusterMessageHandler(model.CLUSTER_EVENT_CLEAR_SESSION_CACHE_FOR_ALL_USERS, a.clusterClearSessionCacheForAllUsersHandler)
	a.Cluster().RegisterClusterMessageHandler(model.CLUSTER_EVENT_INSTALL_PLUGIN, a.clusterInstallPluginHandler)
	a.Cluster().RegisterClusterMessageHandler(model.CLUSTER_EVENT_REMOVE_PLUGIN, a.clusterRemovePluginHandler)
	a.Cluster().RegisterClusterMessageHandler(model.CLUSTER_EVENT_BUSY_STATE_CHANGED, a.clusterBusyStateChgHandler)
}

func (a *App) clusterPublishHandler(msg *model.ClusterMessage) {
	fmt.Println("------ app/cluster_handlers.go:: func (a *App) clusterPublishHandler(msg *model.ClusterMessage) { msg:", msg)
	event := model.WebSocketEventFromJson(strings.NewReader(msg.Data))
	if event == nil {
		return
	}
	a.PublishSkipClusterSend(event)
}

func (a *App) clusterUpdateStatusHandler(msg *model.ClusterMessage) {
	fmt.Println("------ app/cluster_handlers.go:: func (a *App) clusterUpdateStatusHandler(msg *model.ClusterMessage) { msg:", msg)
	status := model.StatusFromJson(strings.NewReader(msg.Data))
	a.AddStatusCacheSkipClusterSend(status)
}

func (a *App) clusterInvalidateAllCachesHandler(msg *model.ClusterMessage) {
	fmt.Println("------ app/cluster_handlers.go:: func (a *App) clusterInvalidateAllCachesHandler(msg *model.ClusterMessage) { msg:", msg)
	a.InvalidateAllCachesSkipSend()
}

func (a *App) clusterInvalidateCacheForChannelMembersNotifyPropHandler(msg *model.ClusterMessage) {
	fmt.Println("------ app/cluster_handlers.go:: func (a *App) clusterInvalidateCacheForChannelMembersNotifyPropHandler(msg *model.ClusterMessage) { msg:", msg)
	a.InvalidateCacheForChannelMembersNotifyPropsSkipClusterSend(msg.Data)
}

func (a *App) clusterInvalidateCacheForChannelByNameHandler(msg *model.ClusterMessage) {
	fmt.Println("------ app/cluster_handlers.go:: func (a *App) clusterInvalidateCacheForChannelByNameHandler(msg *model.ClusterMessage) { msg:", msg)
	a.InvalidateCacheForChannelByNameSkipClusterSend(msg.Props["id"], msg.Props["name"])
}

func (a *App) clusterInvalidateCacheForUserHandler(msg *model.ClusterMessage) {
	fmt.Println("------ app/cluster_handlers.go:: func (a *App) clusterInvalidateCacheForUserHandler(msg *model.ClusterMessage) { msg:", msg)
	a.invalidateCacheForUserSkipClusterSend(msg.Data)
}

func (a *App) clusterInvalidateCacheForUserTeamsHandler(msg *model.ClusterMessage) {
	fmt.Println("------ app/cluster_handlers.go:: func (a *App) clusterInvalidateCacheForUserTeamsHandler(msg *model.ClusterMessage) { msg:", msg)
	a.InvalidateWebConnSessionCacheForUser(msg.Data)
}

func (a *App) clusterClearSessionCacheForUserHandler(msg *model.ClusterMessage) {
	fmt.Println("------ app/cluster_handlers.go:: func (a *App) clusterClearSessionCacheForUserHandler(msg *model.ClusterMessage) { msg:", msg)
	a.ClearSessionCacheForUserSkipClusterSend(msg.Data)
}

func (a *App) clusterClearSessionCacheForAllUsersHandler(msg *model.ClusterMessage) {
	fmt.Println("------ app/cluster_handlers.go:: func (a *App) clusterClearSessionCacheForAllUsersHandler(msg *model.ClusterMessage) { msg:", msg)
	a.ClearSessionCacheForAllUsersSkipClusterSend()
}

func (a *App) clusterInstallPluginHandler(msg *model.ClusterMessage) {
	fmt.Println("------ app/cluster_handlers.go:: func (a *App) clusterInstallPluginHandler(msg *model.ClusterMessage) { msg:", msg)
	a.InstallPluginFromData(model.PluginEventDataFromJson(strings.NewReader(msg.Data)))
}

func (a *App) clusterRemovePluginHandler(msg *model.ClusterMessage) {
	fmt.Println("------ app/cluster_handlers.go:: func (a *App) clusterRemovePluginHandler(msg *model.ClusterMessage) { msg:", msg)
	a.RemovePluginFromData(model.PluginEventDataFromJson(strings.NewReader(msg.Data)))
}

func (a *App) clusterBusyStateChgHandler(msg *model.ClusterMessage) {
	fmt.Println("------ app/cluster_handlers.go:: func (a *App) clusterBusyStateChgHandler(msg *model.ClusterMessage) { msg:", msg)
	a.ServerBusyStateChanged(model.ServerBusyStateFromJson(strings.NewReader(msg.Data)))
}
