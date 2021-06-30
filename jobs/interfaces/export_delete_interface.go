// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package interfaces

import "bitbucket.org/v-cube/mattermost-server/v5/model"

type ExportDeleteInterface interface {
	MakeWorker() model.Worker
	MakeScheduler() model.Scheduler
}
