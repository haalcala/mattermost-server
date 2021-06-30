// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package product_notices

import (
	"bitbucket.org/v-cube/mattermost-server/v5/app"
	tjobs "bitbucket.org/v-cube/mattermost-server/v5/jobs/interfaces"
)

type ProductNoticesJobInterfaceImpl struct {
	App *app.App
}

func init() {
	app.RegisterProductNoticesJobInterface(func(a *app.App) tjobs.ProductNoticesJobInterface {
		return &ProductNoticesJobInterfaceImpl{a}
	})
}
