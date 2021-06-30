// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package slashcommands

import (
	goi18n "github.com/mattermost/go-i18n/i18n"

	"bitbucket.org/v-cube/mattermost-server/v5/app"
	"bitbucket.org/v-cube/mattermost-server/v5/model"
)

type OpenProvider struct {
	JoinProvider
}

const (
	CmdOpen = "open"
)

func init() {
	app.RegisterCommandProvider(&OpenProvider{})
}

func (open *OpenProvider) GetTrigger() string {
	return CmdOpen
}

func (open *OpenProvider) GetCommand(a *app.App, T goi18n.TranslateFunc) *model.Command {
	cmd := open.JoinProvider.GetCommand(a, T)
	cmd.Trigger = CmdOpen
	cmd.DisplayName = T("api.command_open.name")
	return cmd
}
