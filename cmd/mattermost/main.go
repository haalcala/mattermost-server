// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/mattermost/mattermost-server/v5/cmd/mattermost/commands"

	// Plugins
	_ "github.com/mattermost/mattermost-server/v5/model/gitlab"

	// Enterprise Imports
	_ "github.com/mattermost/mattermost-server/v5/imports"

	// Enterprise Deps
	_ "github.com/gorilla/handlers"
	_ "github.com/hako/durafmt"
	_ "github.com/hashicorp/memberlist"
	_ "github.com/mattermost/gosaml2"
	_ "github.com/mattermost/ldap"
	_ "github.com/mattermost/rsc/qr"
	_ "github.com/prometheus/client_golang/prometheus"
	_ "github.com/prometheus/client_golang/prometheus/promhttp"
	_ "github.com/tylerb/graceful"
	_ "gopkg.in/olivere/elastic.v6"
)

func main() {
	timestamp := time.Now()

	workdir, err := os.Getwd()

	fmt.Println("------------------  cmd.mattermost.commands.main.go:: 1111 os.Args", os.Args, "timestamp:", timestamp, "os.Environ():", os.Environ(), "os.Getwd():", workdir, err)
	if err = commands.Run(os.Args[1:]); err != nil {
		fmt.Println("------------------  cmd.mattermost.commands.main.go:: 2222 os.Args", os.Args, "timestamp:", timestamp, time.Now().Sub(timestamp))

		os.Exit(1)
	}

	fmt.Println("------------------  cmd.mattermost.commands.main.go:: 3333 os.Args", os.Args, "timestamp:", timestamp, time.Now().Sub(timestamp))
}
