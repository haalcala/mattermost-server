// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package commands

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/mattermost/mattermost-server/v5/api4"
	"github.com/mattermost/mattermost-server/v5/app"
	"github.com/mattermost/mattermost-server/v5/config"
	"github.com/mattermost/mattermost-server/v5/manualtesting"
	"github.com/mattermost/mattermost-server/v5/mlog"
	"github.com/mattermost/mattermost-server/v5/utils"
	"github.com/mattermost/mattermost-server/v5/web"
	"github.com/mattermost/mattermost-server/v5/wsapi"
	"github.com/mattermost/viper"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:          "server",
	Short:        "Run the Mattermost server",
	RunE:         serverCmdF,
	SilenceUsage: true,
}

func init() {
	RootCmd.AddCommand(serverCmd)
	RootCmd.RunE = serverCmdF
}

func serverCmdF(command *cobra.Command, args []string) error {
	configDSN := viper.GetString("config")

	disableConfigWatch, _ := command.Flags().GetBool("disableconfigwatch")
	usedPlatform, _ := command.Flags().GetBool("platform")

	interruptChan := make(chan os.Signal, 1)

	if err := utils.TranslationsPreInit(); err != nil {
		return errors.Wrapf(err, "unable to load Mattermost translation files")
	}
	configStore, err := config.NewStore(configDSN, !disableConfigWatch)
	if err != nil {
		return errors.Wrap(err, "failed to load configuration")
	}

	return runServer(configStore, disableConfigWatch, usedPlatform, interruptChan)
}

func runServer(configStore config.Store, disableConfigWatch bool, usedPlatform bool, interruptChan chan os.Signal) error {
	fmt.Println("func runServer(configStore config.Store, disableConfigWatch bool, usedPlatform bool, interruptChan chan os.Signal) error {")

	options := []app.Option{
		app.ConfigStore(configStore),
		app.RunJobs,
		app.JoinCluster,
		app.StartElasticsearch,
		app.StartMetrics,
	}
	server, err := app.NewServer(options...)
	if err != nil {
		mlog.Critical(err.Error())
		return err
	}
	defer server.Shutdown()

	if usedPlatform {
		mlog.Error("The platform binary has been deprecated, please switch to using the mattermost binary.")
	}

	api := api4.Init(server, server.AppOptions, server.Router)
	wsapi.Init(server.FakeApp(), server.WebSocketRouter)
	web.New(server, server.AppOptions, server.Router)

	serverErr := server.Start()
	if serverErr != nil {
		mlog.Critical(serverErr.Error())
		return serverErr
	}

	// If we allow testing then listen for manual testing URL hits
	if *server.Config().ServiceSettings.EnableTesting {
		manualtesting.Init(api)
	}

	notifyReady()

	// wait for kill signal before attempting to gracefully shutdown
	// the running service
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-interruptChan

	return nil
}

func notifyReady() {
	// If the environment vars provide a systemd notification socket,
	// notify systemd that the server is ready.
	systemdSocket := os.Getenv("NOTIFY_SOCKET")
	if systemdSocket != "" {
		mlog.Info("Sending systemd READY notification.")

		err := sendSystemdReadyNotification(systemdSocket)
		if err != nil {
			mlog.Error(err.Error())
		}
	}
}

func sendSystemdReadyNotification(socketPath string) error {
	msg := "READY=1"
	addr := &net.UnixAddr{
		Name: socketPath,
		Net:  "unixgram",
	}
	conn, err := net.DialUnix(addr.Net, nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(msg))
	return err
}
