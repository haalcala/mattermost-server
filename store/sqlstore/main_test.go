// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package sqlstore_test

import (
	"testing"

	"bitbucket.org/v-cube/mattermost-server/v5/mlog"
	"bitbucket.org/v-cube/mattermost-server/v5/store/sqlstore"
	"bitbucket.org/v-cube/mattermost-server/v5/testlib"
)

var mainHelper *testlib.MainHelper

func TestMain(m *testing.M) {
	mlog.DisableZap()
	mainHelper = testlib.NewMainHelperWithOptions(nil)
	defer mainHelper.Close()

	sqlstore.InitTest()

	mainHelper.Main(m)
	sqlstore.TearDownTest()
}
