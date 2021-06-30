// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package sqlstore

import (
	"testing"

	"bitbucket.org/v-cube/mattermost-server/v5/store/storetest"
)

func TestSessionStore(t *testing.T) {
	StoreTest(t, storetest.TestSessionStore)
}
