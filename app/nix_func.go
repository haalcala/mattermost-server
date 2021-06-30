// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

// +build linux darwin

package app

import "syscall"

func GetUlimit() uint64 {
	lim := syscall.Rlimit{}
	syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)

	return lim.Cur
}
