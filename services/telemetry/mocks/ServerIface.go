// Code generated by mockery v1.0.0. DO NOT EDIT.

// Regenerate this file using `make telemetry-mocks`.

package mocks

import (
	httpservice "bitbucket.org/v-cube/mattermost-server/v5/services/httpservice"
	mock "github.com/stretchr/testify/mock"

	model "bitbucket.org/v-cube/mattermost-server/v5/model"

	plugin "bitbucket.org/v-cube/mattermost-server/v5/plugin"
)

// ServerIface is an autogenerated mock type for the ServerIface type
type ServerIface struct {
	mock.Mock
}

// Config provides a mock function with given fields:
func (_m *ServerIface) Config() *model.Config {
	ret := _m.Called()

	var r0 *model.Config
	if rf, ok := ret.Get(0).(func() *model.Config); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Config)
		}
	}

	return r0
}

// GetPluginsEnvironment provides a mock function with given fields:
func (_m *ServerIface) GetPluginsEnvironment() *plugin.Environment {
	ret := _m.Called()

	var r0 *plugin.Environment
	if rf, ok := ret.Get(0).(func() *plugin.Environment); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*plugin.Environment)
		}
	}

	return r0
}

// GetRoleByName provides a mock function with given fields: _a0
func (_m *ServerIface) GetRoleByName(_a0 string) (*model.Role, *model.AppError) {
	ret := _m.Called(_a0)

	var r0 *model.Role
	if rf, ok := ret.Get(0).(func(string) *model.Role); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Role)
		}
	}

	var r1 *model.AppError
	if rf, ok := ret.Get(1).(func(string) *model.AppError); ok {
		r1 = rf(_a0)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*model.AppError)
		}
	}

	return r0, r1
}

// GetSchemes provides a mock function with given fields: _a0, _a1, _a2
func (_m *ServerIface) GetSchemes(_a0 string, _a1 int, _a2 int) ([]*model.Scheme, *model.AppError) {
	ret := _m.Called(_a0, _a1, _a2)

	var r0 []*model.Scheme
	if rf, ok := ret.Get(0).(func(string, int, int) []*model.Scheme); ok {
		r0 = rf(_a0, _a1, _a2)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Scheme)
		}
	}

	var r1 *model.AppError
	if rf, ok := ret.Get(1).(func(string, int, int) *model.AppError); ok {
		r1 = rf(_a0, _a1, _a2)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*model.AppError)
		}
	}

	return r0, r1
}

// HttpService provides a mock function with given fields:
func (_m *ServerIface) HttpService() httpservice.HTTPService {
	ret := _m.Called()

	var r0 httpservice.HTTPService
	if rf, ok := ret.Get(0).(func() httpservice.HTTPService); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(httpservice.HTTPService)
		}
	}

	return r0
}

// IsLeader provides a mock function with given fields:
func (_m *ServerIface) IsLeader() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// License provides a mock function with given fields:
func (_m *ServerIface) License() *model.License {
	ret := _m.Called()

	var r0 *model.License
	if rf, ok := ret.Get(0).(func() *model.License); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.License)
		}
	}

	return r0
}
