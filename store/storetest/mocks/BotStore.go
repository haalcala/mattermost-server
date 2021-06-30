// Code generated by mockery v1.0.0. DO NOT EDIT.

// Regenerate this file using `make store-mocks`.

package mocks

import (
	model "bitbucket.org/v-cube/mattermost-server/v5/model"
	mock "github.com/stretchr/testify/mock"
)

// BotStore is an autogenerated mock type for the BotStore type
type BotStore struct {
	mock.Mock
}

// Get provides a mock function with given fields: userId, includeDeleted
func (_m *BotStore) Get(userId string, includeDeleted bool) (*model.Bot, error) {
	ret := _m.Called(userId, includeDeleted)

	var r0 *model.Bot
	if rf, ok := ret.Get(0).(func(string, bool) *model.Bot); ok {
		r0 = rf(userId, includeDeleted)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Bot)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, bool) error); ok {
		r1 = rf(userId, includeDeleted)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetAll provides a mock function with given fields: options
func (_m *BotStore) GetAll(options *model.BotGetOptions) ([]*model.Bot, error) {
	ret := _m.Called(options)

	var r0 []*model.Bot
	if rf, ok := ret.Get(0).(func(*model.BotGetOptions) []*model.Bot); ok {
		r0 = rf(options)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Bot)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.BotGetOptions) error); ok {
		r1 = rf(options)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PermanentDelete provides a mock function with given fields: userId
func (_m *BotStore) PermanentDelete(userId string) error {
	ret := _m.Called(userId)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(userId)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Save provides a mock function with given fields: bot
func (_m *BotStore) Save(bot *model.Bot) (*model.Bot, error) {
	ret := _m.Called(bot)

	var r0 *model.Bot
	if rf, ok := ret.Get(0).(func(*model.Bot) *model.Bot); ok {
		r0 = rf(bot)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Bot)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Bot) error); ok {
		r1 = rf(bot)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Update provides a mock function with given fields: bot
func (_m *BotStore) Update(bot *model.Bot) (*model.Bot, error) {
	ret := _m.Called(bot)

	var r0 *model.Bot
	if rf, ok := ret.Get(0).(func(*model.Bot) *model.Bot); ok {
		r0 = rf(bot)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Bot)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Bot) error); ok {
		r1 = rf(bot)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
