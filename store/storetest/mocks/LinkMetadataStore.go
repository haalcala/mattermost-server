// Code generated by mockery v1.0.0. DO NOT EDIT.

// Regenerate this file using `make store-mocks`.

package mocks

import (
	model "bitbucket.org/v-cube/mattermost-server/v5/model"
	mock "github.com/stretchr/testify/mock"
)

// LinkMetadataStore is an autogenerated mock type for the LinkMetadataStore type
type LinkMetadataStore struct {
	mock.Mock
}

// Get provides a mock function with given fields: url, timestamp
func (_m *LinkMetadataStore) Get(url string, timestamp int64) (*model.LinkMetadata, error) {
	ret := _m.Called(url, timestamp)

	var r0 *model.LinkMetadata
	if rf, ok := ret.Get(0).(func(string, int64) *model.LinkMetadata); ok {
		r0 = rf(url, timestamp)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.LinkMetadata)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, int64) error); ok {
		r1 = rf(url, timestamp)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Save provides a mock function with given fields: linkMetadata
func (_m *LinkMetadataStore) Save(linkMetadata *model.LinkMetadata) (*model.LinkMetadata, error) {
	ret := _m.Called(linkMetadata)

	var r0 *model.LinkMetadata
	if rf, ok := ret.Get(0).(func(*model.LinkMetadata) *model.LinkMetadata); ok {
		r0 = rf(linkMetadata)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.LinkMetadata)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.LinkMetadata) error); ok {
		r1 = rf(linkMetadata)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
