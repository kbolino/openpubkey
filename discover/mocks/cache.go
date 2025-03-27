package mocks

import (
	"context"
	"slices"
	"sync"
	"time"
)

type MockJwksFetchWithExpiresCall struct {
	ArgCtx    context.Context
	ArgIssuer string

	RetValue   []byte
	RetExpires time.Time
	RetErr     error
}

type MockJwksFetchWithExpiresFunc struct {
	mutex       sync.Mutex
	calls       []MockJwksFetchWithExpiresCall
	nextValue   []byte
	nextExpires time.Time
	nextErr     error
}

func NewMockJwksFetchWithExpiresFunc() *MockJwksFetchWithExpiresFunc {
	return &MockJwksFetchWithExpiresFunc{}
}

func (f *MockJwksFetchWithExpiresFunc) Call(ctx context.Context, issuer string) (value []byte, expires time.Time, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.calls = append(f.calls, MockJwksFetchWithExpiresCall{
		ArgCtx:     ctx,
		ArgIssuer:  issuer,
		RetValue:   f.nextValue,
		RetExpires: f.nextExpires,
		RetErr:     f.nextErr,
	})
	return f.nextValue, f.nextExpires, f.nextErr
}

func (f *MockJwksFetchWithExpiresFunc) Reset() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.calls = nil
}

func (f *MockJwksFetchWithExpiresFunc) Calls() []MockJwksFetchWithExpiresCall {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return slices.Clone(f.calls)
}

func (f *MockJwksFetchWithExpiresFunc) Return(value []byte, expires time.Time, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.nextValue = value
	f.nextExpires = expires
	f.nextErr = err
}

type MockClock struct {
	mutex sync.Mutex
	now   time.Time
}

func NewMockClock(now time.Time) *MockClock {
	return &MockClock{now: now}
}

func (c *MockClock) Now() time.Time {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.now
}

func (c *MockClock) Add(diff time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.now = c.now.Add(diff)
}
