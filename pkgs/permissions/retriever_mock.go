package permissions

import (
	"context"
	"sync"
	"testing"
)

type mockedMethods struct {
	permissionsMock func(context.Context, []string, string, ...RetrieverOption) (PermissionMap, error)
	revokedMock     func(context.Context, string, string, []string) (bool, error)
}

// A MockRetriever allows to mock a permissions.Retriever for unit tests.
type MockRetriever interface {
	Retriever
	MockPermissions(t *testing.T, impl func(context.Context, []string, string, ...RetrieverOption) (PermissionMap, error))
	MockRevoked(t *testing.T, impl func(context.Context, string, string, []string) (bool, error))
}

type mockRetriever struct {
	mocks       map[*testing.T]*mockedMethods
	currentTest *testing.T

	sync.Mutex
}

// NewMockRetriever returns a MockRetriever.
func NewMockRetriever() MockRetriever {
	return &mockRetriever{
		mocks: map[*testing.T]*mockedMethods{},
	}
}

// MockPermissions replaces the Permission implementation with the given function.
func (r *mockRetriever) MockPermissions(t *testing.T, impl func(context.Context, []string, string, ...RetrieverOption) (PermissionMap, error)) {

	r.Lock()
	defer r.Unlock()

	r.currentMocks(t).permissionsMock = impl
}

// MockRevoked replaces the Revoked implementation with the given function.
func (r *mockRetriever) MockRevoked(t *testing.T, impl func(context.Context, string, string, []string) (bool, error)) {

	r.Lock()
	defer r.Unlock()

	r.currentMocks(t).revokedMock = impl
}

func (r *mockRetriever) Permissions(ctx context.Context, claims []string, ns string, opts ...RetrieverOption) (PermissionMap, error) {

	r.Lock()
	defer r.Unlock()

	if mock := r.currentMocks(r.currentTest); mock != nil && mock.permissionsMock != nil {
		return mock.permissionsMock(ctx, claims, ns, opts...)
	}

	return PermissionMap{}, nil
}

func (r *mockRetriever) Revoked(ctx context.Context, namespace string, tokenID string, claims []string) (bool, error) {

	r.Lock()
	defer r.Unlock()

	if mock := r.currentMocks(r.currentTest); mock != nil && mock.revokedMock != nil {
		return mock.revokedMock(ctx, namespace, tokenID, claims)
	}

	return false, nil
}

func (r *mockRetriever) currentMocks(t *testing.T) *mockedMethods {

	mocks := r.mocks[t]

	if mocks == nil {
		mocks = &mockedMethods{}
		r.mocks[t] = mocks
	}

	r.currentTest = t
	return mocks
}
