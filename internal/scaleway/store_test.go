package scaleway_test

import (
	"context"
	"errors"
	"testing"

	"github.com/optimiweb/autocert/internal/cache"
	"github.com/optimiweb/autocert/internal/config"
	"github.com/optimiweb/autocert/internal/scaleway"
	secret "github.com/scaleway/scaleway-sdk-go/api/secret/v1beta1"
	"github.com/scaleway/scaleway-sdk-go/scw"
)

func TestIsNotFound(t *testing.T) {
	if !scaleway.IsNotFound(&scw.ResourceNotFoundError{Resource: "secret", ResourceID: "id"}) {
		t.Fatal("ResourceNotFoundError should be not found")
	}
	if !scaleway.IsNotFound(&scw.ResponseError{StatusCode: 404, Message: "missing"}) {
		t.Fatal("ResponseError 404 should be not found")
	}
	if scaleway.IsNotFound(&scw.ResponseError{StatusCode: 500, Message: "boom"}) {
		t.Fatal("ResponseError 500 should not be not found")
	}
	if scaleway.IsNotFound(errors.New("other")) {
		t.Fatal("generic error should not be not found")
	}
}

func TestStoreReadMapsNotFoundToCacheMiss(t *testing.T) {
	api := &fakeSecretAPI{
		accessErr: &scw.ResourceNotFoundError{Resource: "secret_version", ResourceID: "1"},
	}
	store := scaleway.NewStore(api, config.Config{
		Scaleway: config.ScalewayConfig{
			ProjectID:  "project",
			Region:     scw.RegionFrPar,
			SecretPath: "/autocert",
		},
	})
	_, err := store.Read(context.Background(), "secret-id")
	if !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("error = %v, want cache miss", err)
	}
}

func TestStoreFindExactNameAndPath(t *testing.T) {
	api := &fakeSecretAPI{
		list: &secret.ListSecretsResponse{
			Secrets: []*secret.Secret{
				{ID: "other", Name: "name", Path: "/other"},
				{ID: "wanted", Name: "name", Path: "/autocert"},
			},
		},
	}
	store := scaleway.NewStore(api, config.Config{
		Scaleway: config.ScalewayConfig{
			ProjectID:  "project",
			Region:     scw.RegionFrPar,
			SecretPath: "/autocert",
		},
	})
	id, err := store.Find(context.Background(), "name")
	if err != nil {
		t.Fatal(err)
	}
	if id != "wanted" {
		t.Fatalf("id = %q, want wanted", id)
	}
}

func TestStoreFindPaginates(t *testing.T) {
	api := &fakeSecretAPI{
		lists: []*secret.ListSecretsResponse{
			{Secrets: []*secret.Secret{{ID: "other", Name: "other", Path: "/autocert"}}, TotalCount: 101},
			{Secrets: []*secret.Secret{{ID: "wanted", Name: "name", Path: "/autocert"}}, TotalCount: 101},
		},
	}
	store := scaleway.NewStore(api, config.Config{
		Scaleway: config.ScalewayConfig{
			ProjectID:  "project",
			Region:     scw.RegionFrPar,
			SecretPath: "/autocert",
		},
	})
	id, err := store.Find(context.Background(), "name")
	if err != nil {
		t.Fatal(err)
	}
	if id != "wanted" {
		t.Fatalf("id = %q, want wanted", id)
	}
	if api.listCalls != 2 {
		t.Fatalf("list calls = %d, want 2", api.listCalls)
	}
}

func TestStoreCreateUsesConfiguredPath(t *testing.T) {
	api := &fakeSecretAPI{}
	store := scaleway.NewStore(api, config.Config{
		Scaleway: config.ScalewayConfig{
			ProjectID:  "project",
			Region:     scw.RegionFrPar,
			SecretPath: "/autocert",
			KeyID:      "key",
		},
	})
	id, err := store.Create(context.Background(), cache.SecretMeta{
		Name: "secret-name",
		Type: cache.SecretTypeOpaque,
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != "created-id" {
		t.Fatalf("id = %q", id)
	}
	if api.createReq == nil || api.createReq.Path == nil || *api.createReq.Path != "/autocert" {
		t.Fatalf("create path = %+v", api.createReq)
	}
	if api.createReq.KeyID == nil || *api.createReq.KeyID != "key" {
		t.Fatalf("create key = %+v", api.createReq.KeyID)
	}
}

func TestStoreCreateSetsType(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in       cache.SecretType
		want     secret.SecretType
	}{
		{"opaque", cache.SecretTypeOpaque, secret.SecretTypeOpaque},
		{"certificate", cache.SecretTypeCertificate, secret.SecretTypeCertificate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeSecretAPI{}
			store := scaleway.NewStore(api, config.Config{
				Scaleway: config.ScalewayConfig{
					ProjectID:  "project",
					Region:     scw.RegionFrPar,
					SecretPath: "/autocert",
				},
			})
			if _, err := store.Create(context.Background(), cache.SecretMeta{
				Name: "secret-name",
				Type: tc.in,
			}); err != nil {
				t.Fatal(err)
			}
			if api.createReq == nil || api.createReq.Type != tc.want {
				t.Fatalf("type = %v, want %v", api.createReq, tc.want)
			}
		})
	}
}

type fakeSecretAPI struct {
	list      *secret.ListSecretsResponse
	lists     []*secret.ListSecretsResponse
	listCalls int
	accessErr error
	createReq *secret.CreateSecretRequest
}

func (f *fakeSecretAPI) ListSecrets(*secret.ListSecretsRequest, ...scw.RequestOption) (*secret.ListSecretsResponse, error) {
	if len(f.lists) > 0 {
		index := f.listCalls
		f.listCalls++
		if index < len(f.lists) {
			return f.lists[index], nil
		}
		return &secret.ListSecretsResponse{}, nil
	}
	if f.list == nil {
		return &secret.ListSecretsResponse{}, nil
	}
	return f.list, nil
}

func (f *fakeSecretAPI) AccessSecretVersion(*secret.AccessSecretVersionRequest, ...scw.RequestOption) (*secret.AccessSecretVersionResponse, error) {
	return nil, f.accessErr
}

func (f *fakeSecretAPI) CreateSecret(req *secret.CreateSecretRequest, _ ...scw.RequestOption) (*secret.Secret, error) {
	f.createReq = req
	return &secret.Secret{ID: "created-id", Name: req.Name}, nil
}

func (f *fakeSecretAPI) CreateSecretVersion(*secret.CreateSecretVersionRequest, ...scw.RequestOption) (*secret.SecretVersion, error) {
	return &secret.SecretVersion{}, nil
}

func (f *fakeSecretAPI) DisableSecretVersion(*secret.DisableSecretVersionRequest, ...scw.RequestOption) (*secret.SecretVersion, error) {
	return &secret.SecretVersion{}, nil
}
