package scaleway

import (
	"context"
	"errors"

	secret "github.com/scaleway/scaleway-sdk-go/api/secret/v1beta1"
	"github.com/scaleway/scaleway-sdk-go/scw"

	"github.com/optimiweb/autocert/internal/cache"
	"github.com/optimiweb/autocert/internal/config"
)

// Store implements cache.Store using Scaleway Secret Manager.
type Store struct {
	api       secretAPI
	projectID string
	region    scw.Region
	keyID     string
	path      string
}

type secretAPI interface {
	ListSecrets(req *secret.ListSecretsRequest, opts ...scw.RequestOption) (*secret.ListSecretsResponse, error)
	AccessSecretVersion(req *secret.AccessSecretVersionRequest, opts ...scw.RequestOption) (*secret.AccessSecretVersionResponse, error)
	CreateSecret(req *secret.CreateSecretRequest, opts ...scw.RequestOption) (*secret.Secret, error)
	CreateSecretVersion(req *secret.CreateSecretVersionRequest, opts ...scw.RequestOption) (*secret.SecretVersion, error)
	DisableSecretVersion(req *secret.DisableSecretVersionRequest, opts ...scw.RequestOption) (*secret.SecretVersion, error)
}

func NewCache(client *scw.Client, cfg config.Config) *cache.Cache {
	return cache.New(NewStore(secret.NewAPI(client), cfg), cfg.Scaleway.SecretPrefix)
}

func NewStore(api secretAPI, cfg config.Config) *Store {
	return &Store{
		api:       api,
		projectID: cfg.Scaleway.ProjectID,
		region:    cfg.Scaleway.Region,
		keyID:     cfg.Scaleway.KeyID,
		path:      cfg.Scaleway.SecretPath,
	}
}

func (s *Store) Find(ctx context.Context, name string) (string, error) {
	projectID := s.projectID
	path := s.path
	pageSize := uint32(100)
	page := int32(1)
	for {
		secrets, err := s.api.ListSecrets(&secret.ListSecretsRequest{
			Region:    s.region,
			ProjectID: &projectID,
			Name:      &name,
			Path:      &path,
			Page:      &page,
			PageSize:  &pageSize,
		}, scw.WithContext(ctx))
		if err != nil {
			return "", err
		}
		for _, item := range secrets.Secrets {
			if item.Name == name && item.Path == s.path {
				return item.ID, nil
			}
		}
		if uint64(page)*uint64(pageSize) >= secrets.TotalCount {
			break
		}
		page++
	}
	return "", cache.ErrNotFound
}

func (s *Store) Read(ctx context.Context, id string) ([]byte, error) {
	version, err := s.api.AccessSecretVersion(&secret.AccessSecretVersionRequest{
		Region:   s.region,
		SecretID: id,
		Revision: "latest_enabled",
	}, scw.WithContext(ctx))
	if IsNotFound(err) {
		return nil, cache.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return version.Data, nil
}

func (s *Store) Create(ctx context.Context, name string) (string, error) {
	path := s.path
	request := &secret.CreateSecretRequest{
		Region:    s.region,
		ProjectID: s.projectID,
		Name:      name,
		Path:      &path,
		Tags:      []string{"autocert"},
	}
	if s.keyID != "" {
		request.KeyID = &s.keyID
	}
	created, err := s.api.CreateSecret(request, scw.WithContext(ctx))
	if err == nil {
		return created.ID, nil
	}
	if id, findErr := s.Find(ctx, name); findErr == nil {
		return id, nil
	}
	return "", err
}

func (s *Store) Write(ctx context.Context, id string, data []byte) error {
	disablePrevious := true
	_, err := s.api.CreateSecretVersion(&secret.CreateSecretVersionRequest{
		Region:          s.region,
		SecretID:        id,
		Data:            data,
		DisablePrevious: &disablePrevious,
	}, scw.WithContext(ctx))
	return err
}

func (s *Store) DisableLatest(ctx context.Context, id string) error {
	_, err := s.api.DisableSecretVersion(&secret.DisableSecretVersionRequest{
		Region:   s.region,
		SecretID: id,
		Revision: "latest_enabled",
	}, scw.WithContext(ctx))
	if IsNotFound(err) {
		return nil
	}
	return err
}

// IsNotFound reports whether err represents a missing Scaleway resource.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	var notFound *scw.ResourceNotFoundError
	if errors.As(err, &notFound) {
		return true
	}
	var responseErr *scw.ResponseError
	if errors.As(err, &responseErr) && responseErr.StatusCode == 404 {
		return true
	}
	return false
}

// Ensure Store satisfies cache.Store at compile time.
var _ cache.Store = (*Store)(nil)
