package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

type JupyterHubProvider struct {
	*ProviderData
}

var _ Provider = (*JupyterHubProvider)(nil)

const (
	jupyterhubProviderName = "JupyterHub"
	jupyterhubDefaultScope = "identify"
)

var (
	// Default Login URL for JupyterHub.
	jupyterhubDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "jupyterhub.example.com",
		Path:   "/hub/api/oauth2/authorize",
	}

	// Default Redeem URL for JupyterHub.
	jupyterhubDefaultRedeemURL = &url.URL{
		Scheme: "http",
		Host:   "internal.jupyterhub.example.com:8000",
		Path:   "/hub/api/oauth2/token",
	}

	// Default Validation URL for JupyterHub.
	jupyterhubDefaultValidateURL = &url.URL{
		Scheme: "http",
		Host:   "internal.jupyterhub.example.com:8000",
		Path:   "/hub/api/user",
	}
)

// NewJupyterHubProvider creates a JupyterHubProvider using the passed ProviderData
func NewJupyterHubProvider(p *ProviderData) *JupyterHubProvider {
	p.setProviderDefaults(providerDefaults{
		name:        jupyterhubProviderName,
		loginURL:    jupyterhubDefaultLoginURL,
		redeemURL:   jupyterhubDefaultRedeemURL,
		profileURL:  nil,
		validateURL: jupyterhubDefaultValidateURL,
		scope:       jupyterhubDefaultScope,
	})

	provider := &JupyterHubProvider{ProviderData: p}
	return provider
}

// EnrichSession uses the JupyterHub userinfo endpoint to populate the session's
// name.
func (p *JupyterHubProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Fallback to ValidateURL if ProfileURL not set for legacy compatibility
	profileURL := p.ValidateURL.String()
	if p.ProfileURL.String() != "" {
		profileURL = p.ProfileURL.String()
	}

	json, err := requests.New(profileURL).
		WithContext(ctx).
		SetHeader("Authorization", tokenTypeBearer+" "+s.AccessToken).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		logger.Errorf("failed making request %v", err)
		return err
	}

	name, err := json.Get("name").String()
	if err != nil {
		return fmt.Errorf("unable to extract name from userinfo endpoint: %v", err)
	}
	s.Email = fmt.Sprintf("%s@example.com", name)

	preferredUsername, err := json.Get("preferred_username").String()
	if err == nil {
		s.PreferredUsername = preferredUsername
	}

	s.User = name
	return nil
}

// ValidateSession validates the AccessToken
func (p *JupyterHubProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
