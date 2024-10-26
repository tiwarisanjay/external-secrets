package vault

import (
	"context"
	"errors"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/auth/gcp"
	"google.golang.org/api/option"
)

func setGCPAuthToken(ctx context.Context, v *client) (bool, error) {
	gcpAuth := v.store.Auth.GCP
	if gcpAuth != nil {
		err := v.requestTokenWithGCPAuth(ctx, gcpAuth)
		if err != nil {
			return true, err
		}
		return true, nil
	}
	return false, nil
}
func (c *client) requestTokenWithGCPAuth(ctx context.Context, gcpAuth *esv1beta1.VaultGCPAuth) error {
	gcpProjectID := gcpAuth.ProjectID
	// Create a new GCP auth client using the default credentials
	ctx := context.Background()
	gAuth, err := gcp.NewGCPAuthWithCredentials(ctx, &gcp.GCPAuthConfig{
		ProjectID: gcpProjectID,
	}, option.WithCredentialsFile(""))
	if err != nil {
		return err
	}

	// Authenticate with Vault using the GCP auth client
	auth, err := client.Auth().Login(context.Background(), &api.LoginInput{
		Auth: &api.Auth{
			Type: "gcp",
			Config: map[string]interface{}{
				"credentials":  gAuth.Credentials(),
				"jwt_validity": 15,
			},
		},
	})
	if err != nil {
		return err
	}
	return nil
}
