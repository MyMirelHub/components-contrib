/*
Copyright 2021 The Dapr Authors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oauth2

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	ccreds "golang.org/x/oauth2/clientcredentials"

	"github.com/dapr/kit/logger"
)

func Test_toConfig(t *testing.T) {
	tests := map[string]struct {
		opts      ClientCredentialsOptions
		expConfig *ccreds.Config
		expErr    bool
	}{
		"no scopes should error": {
			opts: ClientCredentialsOptions{
				TokenURL:     "https://localhost:8080",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				Audiences:    []string{"audience"},
			},
			expErr: true,
		},
		"bad URL endpoint should error": {
			opts: ClientCredentialsOptions{
				TokenURL:     "&&htp:/f url",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				Audiences:    []string{"audience"},
				Scopes:       []string{"foo"},
			},
			expErr: true,
		},
		"bad CA certificate should error": {
			opts: ClientCredentialsOptions{
				TokenURL:     "http://localhost:8080",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				Audiences:    []string{"audience"},
				Scopes:       []string{"foo"},
				CAPEM:        []byte("ca-pem"),
			},
			expErr: true,
		},
		"no audiences should error": {
			opts: ClientCredentialsOptions{
				TokenURL:     "http://localhost:8080",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				Scopes:       []string{"foo"},
			},
			expErr: true,
		},
		"should default scope": {
			opts: ClientCredentialsOptions{
				TokenURL:     "http://localhost:8080",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				Audiences:    []string{"audience"},
				Scopes:       []string{"foo", "bar"},
			},
			expConfig: &ccreds.Config{
				ClientID:       "client-id",
				ClientSecret:   "client-secret",
				TokenURL:       "http://localhost:8080",
				Scopes:         []string{"foo", "bar"},
				EndpointParams: url.Values{"audience": []string{"audience"}},
			},
			expErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config, _, err := test.opts.toConfig()
			assert.Equalf(t, test.expErr, err != nil, "%v", err)
			assert.Equal(t, test.expConfig, config)
		})
	}
}

func Test_TokenRenewal(t *testing.T) {
	expired := &oauth2.Token{AccessToken: "old-token", Expiry: time.Now().Add(-1 * time.Minute)}
	renewed := &oauth2.Token{AccessToken: "new-token", Expiry: time.Now().Add(1 * time.Hour)}

	c := &ClientCredentials{
		log:          logger.NewLogger("test"),
		currentToken: expired,
		fetchTokenFn: func(ctx context.Context) (*oauth2.Token, error) {
			return renewed, nil
		},
	}

	tok, err := c.Token()
	require.NoError(t, err)
	assert.Equal(t, "new-token", tok)
}

func TestLoadCredentialsFromJSONFile(t *testing.T) {
	tests := map[string]struct {
		fileContent     string
		expClientID     string
		expClientSecret string
		expErr          bool
		expErrContains  string
	}{
		"valid JSON with all required fields": {
			fileContent: `{
				"client_id": "test-id",
				"client_secret": "test-secret",
				"issuer_url": "https://oauth.example.com/token"
			}`,
			expClientID:     "test-id",
			expClientSecret: "test-secret",
		},
		"missing issuer_url": {
			fileContent: `{
				"client_id": "test-id",
				"client_secret": "test-secret"
			}`,
			expErr:         true,
			expErrContains: "issuer_url is required",
		},
		"missing client_id": {
			fileContent: `{
				"client_secret": "test-secret",
				"issuer_url": "https://oauth.example.com/token"
			}`,
			expErr:         true,
			expErrContains: "client_id is required",
		},
		"missing client_secret": {
			fileContent: `{
				"client_id": "test-id",
				"issuer_url": "https://oauth.example.com/token"
			}`,
			expErr:         true,
			expErrContains: "client_secret is required",
		},
		"invalid JSON": {
			fileContent:    "{ invalid json }",
			expErr:         true,
			expErrContains: "failed to parse JSON",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp(t.TempDir(), "credentials-*.json")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(test.fileContent)
			require.NoError(t, err)
			require.NoError(t, tmpFile.Close())

			clientID, clientSecret, issuerURL, err := LoadCredentialsFromJSONFile(tmpFile.Name())

			if test.expErr {
				require.Error(t, err)
				if test.expErrContains != "" {
					assert.Contains(t, err.Error(), test.expErrContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.expClientID, clientID)
				assert.Equal(t, test.expClientSecret, clientSecret)
				assert.NotEmpty(t, issuerURL)
			}
		})
	}

	t.Run("file not found", func(t *testing.T) {
		_, _, _, err := LoadCredentialsFromJSONFile("/nonexistent/file/path")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not read oauth2 credentials from file")
	})
}

func TestClientCredentialsMetadata_ResolveCredentials(t *testing.T) {
	tests := map[string]struct {
		metadata            ClientCredentialsMetadata
		credentialsFileJSON string // For oauth2CredentialsFile (JSON with both client_id and client_secret)
		plainTextSecret     string // For oauth2ClientSecretPath (plain text secret only)
		expClientID         string
		expClientSecret     string
		expTokenURL         string
		expErr              bool
		expErrContains      string
	}{
		"oauth2CredentialsFile with metadata ClientID override": {
			metadata: ClientCredentialsMetadata{
				ClientID: "metadata-id",
			},
			credentialsFileJSON: `{
				"client_id": "file-id",
				"client_secret": "file-secret",
				"issuer_url": "https://oauth.example.com/token"
			}`,
			expClientID:     "metadata-id",
			expClientSecret: "file-secret",
			expTokenURL:     "https://oauth.example.com/token",
		},
		"oauth2CredentialsFile with metadata ClientSecret override": {
			metadata: ClientCredentialsMetadata{
				ClientSecret: "metadata-secret",
			},
			credentialsFileJSON: `{
				"client_id": "file-id",
				"client_secret": "file-secret",
				"issuer_url": "https://oauth.example.com/token"
			}`,
			expClientID:     "file-id",
			expClientSecret: "metadata-secret",
			expTokenURL:     "https://oauth.example.com/token",
		},
		"oauth2CredentialsFile provides issuer_url as TokenURL": {
			metadata: ClientCredentialsMetadata{},
			credentialsFileJSON: `{
				"client_id": "file-id",
				"client_secret": "file-secret",
				"issuer_url": "https://oauth.example.com/o/oauth2/token"
			}`,
			expClientID:     "file-id",
			expClientSecret: "file-secret",
			expTokenURL:     "https://oauth.example.com/o/oauth2/token",
		},
		"oauth2CredentialsFile with metadata TokenURL override": {
			metadata: ClientCredentialsMetadata{
				TokenURL: "https://metadata.com/token",
			},
			credentialsFileJSON: `{
				"client_id": "file-id",
				"client_secret": "file-secret",
				"issuer_url": "https://file.com/token"
			}`,
			expClientID:     "file-id",
			expClientSecret: "file-secret",
			expTokenURL:     "https://metadata.com/token",
		},
		"oauth2CredentialsFile provides credentials when metadata is empty": {
			metadata: ClientCredentialsMetadata{},
			credentialsFileJSON: `{
				"client_id": "file-only-id",
				"client_secret": "file-only-secret",
				"issuer_url": "https://oauth.example.com/o/oauth2/token"
			}`,
			expClientID:     "file-only-id",
			expClientSecret: "file-only-secret",
			expTokenURL:     "https://oauth.example.com/o/oauth2/token",
		},
		"oauth2ClientSecretPath provides plain text secret and allows client_id from metadata": {
			metadata: ClientCredentialsMetadata{
				ClientID: "metadata-id",
			},
			plainTextSecret: "plain-text-secret-12345",
			expClientID:     "metadata-id",
			expClientSecret: "plain-text-secret-12345",
		},
		"oauth2ClientSecretPath with metadata ClientSecret override": {
			metadata: ClientCredentialsMetadata{
				ClientID:     "metadata-id",
				ClientSecret: "metadata-secret",
			},
			plainTextSecret: "plain-text-secret-12345",
			expClientID:     "metadata-id",
			expClientSecret: "metadata-secret",
		},
		"error both fields set": {
			metadata: ClientCredentialsMetadata{},
			credentialsFileJSON: `{
				"client_id": "test-id",
				"client_secret": "test-secret",
				"issuer_url": "https://oauth.example.com/token"
			}`,
			plainTextSecret: "plain-text-secret",
			expErr:          true,
			expErrContains:  "mutually exclusive",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create JSON file for oauth2CredentialsFile if provided
			if test.credentialsFileJSON != "" {
				tmpFile, err := os.CreateTemp(t.TempDir(), "credentials-*.json")
				require.NoError(t, err)
				defer os.Remove(tmpFile.Name())

				_, err = tmpFile.WriteString(test.credentialsFileJSON)
				require.NoError(t, err)
				require.NoError(t, tmpFile.Close())

				test.metadata.CredentialsFilePath = tmpFile.Name()
			}

			// Create plain text file for oauth2ClientSecretPath if provided
			if test.plainTextSecret != "" {
				tmpFile, err := os.CreateTemp(t.TempDir(), "secret-*.txt")
				require.NoError(t, err)
				defer os.Remove(tmpFile.Name())

				_, err = tmpFile.WriteString(test.plainTextSecret)
				require.NoError(t, err)
				require.NoError(t, tmpFile.Close())

				test.metadata.ClientSecretPath = tmpFile.Name()
			}

			err := test.metadata.ResolveCredentials()

			if test.expErr {
				require.Error(t, err)
				if test.expErrContains != "" {
					assert.Contains(t, err.Error(), test.expErrContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.expClientID, test.metadata.ClientID)
				assert.Equal(t, test.expClientSecret, test.metadata.ClientSecret)
				if test.expTokenURL != "" {
					assert.Equal(t, test.expTokenURL, test.metadata.TokenURL)
				}
			}
		})
	}
}

func TestClientCredentialsMetadata_ToOptions(t *testing.T) {
	logger := logger.NewLogger("test")
	metadata := ClientCredentialsMetadata{
		TokenURL:     "https://token.example.com",
		TokenCAPEM:   "cert-pem-content",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Scopes:       []string{"scope1", "scope2"},
		Audiences:    []string{"audience1"},
	}

	opts := metadata.ToOptions(logger)

	assert.Equal(t, logger, opts.Logger)
	assert.Equal(t, "https://token.example.com", opts.TokenURL)
	assert.Equal(t, []byte("cert-pem-content"), opts.CAPEM)
	assert.Equal(t, "test-client-id", opts.ClientID)
	assert.Equal(t, "test-client-secret", opts.ClientSecret)
	assert.Equal(t, []string{"scope1", "scope2"}, opts.Scopes)
	assert.Equal(t, []string{"audience1"}, opts.Audiences)
}
