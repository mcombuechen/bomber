package snyk

import (
	_ "embed"
	"os"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/models"
)

//go:embed testdata/snyk_package_isssues_response.json
var snykTestResponse []byte

func TestInfo(t *testing.T) {
	provider := Provider{}
	info := provider.Info()
	assert.Equal(t, "Snyk (https://security.snyk.io)", info)
}

func Test_validateCredentials(t *testing.T) {
	// Back up any env tokens
	err := validateCredentials(nil)
	assert.Error(t, err)

	token := os.Getenv("BOMBER_PROVIDER_TOKEN")

	os.Unsetenv("BOMBER_PROVIDER_TOKEN")
	credentials := models.Credentials{
		Token: "token",
	}

	err = validateCredentials(&credentials)
	assert.NoError(t, err)

	credentials.Token = ""
	err = validateCredentials(&credentials)
	assert.Error(t, err)

	os.Setenv("BOMBER_PROVIDER_TOKEN", "token-env")

	err = validateCredentials(&credentials)
	assert.NoError(t, err)
	assert.Equal(t, "token-env", credentials.Token)

	//reset env
	os.Setenv("BOMBER_PROVIDER_TOKEN", token)
}

func TestProvider_Scan_FakeCredentials(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", SNYK_URL,
		httpmock.NewBytesResponder(200, snykTestResponse))
	httpmock.RegisterResponder("GET", SNYK_URL,
		httpmock.NewBytesResponder(200, snykTestResponse))

	credentials := models.Credentials{
		Token: "token",
	}

	provider := Provider{}
	packages, err := provider.Scan([]string{"pkg:gem/tzinfo@1.2.5"}, &credentials)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:gem/tzinfo@1.2.5", packages[0].Purl)
	assert.Len(t, packages[0].Vulnerabilities, 1)
	httpmock.GetTotalCallCount()
}
