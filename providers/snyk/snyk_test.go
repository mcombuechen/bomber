package snyk

import (
	"os"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"

  "github.com/devops-kung-fu/bomber/models"
)

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
		Token:    "token",
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
		httpmock.NewBytesResponder(200, snykTestResponse()))

	credentials := models.Credentials{
		Token:    "token",
	}

	provider := Provider{}
  _, err := provider.Scan([]string{"pkg:gem/tzinfo@1.2.5"}, &credentials)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:gem/tzinfo@1.2.5", packages[0].Purl)
	assert.Len(t, packages[0].Vulnerabilities, 1)
	httpmock.GetTotalCallCount()
}

func snykTestResponse() []byte {
	response := `{
  "jsonapi": {
    "version": "1.0"
  },
  "data": [
    {
      "id": "SNYK-RUBY-TZINFO-2958048",
      "type": "issue",
      "attributes": {
        "key": "SNYK-RUBY-TZINFO-2958048",
        "title": "Directory Traversal",
        "type": "package_vulnerability",
        "created_at": "2022-07-22T07:23:05.273956Z",
        "updated_at": "2022-07-24T07:54:55.039170Z",
        "description": "",
        "problems": [
          {
            "id": "CWE-22",
            "source": "CWE"
          },
          {
            "id": "GHSA-5cm2-9h8c-rvfx",
            "source": "GHSA"
          },
          {
            "id": "CVE-2022-31163",
            "source": "CVE"
          }
        ],
        "coordinates": [
          {
            "remedies": [
              {
                "type": "indeterminate",
                "description": "Upgrade the package version to 0.3.61,1.2.10 to fix this vulnerability",
                "details": {
                  "upgrade_package": "0.3.61,1.2.10"
                }
              }
            ],
            "representation": [
              "<0.3.61",
              ">=1.0.0, <1.2.10"
            ]
          }
        ],
        "severities": [
          {
            "source": "Snyk",
            "level": "high",
            "score": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          {
            "source": "SUSE",
            "level": "high",
            "score": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
          },
          {
            "source": "NVD",
            "level": "high",
            "score": 8.1,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        ],
        "effective_severity_level": "high",
        "slots": {
          "disclosure_time": "2022-07-21T21:39:29Z",
          "exploit": "Not Defined",
          "publication_time": "2022-07-22T07:23:05Z",
          "references": [
            {
              "title": "GitHub 0.3.61 Release",
              "url": "https://github.com/tzinfo/tzinfo/releases/tag/v0.3.61"
            },
            {
              "title": "GitHub 1.2.10 Release",
              "url": "https://github.com/tzinfo/tzinfo/releases/tag/v1.2.10"
            },
            {
              "title": "GitHub Commit",
              "url": "https://github.com/tzinfo/tzinfo/commit/ca29f349856d62cb2b2edb3257d9ddd2f97b3c27"
            }
          ]
        }
      }
    }
  ],
  "links": {
    "self": ""
  },
  "meta": {
    "package": {
      "name": "tzinfo",
      "type": "gem",
      "url": "pkg:gem/tzinfo@1.2.5",
      "version": "1.2.5"
    }
  }
}`
	return []byte(response)
}
