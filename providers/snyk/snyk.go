package snyk

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kirinlabs/HttpRequest"
	"github.com/package-url/packageurl-go"
	"github.com/remeh/sizedwaitgroup"

	"github.com/devops-kung-fu/bomber/models"
)

const SNYK_URL = "https://api.snyk.io/rest"

const SNYK_API_VERSION = "?version=2022-09-15~experimental"

const CONCURRENCY = 10

type Provider struct{}

const (
	Critical CommonIssueModelAttributesEffectiveSeverityLevel = "critical"
	High     CommonIssueModelAttributesEffectiveSeverityLevel = "high"
	Info     CommonIssueModelAttributesEffectiveSeverityLevel = "info"
	Low      CommonIssueModelAttributesEffectiveSeverityLevel = "low"
	Medium   CommonIssueModelAttributesEffectiveSeverityLevel = "medium"
)

type CommonIssueModel struct {
	Attributes struct {
		Coordinates []Coordinate `json:"coordinates,omitempty"`
		CreatedAt   time.Time    `json:"created_at,omitempty"`

		// A description of the issue in Markdown format
		Description string `json:"description,omitempty"`

		// The type from enumeration of the issue’s severity level. This is usually set from the issue’s producer, but can be overridden by policies.
		EffectiveSeverityLevel CommonIssueModelAttributesEffectiveSeverityLevel `json:"effective_severity_level,omitempty"`

		// The Snyk vulnerability ID.
		Key      string    `json:"key,omitempty"`
		Problems []Problem `json:"problems,omitempty"`

		// The severity level of the vulnerability: ‘low’, ‘medium’, ‘high’ or ‘critical’.
		Severities []Severity `json:"severities,omitempty"`
		Slots      Slots      `json:"slots,omitempty"`

		// A human-readable title for this issue.
		Title string `json:"title,omitempty"`

		// The issue type
		Type string `json:"type,omitempty"`

		// When the vulnerability information was last modified.
		UpdatedAt *string `json:"updated_at,omitempty"`
	} `json:"attributes,omitempty"`

	// The Snyk ID of the vulnerability.
	Id string `json:"id,omitempty"`

	// The type of the REST resource. Always ‘issue’.
	Type string `json:"type,omitempty"`
}

// The type from enumeration of the issue’s severity level. This is usually set from the issue’s producer, but can be overridden by policies.
type CommonIssueModelAttributesEffectiveSeverityLevel string

type Coordinate struct {
	Remedies []Remedy `json:"remedies,omitempty"`

	// The affected versions of this vulnerability.
	Representation []string `json:"representation,omitempty"`
}

type IssuesMeta struct {
	Package PackageMeta `json:"package,omitempty"`
}

type IssuesResponse struct {
	Data    []CommonIssueModel `json:"data,omitempty"`
	Jsonapi JsonApi            `json:"jsonapi,omitempty"`
	Links   PaginatedLinks     `json:"links,omitempty"`
	Meta    IssuesMeta         `json:"meta,omitempty"`
}

type SelfResponse struct {
	Data struct {
		Attributes struct {
			AvatarUrl         string `json:"avatar_url,omitempty"`
			DefaultOrgContext string `json:"default_org_context,omitempty"`
			Name              string `json:"name,omitempty"`
			Username          string `json:"username,omitempty"`
		} `json:"attributes,omitempty"`
		Id   string `json:"id,omitempty"`
		Type string `json:"type,omitempty"`
	}
	Jsonapi JsonApi        `json:"jsonapi,omitempty"`
	Links   PaginatedLinks `json:"links,omitempty"`
}

type JsonApi struct {
	// Version of the JSON API specification this server supports.
	Version string `json:"version"`
}

type LinkProperty interface{}

type Links struct {
	First   LinkProperty `json:"first,omitempty"`
	Last    LinkProperty `json:"last,omitempty"`
	Next    LinkProperty `json:"next,omitempty"`
	Prev    LinkProperty `json:"prev,omitempty"`
	Related LinkProperty `json:"related,omitempty"`
	Self    LinkProperty `json:"self,omitempty"`
}

// Free-form object that may contain non-standard information.
type Meta struct {
	AdditionalProperties map[string]interface{} `json:"-"`
}

type PackageMeta struct {
	// The package’s name
	Name string `json:"name,omitempty"`

	// A name prefix, such as a maven group id or docker image owner
	Namespace string `json:"namespace,omitempty"`

	// The package type or protocol
	Type string `json:"type,omitempty"`

	// The purl of the package
	Url string `json:"url,omitempty"`

	// The version of the package
	Version string `json:"version,omitempty"`
}

type PaginatedLinks struct {
	First LinkProperty `json:"first,omitempty"`
	Last  LinkProperty `json:"last,omitempty"`
	Next  LinkProperty `json:"next,omitempty"`
	Prev  LinkProperty `json:"prev,omitempty"`
	Self  LinkProperty `json:"self,omitempty"`
}

type Problem struct {
	// When this problem was disclosed to the public.
	DisclosedAt time.Time `json:"disclosed_at,omitempty"`

	// When this problem was first discovered.
	DiscoveredAt time.Time `json:"discovered_at,omitempty"`
	Id           string    `json:"id"`
	Source       string    `json:"source"`

	// When this problem was last updated.
	UpdatedAt time.Time `json:"updated_at,omitempty"`

	// An optional URL for this problem.
	Url *string `json:"url,omitempty"`
}

type Remedy struct {
	// A markdown-formatted optional description of this remedy.
	Description string `json:"description,omitempty"`
	Details     struct {
		// A minimum version to upgrade to in order to remedy the issue.
		UpgradePackage string `json:"upgrade_package,omitempty"`
	} `json:"details,omitempty"`

	// The type of the remedy. Always ‘indeterminate’.
	Type string `json:"type,omitempty"`
}

type Severity struct {
	Level string `json:"level,omitempty"`

	// The CVSSv3 value of the vulnerability.
	Score float32 `json:"score,omitempty"`

	// The source of this severity. The value must be the id of a referenced problem or class, in which case that problem or class is the source of this issue. If source is omitted, this severity is sourced internally in the Snyk application.
	Source string `json:"source,omitempty"`

	// The CVSSv3 value of the vulnerability.
	Vector string `json:"vector,omitempty"`
}

type Slots struct {
	// The time at which this vulnerability was disclosed.
	DisclosureTime time.Time `json:"disclosure_time,omitempty"`

	// The exploit maturity. Value of ‘No Data’, ‘Not Defined’, ‘Unproven’, ‘Proof of Concept’, ‘Functional’ or ‘High’.
	Exploit string `json:"exploit,omitempty"`

	// The time at which this vulnerability was published.
	PublicationTime string `json:"publication_time,omitempty"`
	References      []struct {
		// Descriptor for an external reference to the issue
		Title string `json:"title,omitempty"`

		// URL for an external reference to the issue
		Url string `json:"url,omitempty"`
	} `json:"references,omitempty"`
}

// Info provides basic information about the Snyk Provider
func (Provider) Info() string {
	return "Snyk (https://security.snyk.io)"
}

// Scan scans a list of Purls for vulnerabilities against Snyk.
func (Provider) Scan(purls []string, credentials *models.Credentials) (packages []models.Package, err error) {
	err = validateCredentials(credentials)
	req := HttpRequest.NewRequest().SetHeaders(map[string]string{
		"Content-Type":  "application/vnd.api+json",
		"Authorization": fmt.Sprintf("token %s", credentials.Token),
		"User-Agent":    "Bomber",
	})

	wg := sizedwaitgroup.New(CONCURRENCY)

	self_resp, _ := req.Get(SNYK_URL + "/self" + SNYK_API_VERSION)
	self_body, _ := self_resp.Body()
	var org_id string

	if self_resp.StatusCode() == 200 {
		var self_response SelfResponse
		err = json.Unmarshal(self_body, &self_response)
		if err != nil {
			log.Println("Error, unable to retrieve org ID. Status:", self_resp.Response().Status)
			return
		}
		org_id = self_response.Data.Attributes.DefaultOrgContext
	} else {
		log.Println("Error, unable to retrieve org ID. Status:", self_resp.Response().Status)
		return
	}

	for _, pp := range purls {
		wg.Add()

		go func(purl string, org_id string) {
			defer wg.Done()

			_, e := packageurl.FromString(pp)
			if e != nil {
				err = e
				return
			}

			parts := []string{SNYK_URL, "/orgs/", org_id, "/packages/", url.QueryEscape(purl), "/issues", SNYK_API_VERSION}
			url := strings.Join(parts, "")

			resp, _ := req.Get(url)
			defer func() {
				_ = resp.Close()
			}()

			body, _ := resp.Body()
			if resp.StatusCode() == 200 {

				var response IssuesResponse
				err = json.Unmarshal(body, &response)
				if err != nil {
					return
				}
				if len(response.Data) > 0 {
					pkg := models.Package{
						Purl: purl,
					}
					for _, v := range response.Data {
						vuln := models.Vulnerability{
							ID:          v.Id,
							Title:       v.Attributes.Title,
							Description: v.Attributes.Description,
							Severity:    strings.ToUpper(string(v.Attributes.EffectiveSeverityLevel)),
							// TODO add
							// Cwe
							// CvssScore
							// CvssVector
							// Reference
							// ExternalReferences
						}
						if vuln.Severity == "MEDIUM" {
							vuln.Severity = "MODERATE"
						}
						pkg.Vulnerabilities = append(pkg.Vulnerabilities, vuln)
					}
					packages = append(packages, pkg)
				}
			} else {
				//err = fmt.Errorf("error retrieving vulnerability data (%v)", resp.Response().Status)

				log.Println("Error:", purl, resp.Response().Status)
				//break
			}
		}(pp, org_id)

	}
	wg.Wait()
	return
}

func validateCredentials(credentials *models.Credentials) (err error) {
	if credentials == nil {
		return errors.New("credentials cannot be nil")
	}
	if credentials.Token == "" {
		credentials.Token = os.Getenv("BOMBER_PROVIDER_TOKEN")
	}

	if credentials.Token == "" {
		err = errors.New("bomber requires a token to use the Snyk provider")
	}
	return
}
