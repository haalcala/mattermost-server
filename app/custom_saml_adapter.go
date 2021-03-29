package app

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sync"
	"time"

	"github.com/haalcala/saml"
	"github.com/haalcala/saml/samlsp"
	"github.com/mattermost/mattermost-server/v5/einterfaces"
	"github.com/mattermost/mattermost-server/v5/model"

	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
)

var (
	lock  = &sync.Mutex{}
	csaml *CustomSamlAdapter
)

const (
	SAML_ACTION_SIGNUP       = "signup"
	SAML_ACTION_LOGIN        = "login"
	SAML_ACTION_EMAIL_TO_SSO = "email_to_sso"
	SAML_ACTION_SSO_TO_EMAIL = "sso_to_email"
)

type CustomSamlAdapter struct {
	app        AppIface
	Middleware *samlsp.Middleware
	randomId   int64
}

func init() {
	fmt.Println("------ app/CustomSamlAdapter.go:: init()")

	RegisterNewSamlInterface(func(app *App) einterfaces.SamlInterface {
		provider := NewCustomSamlAdapter(app)

		provider.ConfigureSP()

		einterfaces.RegisterOauthProvider(model.USER_AUTH_SERVICE_SAML, provider)

		return provider
	})
}

func (m *CustomSamlAdapter) GetUserFromJson(data io.Reader) (*model.User, error) {
	return model.UserFromJson(data), nil
}

func (m *CustomSamlAdapter) ConfigureSP() error {
	fmt.Println("------ app/CustomSamlAdapter.go:: func (m *CustomSamlAdapter) ConfigureSP() error")

	conf := m.app.Config().SamlSettings

	if data, err := m.app.Srv().configStore.GetFile(SamlPublicCertificateName); err != nil {
		return err
	} else {
		ioutil.WriteFile("./config/"+*conf.PublicCertificateFile, data, 0644)
	}

	if data, err := m.app.Srv().configStore.GetFile(SamlPrivateKeyName); err != nil {
		return err
	} else {
		ioutil.WriteFile("./config/"+*conf.PrivateKeyFile, data, 0644)
	}

	var metdataurl = *conf.IdpMetadataUrl                       //Metadata of the IDP
	var sessioncert = "./config/" + *conf.PublicCertificateFile //Key pair used for creating a signed session
	var sessionkey = "./config/" + *conf.PrivateKeyFile
	var serverurl = *m.app.Config().ServiceSettings.SiteURL + "/saml" // base url of this service
	var entityId = os.Getenv("SAML_ENTITY_ID")                        //Entity ID uniquely identifies your service for IDP (does not have to be server url)

	keyPair, err := tls.LoadX509KeyPair(sessioncert, sessionkey)
	if err != nil {
		return err
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return err
	}

	idpMetadataURL, err := url.Parse(metdataurl)
	if err != nil {
		return err
	}

	rootURL, err := url.Parse(serverurl)
	if err != nil {
		return err
	}

	if entityId == "" {
		return model.NewAppError("custom_saml_adapter.go", "SAML EntityId cannot be left empty", map[string]interface{}{}, "", 99)
	}

	samlSP, _ := samlsp.New(samlsp.Options{
		URL:            *rootURL,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
		IDPMetadataURL: idpMetadataURL, // you can also have Metadata XML instead of URL
		EntityID:       entityId,
		RelayStateFunc: func(w http.ResponseWriter, r *http.Request) string {
			teamId, err := m.app.GetTeamIdFromQuery(r.URL.Query())

			if err != nil {
				return ""
			}

			action := r.URL.Query().Get("action")
			redirectTo := r.URL.Query().Get("redirect_to")
			relayProps := map[string]string{
				"random": fmt.Sprintf("%v", time.Now().UnixNano()),
			}

			if len(action) != 0 {
				relayProps["team_id"] = teamId
				relayProps["action"] = action
				if action == model.OAUTH_ACTION_EMAIL_TO_SSO {
					relayProps["email"] = r.URL.Query().Get("email")
				}
			}

			if len(redirectTo) != 0 {
				relayProps["redirect_to"] = redirectTo
			} else if action == "mobile" {
				relayProps["redirect_to"] = "/login/sso/saml" + r.URL.RawQuery // this will produce an uknown url, don't fix it!
			}

			relayState := base64.StdEncoding.EncodeToString([]byte(model.MapToJson(relayProps)))

			fmt.Println("Returning relayState:", relayState)

			return relayState
		},
	})

	csaml.Middleware = samlSP

	return nil
}

func (m *CustomSamlAdapter) BuildRequest(relayState string) (*model.SamlAuthRequest, *model.AppError) {
	fmt.Println("------ app/CustomSamlAdapter.go:: func (m *CustomSamlAdapter) BuildRequest(relayState string) (*model.SamlAuthRequest, *model.AppError)")

	config := m.app.Config().SamlSettings

	saml_req, err := m.Middleware.ServiceProvider.MakeAuthenticationRequest(*config.IdpUrl)

	if err != nil {
		return nil, model.NewAppError("custom_saml_adapter.go", "", map[string]interface{}{}, "", 99)
	}

	redirect_url := saml_req.Redirect(relayState)

	fmt.Println("redirect_url:", redirect_url.String())

	saml_req_b64 := redirect_url.Query().Get("SAMLRequest")

	fmt.Println("saml_req_b64:", saml_req_b64)

	req := &model.SamlAuthRequest{
		Base64AuthRequest: saml_req_b64,
		RelayState:        relayState,
		URL:               redirect_url.String(),
		ID:                saml_req.ID,
	}

	fmt.Println("req:", req)

	return req, nil
}

func (m *CustomSamlAdapter) DoLogin(encodedXML string, relayState map[string]string) (*model.User, *model.AppError) {
	fmt.Println("------ app/CustomSamlAdapter.go:: func (m *CustomSamlAdapter) DoLogin(encodedXML string, relayState map[string]string) (*model.User, *model.AppError)")

	saml_config := m.app.Config().SamlSettings

	fmt.Println("encodedXML:", encodedXML)
	fmt.Println("relayState:", relayState)

	decodedResponseXML, err := base64.StdEncoding.DecodeString(encodedXML)

	fmt.Println("decodedResponseXML:", string(decodedResponseXML))

	if err != nil {
		return nil, model.NewAppError("app/custom_saml_adapter.go", "", map[string]interface{}{}, fmt.Sprintf("cannot parse base64: %s", err), 999)
	}

	resp := &saml.Response{}

	fmt.Println("1111 resp:", resp)

	if err := xml.Unmarshal([]byte(decodedResponseXML), &resp); err != nil {
		return nil, model.NewAppError("app/custom_saml_adapter.go", "", map[string]interface{}{}, fmt.Sprintf("cannot unmarshal response: %s", err), 999)
	}

	fmt.Println("2222 resp:", *resp)
	fmt.Println("2222 resp.Assertion:", *resp.Assertion)
	fmt.Println("2222 resp.Assertion.AttributeStatements:", resp.Assertion.AttributeStatements)

	_user := &model.User{
		AuthService: model.USER_AUTH_SERVICE_SAML,
	}

	if resp.Assertion != nil {
		for _, st := range resp.Assertion.AttributeStatements {
			fmt.Println("st:", st)

			for _, att := range st.Attributes {
				fmt.Println("att:", att.Name, att.FriendlyName, att.Values[0])

				if att.Name == *saml_config.UsernameAttribute {
					_user.Username = att.Values[0].Value
				} else if att.Name == *saml_config.EmailAttribute {
					_user.Email = att.Values[0].Value
					_user.EmailVerified = true
				} else if att.Name == *saml_config.IdAttribute {
					_user.AuthData = &att.Values[0].Value
				} else if att.Name == *saml_config.FirstNameAttribute {
					_user.FirstName = att.Values[0].Value
				} else if att.Name == *saml_config.LastNameAttribute {
					_user.LastName = att.Values[0].Value
				}
			}
		}
	}

	teamId := relayState["team_id"]

	user, aerr := m.CompleteSaml(model.USER_AUTH_SERVICE_SAML, ioutil.NopCloser(bytes.NewReader([]byte(_user.ToJson()))), teamId, relayState)

	return user, aerr
}

func (m *CustomSamlAdapter) CompleteSaml(service string, body io.ReadCloser, teamId string, props map[string]string) (*model.User, *model.AppError) {
	fmt.Println("------ app/custom_saml_adapter.so:: CompleteSaml(service string, body io.ReadCloser, teamId string, props map[string]string) (*model.User, *model.AppError)")

	defer body.Close()

	action := props["action"]

	switch action {
	case SAML_ACTION_SIGNUP:
		return m.app.CreateOAuthUser(service, body, teamId)
	case SAML_ACTION_LOGIN:
		return m.app.LoginByOAuth(service, body, teamId)
	case SAML_ACTION_EMAIL_TO_SSO:
		return m.app.CompleteSwitchWithOAuth(service, body, props["email"])
	case SAML_ACTION_SSO_TO_EMAIL:
		return m.app.LoginByOAuth(service, body, teamId)
	default:
		return m.app.LoginByOAuth(service, body, teamId)
	}
}

func (m *CustomSamlAdapter) GetMetadata() (string, *model.AppError) {
	fmt.Println("------ app/CustomSamlAdapter.go:: func (m *CustomSamlAdapter) GetMetadata() (string, *model.AppError)")

	return "", nil
}

func (m *CustomSamlAdapter) GetUserFromAssertion(encodedXML string) (*model.User, *model.AppError) {
	return nil, nil
}

func NewCustomSamlAdapter(app AppIface) *CustomSamlAdapter {
	fmt.Println("------ app/CustomSamlAdapter.go:: func (a *App) NewCustomSamlAdapter() (*CustomSamlAdapter, error) {")

	lock.Lock()
	defer lock.Unlock()

	if csaml == nil {
		csaml = &CustomSamlAdapter{
			app:      app,
			randomId: time.Now().UnixNano(),
		}
	}

	fmt.Println("-------------------------------------------- 2222 csaml:", csaml)

	return csaml
}
