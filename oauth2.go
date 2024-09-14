package littleoauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"
)

type KeyValueStore interface {
	Set(key string, value []byte) error
	Get(key string) ([]byte, error)
	Delete(key string) error
}

type AuthServerMetadata struct {
	Issuer                            string   `json:"issuer,omitempty"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                     string   `json:"token_endpoint,omitempty"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	JwksUri                           string   `json:"jwks_uri,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
}

type AuthRequest struct {
	ResponseType  string `json:"response_type"`
	ClientId      string `json:"client_id"`
	RedirectUri   string `json:"redirect_uri"`
	Scope         string `json:"scope"`
	State         string `json:"state"`
	CodeChallenge string `json:"code_challenge"`
}

type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectUri  string
	CodeVerifier string
	ClientId     string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationUri         string `json:"verification_uri"`
	VerificationUriComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type Options struct {
	AllowMissingPkce bool
}

func EncodeAuthRequestState(token, authReqParams string) string {
	return token + "_littleoauth2_sep_" + authReqParams
}

func DecodeAuthRequestState(str string) (string, string, error) {
	parts := strings.Split(str, "_littleoauth2_sep_")
	if len(parts) != 2 {
		return "", "", errors.New("Invalid AuthRequestState")
	}
	return parts[0], parts[1], nil
}

func ParseAuthRequest(params url.Values, options ...Options) (*AuthRequest, error) {

	var opt Options
	if len(options) > 0 {
		opt = options[0]
	}

	clientId := params.Get("client_id")
	if clientId == "" {
		return nil, errors.New("Missing client_id param")
	}

	redirectUri := params.Get("redirect_uri")
	if redirectUri == "" {
		return nil, errors.New("Missing redirect_uri param")
	}

	codeChallenge := params.Get("code_challenge")
	if codeChallenge == "" && !opt.AllowMissingPkce {
		return nil, errors.New("Missing code_challenge param")
	}

	codeChallengeMethod := params.Get("code_challenge_method")
	if codeChallengeMethod != "S256" && !opt.AllowMissingPkce {
		return nil, errors.New("Invalid code_challenge_method param")
	}

	req := &AuthRequest{
		ClientId:      clientId,
		RedirectUri:   redirectUri,
		Scope:         params.Get("scope"),
		State:         params.Get("state"),
		CodeChallenge: codeChallenge,
	}

	return req, nil
}

func ParseTokenRequest(tokenReqParams url.Values, options ...Options) (req *TokenRequest, err error) {

	var opt Options
	if len(options) > 0 {
		opt = options[0]
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
	grantType := tokenReqParams.Get("grant_type")
	if grantType == "" {
		err = errors.New("Missing grant_type param")
		return
	}

	code := tokenReqParams.Get("code")
	redirectUri := tokenReqParams.Get("redirect_uri")
	deviceCode := tokenReqParams.Get("device_code")
	codeVerifier := tokenReqParams.Get("code_verifier")

	clientId := tokenReqParams.Get("client_id")
	if clientId == "" {
		err = errors.New("Missing client_id param")
		return
	}

	switch grantType {
	case "authorization_code":

		if code == "" {
			err = errors.New("Missing code param")
			return
		}

		if redirectUri == "" {
			err = errors.New("Missing redirect_uri param")
			return
		}

		if !opt.AllowMissingPkce {
			if codeVerifier == "" {
				err = errors.New("Missing code_verifier param")
				return
			}
		}

	case "urn:ietf:params:oauth:grant-type:device_code":

		if deviceCode == "" {
			err = errors.New("Missing device_code param")
			return
		}

	default:
		err = errors.New("Invalid grant_type param")
		return
	}

	req = &TokenRequest{
		Code:         code,
		GrantType:    grantType,
		RedirectUri:  redirectUri,
		CodeVerifier: codeVerifier,
		ClientId:     clientId,
	}

	return
}

// TODO: See if we can pack options into AuthRequestState
func VerifyTokenRequest(tokenReqParams url.Values, authReqState string, options ...Options) (token string, err error) {

	var opt Options
	if len(options) > 0 {
		opt = options[0]
	}

	tok, authReqParams, err := DecodeAuthRequestState(authReqState)
	if err != nil {
		return
	}

	vals, err := url.ParseQuery(authReqParams)
	if err != nil {
		return
	}

	authReq, err := ParseAuthRequest(vals, opt)
	if err != nil {
		return
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
	grantType := tokenReqParams.Get("grant_type")
	if grantType == "" {
		err = errors.New("Missing grant_type param")
		return
	}

	if grantType != "authorization_code" {
		err = errors.New("Invalid grant_type param")
		return
	}

	redirectUri := tokenReqParams.Get("redirect_uri")

	if redirectUri == "" {
		err = errors.New("Missing redirect_uri param")
		return
	} else if redirectUri != authReq.RedirectUri {
		err = errors.New("redirect_uri param doesn't match auth request")
		return
	}

	codeVerifier := tokenReqParams.Get("code_verifier")

	if authReq.CodeChallenge == "" && codeVerifier != "" {
		err = errors.New("code_verifier provided but no code_challenge")
		return
	}

	if authReq.CodeChallenge != "" && codeVerifier == "" {
		err = errors.New("Missing code_verifier param")
		return
	}

	if !opt.AllowMissingPkce {
		if codeVerifier == "" {
			err = errors.New("Missing code_verifier param")
			return
		}

		codeChallenge := PKCEChallengeFromVerifier(codeVerifier)

		if codeChallenge != authReq.CodeChallenge {
			err = errors.New("Mismatched code_challenge")
			return
		}
	}

	token = tok

	return
}

func ParseRefreshRequest(params url.Values, options ...Options) (refreshToken string, err error) {

	//var opt Options
	//if len(options) > 0 {
	//	opt = options[0]
	//}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
	grantType := params.Get("grant_type")
	if grantType == "" {
		err = errors.New("Missing grant_type param")
		return
	}

	if grantType != "refresh_token" {
		err = errors.New("Invalid grant_type param")
		return
	}

	refreshToken = params.Get("refresh_token")
	if refreshToken == "" {
		err = errors.New("Missing refresh_token param")
		return
	}

	return
}

func ParseDeviceTokenRequest(tokenReqParams url.Values) (deviceCode string, err error) {

	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
	grantType := tokenReqParams.Get("grant_type")
	if grantType == "" {
		err = errors.New("Missing grant_type param")
		return
	}

	if grantType != "urn:ietf:params:oauth:grant-type:device_code" {
		err = errors.New("Invalid grant_type param")
		return
	}

	clientId := tokenReqParams.Get("client_id")
	if clientId == "" {
		err = errors.New("Missing client_id param")
		return
	}

	deviceCode = tokenReqParams.Get("device_code")
	if deviceCode == "" {
		err = errors.New("Missing device_code param")
		return
	}

	return
}

func Expired(issuedAt time.Time, expiresIn int) bool {
	now := time.Now().UTC()
	expiresInDur := time.Duration(expiresIn) * time.Second
	expiresTime := issuedAt.Add(expiresInDur)
	return now.After(expiresTime)
}

const chars string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func genRandomText(length int) (string, error) {
	id := ""
	for i := 0; i < length; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		id += string(chars[randIndex.Int64()])
	}
	return id, nil
}

const codeChars string = "0123456789"

func genRandomCode(length int) (string, error) {
	id := ""
	for i := 0; i < length; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(codeChars))))
		if err != nil {
			return "", err
		}
		id += string(chars[randIndex.Int64()])
	}
	return id, nil
}

// PKCE code copied from go/x/oauth2
func PKCEGenerateVerifier() (string, error) {
	// "RECOMMENDED that the output of a suitable random number generator be
	// used to create a 32-octet sequence.  The octet sequence is then
	// base64url-encoded to produce a 43-octet URL-safe string to use as the
	// code verifier."
	// https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	str := base64.RawURLEncoding.EncodeToString(data)

	return str, nil
}

func PKCEChallengeFromVerifier(verifier string) string {
	sha := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sha[:])
}
