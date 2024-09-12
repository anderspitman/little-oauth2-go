package littleoauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

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

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type AuthCodeFlowState struct {
	AuthUri      string
	State        string
	PKCEVerifier string
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

// TODO: See if we can pack options into AuthRequestState
func ParseTokenRequest(tokenReqParams url.Values, authReqState string, options ...Options) (token string, err error) {

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

func StartAuthCodeFlow(serverUri string, authReq *AuthRequest) (flowState *AuthCodeFlowState, err error) {

	ar := *authReq

	flowState = &AuthCodeFlowState{}

	if ar.ResponseType == "" {
		ar.ResponseType = "code"
	}

	if ar.State == "" {
		ar.State, err = genRandomText(32)
		if err != nil {
			return nil, err
		}
	}

	if ar.CodeChallenge == "" {
		flowState.PKCEVerifier, err = PKCEGenerateVerifier()
		if err != nil {
			return nil, err
		}

		ar.CodeChallenge = PKCEChallengeFromVerifier(flowState.PKCEVerifier)
	}

	if ar.RedirectUri == "" {
		// TODO: start server
		return nil, errors.New("RedirectUri required")
	}

	flowState.AuthUri = fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s&state=%s&code_challenge_method=S256&code_challenge=%s",
		serverUri, ar.ClientId, ar.RedirectUri, ar.ResponseType, ar.Scope, ar.State, ar.CodeChallenge)
	flowState.State = ar.State

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
