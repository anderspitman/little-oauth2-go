package littleoauth2

import (
	"errors"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

type AuthRequest struct {
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

		codeChallenge := oauth2.S256ChallengeFromVerifier(codeVerifier)

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
