package littleoauth2

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type DeviceFlow struct {
	AuthRequest    *AuthRequest
	DeviceResponse *DeviceAuthResponse
}

type AuthCodeFlowState struct {
	AuthUri      string
	RedirectUri  string `json:"redirect_uri"`
	State        string
	CodeVerifier string
}

func (f *DeviceFlow) Complete(uri string) (*TokenResponse, error) {

	r := f.DeviceResponse

	params := url.Values{}
	params.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	params.Set("device_code", r.DeviceCode)
	params.Set("client_id", f.AuthRequest.ClientId)

	res, err := http.PostForm(uri, params)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("Bad status code %d, %s", res.StatusCode, string(bodyBytes))
	}

	var tokenRes *TokenResponse

	err = json.Unmarshal(bodyBytes, &tokenRes)
	if err != nil {
		return nil, err
	}

	return tokenRes, nil
}

func MakeTokenRequest(tokenUri string, tokenReq *TokenRequest) (tokenRes *TokenResponse, err error) {

	resBytes, err := MakeTokenRequestRaw(tokenUri, tokenReq)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(resBytes, &tokenRes)
	if err != nil {
		return
	}

	return
}

func MakeTokenRequestRaw(tokenUri string, tokenReq *TokenRequest) (bodyBytes []byte, err error) {

	httpClient := &http.Client{}

	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("code", tokenReq.Code)
	params.Set("client_id", tokenReq.ClientId)
	params.Set("redirect_uri", tokenReq.RedirectUri)
	params.Set("code_verifier", tokenReq.CodeVerifier)
	body := strings.NewReader(params.Encode())

	var req *http.Request
	req, err = http.NewRequest(http.MethodPost, tokenUri, body)
	if err != nil {
		return
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	var res *http.Response
	res, err = httpClient.Do(req)
	if err != nil {
		return
	}

	bodyBytes, err = io.ReadAll(res.Body)
	if err != nil {
		return
	}

	if res.StatusCode != 200 {
		err = fmt.Errorf("MakeTokenRequestRaw: invalid status code: %s", string(bodyBytes))
		return
	}

	return
}

func StartAuthCodeFlow(serverUri string, authReq *AuthRequest) (flowState *AuthCodeFlowState, err error) {

	ar := *authReq

	flowState = &AuthCodeFlowState{
		RedirectUri: ar.RedirectUri,
	}

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
		flowState.CodeVerifier, err = PKCEGenerateVerifier()
		if err != nil {
			return nil, err
		}

		ar.CodeChallenge = PKCEChallengeFromVerifier(flowState.CodeVerifier)
	}

	if ar.RedirectUri == "" {
		// TODO: start server
		return nil, errors.New("RedirectUri required")
	}

	if ar.ClientId == "" {
		ar.ClientId = ar.RedirectUri
	}

	scope := encodeScopeParam(ar.Scopes)

	flowState.AuthUri = fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s&state=%s&code_challenge_method=S256&code_challenge=%s",
		serverUri, ar.ClientId, ar.RedirectUri, ar.ResponseType, scope, ar.State, ar.CodeChallenge)
	flowState.State = ar.State

	return
}

func CompleteAuthCodeFlow(serverUri, code, state string, flowState *AuthCodeFlowState) ([]byte, error) {

	if state != flowState.State {
		return nil, fmt.Errorf("State %s does not match expected", state, flowState.State)
	}

	tokenReq := &TokenRequest{
		Code:         code,
		RedirectUri:  flowState.RedirectUri,
		CodeVerifier: flowState.CodeVerifier,
	}

	return MakeTokenRequestRaw(serverUri, tokenReq)
}

func StartDeviceFlow(uri string, authReq *AuthRequest) (flow *DeviceFlow, err error) {

	params := url.Values{}

	params.Set("client_id", authReq.ClientId)
	scope := encodeScopeParam(authReq.Scopes)
	params.Set("scope", scope)

	var res *http.Response
	res, err = http.PostForm(uri, params)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var deviceRes *DeviceAuthResponse

	var bodyBytes []byte
	bodyBytes, err = io.ReadAll(res.Body)
	if err != nil {
		return
	}

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("Bad status code %d, %s", res.StatusCode, string(bodyBytes))
	}

	err = json.Unmarshal(bodyBytes, &deviceRes)
	if err != nil {
		return
	}

	flow = &DeviceFlow{
		AuthRequest:    authReq,
		DeviceResponse: deviceRes,
	}

	return
}

func encodeScopeParam(scopes []string) string {
	return url.QueryEscape(strings.Join(scopes, " "))
}
