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

func MakeTokenRequest(authServerUri string, tokenReq *TokenRequest) (tokenRes *TokenResponse, err error) {

	httpClient := &http.Client{}

	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("code", tokenReq.Code)
	params.Set("client_id", tokenReq.ClientId)
	params.Set("redirect_uri", tokenReq.RedirectUri)
	params.Set("code_verifier", tokenReq.CodeVerifier)
	body := strings.NewReader(params.Encode())

	tokenUri := fmt.Sprintf("%s/token", authServerUri)

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

	var bodyBytes []byte
	bodyBytes, err = io.ReadAll(res.Body)
	if err != nil {
		return
	}

	if res.StatusCode != 200 {
		err = errors.New(string(bodyBytes))
		return
	}

	err = json.Unmarshal(bodyBytes, &tokenRes)
	if err != nil {
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

	flowState.AuthUri = fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s&state=%s&code_challenge_method=S256&code_challenge=%s",
		serverUri, ar.ClientId, ar.RedirectUri, ar.ResponseType, ar.Scope, ar.State, ar.CodeChallenge)
	flowState.State = ar.State

	return
}

func StartDeviceFlow(uri string, authReq *AuthRequest) (flow *DeviceFlow, err error) {

	params := url.Values{}

	params.Set("client_id", authReq.ClientId)
	params.Set("scope", authReq.Scope)

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
