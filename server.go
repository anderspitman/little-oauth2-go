package littleoauth2

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

type Server struct {
	rootUri       string
	store         KeyValueStore
	mux           *http.ServeMux
	deviceFlowMap map[string]chan *TokenResponse
	mu            *sync.Mutex
}

func NewServer(rootUri string, store KeyValueStore) *Server {

	mux := http.NewServeMux()

	s := &Server{
		rootUri:       rootUri,
		store:         store,
		mux:           mux,
		deviceFlowMap: make(map[string]chan *TokenResponse),
		mu:            &sync.Mutex{},
	}

	mux.HandleFunc("/device", s.HandleDeviceFlow)
	//mux.HandleFunc("/user-verify", s.HandleUserVerify)
	mux.HandleFunc("/token", s.HandleToken)

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) CompleteDeviceFlow(userCode string, tokenRes *TokenResponse) (err error) {

	var deviceResBytes []byte
	deviceResBytes, err = s.store.Get(userCode)
	if err != nil {
		return
	}

	s.store.Delete(userCode)

	var deviceRes *DeviceAuthResponse

	err = json.Unmarshal(deviceResBytes, &deviceRes)
	if err != nil {
		return
	}

	fmt.Printf("%+v\n", deviceRes)

	s.mu.Lock()
	ch, exists := s.deviceFlowMap[deviceRes.DeviceCode]
	s.mu.Unlock()

	if !exists {
		err = fmt.Errorf("No pending request for code %s", userCode)
		return
	}

	ch <- tokenRes

	return
}

func (s *Server) HandleDeviceFlow(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	deviceCode, err := genRandomText(32)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	userCode, err := genRandomCode(6)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	deviceRes := &DeviceAuthResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationUri:         fmt.Sprintf("%s/user-verify", s.rootUri),
		VerificationUriComplete: fmt.Sprintf("%s/user-verify?code=%s", s.rootUri, userCode),
		ExpiresIn:               3600,
		Interval:                5,
	}

	deviceResBytes, err := json.Marshal(deviceRes)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	// TODO: would be nice if we didn't need to store everything twice, but
	// might be necessary with a pure KV store.
	err = s.store.Set(userCode, deviceResBytes)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	err = s.store.Set(deviceCode, deviceResBytes)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	s.mu.Lock()
	s.deviceFlowMap[deviceCode] = make(chan *TokenResponse)
	s.mu.Unlock()

	w.Write(deviceResBytes)
}

func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

	deviceCode, err := ParseDeviceTokenRequest(r.Form)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	deviceResBytes, err := s.store.Get(deviceCode)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	s.store.Delete(deviceCode)

	var deviceRes *DeviceAuthResponse

	err = json.Unmarshal(deviceResBytes, &deviceRes)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	s.mu.Lock()
	ch := s.deviceFlowMap[deviceCode]
	s.mu.Unlock()

	// TODO: probably shouldn't be forcing long polling here

	tokenRes := <-ch

	resBytes, err := json.Marshal(tokenRes)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")

	w.Write(resBytes)
}
