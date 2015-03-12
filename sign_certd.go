package main

import (
	"./ssh_ca"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/ssh"
	"log"
	"net/http"
	"os"
	"time"
)

type CertRequest struct {
	request     *ssh.Certificate
	submit_time time.Time
	environment string
}

func new_cert_request() CertRequest {
	var cr CertRequest
	cr.submit_time = time.Now()
	return cr
}

type CertRequestHandler struct {
	Config map[string]ssh_ca.SignerConfig
	state  map[string]CertRequest
}

type CertRequestForm struct {
	cert string
}

func (h *CertRequestHandler) form_boilerplate(req *http.Request) (*ssh_ca.SignerConfig, string, error) {
	err := req.ParseForm()
	if err != nil {
		err := errors.New(fmt.Sprintf("%v", err))
		return nil, "", err
	}
	if req.Form["environment"] == nil {
		err := errors.New("Must specify environment")
		return nil, "", err
	}
	environment := req.Form["environment"][0]
	config, ok := h.Config[environment]
	if !ok {
		err := errors.New("Environment is not configured (is it valid?)")
		return nil, "", err
	}
	return &config, environment, nil
}

func (h *CertRequestHandler) create_signing_request(rw http.ResponseWriter, req *http.Request) {
	log.Println("create_signing_request")

	config, environment, err := h.form_boilerplate(req)
	if err != nil {
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	if req.PostForm["cert"] == nil || len(req.PostForm["cert"]) == 0 {
		http.Error(rw, "Please specify exactly one cert request", http.StatusBadRequest)
		return
	}

	raw_cert_request, err := base64.StdEncoding.DecodeString(req.PostForm["cert"][0])
	if err != nil {
		http.Error(rw, "Unable to base64 decode cert request", http.StatusBadRequest)
		return
	}
	pub_key, err := ssh.ParsePublicKey(raw_cert_request)
	if err != nil {
		http.Error(rw, "Unable to parse cert request", http.StatusBadRequest)
		return
	}

	cert := pub_key.(*ssh.Certificate)
	log.Println("Cert serial", cert.Serial)
	log.Println("Cert principals", cert.ValidPrincipals)
	log.Println("Signed by key", ssh_ca.MakeFingerprint(cert.SignatureKey.Marshal()))
	log.Println("Valid between", cert.ValidAfter, cert.ValidBefore)

	var cert_checker ssh.CertChecker
	cert_checker.IsAuthority = func(auth ssh.PublicKey) bool {
		for _, v := range config.AuthorizedUsers {
			if v == ssh_ca.MakeFingerprint(auth.Marshal()) {
				return true
			}
		}
		return false
	}
	err = cert_checker.CheckCert(cert.ValidPrincipals[0], cert)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Cert not valid: %v", err), http.StatusBadRequest)
		return
	}

	request_id := make([]byte, 15)
	rand.Reader.Read(request_id)
	request_id_str := base64.StdEncoding.EncodeToString(request_id)

	cert_request := new_cert_request()
	cert_request.request = cert
	cert_request.environment = environment
	h.state[request_id_str] = cert_request

	rw.WriteHeader(http.StatusCreated)
	rw.Write([]byte(request_id_str))
	return
}
func (h *CertRequestHandler) list_pending_requests(rw http.ResponseWriter, req *http.Request) {
	log.Println("list_pending_requests")
	_, environment, err := h.form_boilerplate(req)
	if err != nil {
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	results := make(map[string]string)
	for k, v := range h.state {
		if v.environment == environment {
			results[k] = base64.StdEncoding.EncodeToString(v.request.Marshal())
		}
	}
	output, err := json.Marshal(results)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Trouble marshaling json response %v", err), http.StatusInternalServerError)
		return
	}
	rw.Write(output)
}
func (h *CertRequestHandler) get_request_status(rw http.ResponseWriter, req *http.Request) {
	log.Println("get_request_status", req)
}
func (h *CertRequestHandler) sign_request(rw http.ResponseWriter, req *http.Request) {
	log.Println("sign_request", req)
}

func main() {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/"
	}
	config_path := home + "/.ssh_ca/sign_certd_config.json"
	flag.StringVar(&config_path, "config_path", config_path, "Path to config json.")
	flag.Parse()

	config, err := ssh_ca.LoadSignerConfig(config_path)
	if err != nil {
		log.Println("Load Config failed:", err)
		os.Exit(1)
	}

	var request_handler CertRequestHandler
	request_handler.Config = config
	request_handler.state = make(map[string]CertRequest)

	r := mux.NewRouter()
	requests := r.Path("/cert/requests").Subrouter()
	requests.Methods("POST").HandlerFunc(request_handler.create_signing_request)
	requests.Methods("GET").HandlerFunc(request_handler.list_pending_requests)
	request := r.Path("/cert/requests/{uuid}").Subrouter()
	request.Methods("GET").HandlerFunc(request_handler.get_request_status)
	request.Methods("POST").HandlerFunc(request_handler.sign_request)
	http.ListenAndServe(":8080", r)
}
