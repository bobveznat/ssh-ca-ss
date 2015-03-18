package main

import (
	"./ssh_ca"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

const MAX_SIGNERS_ALLOWED = 5

type CertRequest struct {
	request     *ssh.Certificate
	submit_time time.Time
	environment string
	signatures  map[string]bool
	cert_signed bool
	reason      string
}

func new_cert_request() CertRequest {
	var cr CertRequest
	cr.submit_time = time.Now()
	cr.cert_signed = false
	cr.signatures = make(map[string]bool)
	return cr
}

type CertRequestHandler struct {
	Config    map[string]ssh_ca.SignerdConfig
	state     map[string]CertRequest
	ssh_agent agent.Agent
}

type CertRequestForm struct {
	cert string
}

func (h *CertRequestHandler) form_boilerplate(req *http.Request) (*ssh_ca.SignerdConfig, string, error) {
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
	var request_data SigningRequest
	config, environment, err := h.form_boilerplate(req)
	request_data.config = config
	request_data.environment = environment
	if err != nil {
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}
	err = h.extract_cert_from_request(req, &request_data, config.AuthorizedUsers)
	if err != nil {
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	if req.Form["reason"][0] == "" {
		http.Error(rw, "You forgot to send in a reason", http.StatusBadRequest)
		return
	}

	request_id := make([]byte, 15)
	rand.Reader.Read(request_id)
	request_id_str := base32.StdEncoding.EncodeToString(request_id)

	cert_request := new_cert_request()
	cert_request.request = request_data.cert
	cert_request.environment = request_data.environment
	cert_request.reason = req.Form["reason"][0]
	h.state[request_id_str] = cert_request

	rw.WriteHeader(http.StatusCreated)
	requester_fp := ssh_ca.MakeFingerprint(request_data.cert.SignatureKey.Marshal())
	rw.Write([]byte(request_id_str))
	log.Printf("Cert request %s from %s (%s) principals %v valid from %d to %d for '%s'\n",
		request_id_str, requester_fp, config.AuthorizedUsers[requester_fp],
		request_data.cert.ValidPrincipals, request_data.cert.ValidAfter, request_data.cert.ValidBefore, cert_request.reason)
	return
}

type SigningRequest struct {
	config      *ssh_ca.SignerdConfig
	environment string
	cert        *ssh.Certificate
}

func (h *CertRequestHandler) extract_cert_from_request(req *http.Request, request_data *SigningRequest, authorized_signers map[string]string) error {

	if req.PostForm["cert"] == nil || len(req.PostForm["cert"]) == 0 {
		err := errors.New("Please specify exactly one cert request")
		return err
	}

	raw_cert_request, err := base64.StdEncoding.DecodeString(req.PostForm["cert"][0])
	if err != nil {
		err := errors.New("Unable to base64 decode cert request")
		return err
	}
	pub_key, err := ssh.ParsePublicKey(raw_cert_request)
	if err != nil {
		err := errors.New("Unable to parse cert request")
		return err
	}

	cert := pub_key.(*ssh.Certificate)
	request_data.cert = cert

	var cert_checker ssh.CertChecker
	cert_checker.IsAuthority = func(auth ssh.PublicKey) bool {
		fingerprint := ssh_ca.MakeFingerprint(auth.Marshal())
		_, ok := authorized_signers[fingerprint]
		return ok
	}
	err = cert_checker.CheckCert(cert.ValidPrincipals[0], cert)
	if err != nil {
		err := errors.New(fmt.Sprintf("Cert not valid: %v", err))
		return err
	}
	return nil
}

func (h *CertRequestHandler) list_pending_requests(rw http.ResponseWriter, req *http.Request) {
	_, environment, err := h.form_boilerplate(req)
	if err != nil {
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	var cert_request_id string
	cert_request_ids, ok := req.Form["cert_request_id"]
	if ok {
		cert_request_id = cert_request_ids[0]
	}

	found_something := false
	results := make(map[string]string)
	for k, v := range h.state {
		if v.environment == environment {
			encoded_cert := base64.StdEncoding.EncodeToString(v.request.Marshal())
			// Two ways to use this URL. If caller specified a cert_request_id
			// then we return only that one. Otherwise everything.
			if cert_request_id == "" {
				results[k] = encoded_cert
				found_something = true
			} else {
				if cert_request_id == k {
					results[k] = encoded_cert
					found_something = true
					break
				}
			}
		}
	}
	if found_something {
		output, err := json.Marshal(results)
		if err != nil {
			http.Error(rw, fmt.Sprintf("Trouble marshaling json response %v", err), http.StatusInternalServerError)
			return
		}
		rw.Write(output)
	} else {
		http.Error(rw, fmt.Sprintf("No certs found."), http.StatusNotFound)
		return
	}
}

func (h *CertRequestHandler) get_request_status(rw http.ResponseWriter, req *http.Request) {
	uri_vars := mux.Vars(req)
	request_id := uri_vars["request_id"]

	type Response struct {
		cert_signed bool
		cert        string
	}
	if h.state[request_id].cert_signed == true {
		rw.Write([]byte(h.state[request_id].request.Type()))
		rw.Write([]byte(" "))
		rw.Write([]byte(base64.StdEncoding.EncodeToString(h.state[request_id].request.Marshal())))
		rw.Write([]byte("\n"))
	} else {
		http.Error(rw, "Cert not signed yet.", http.StatusPreconditionFailed)
	}
}

func (h *CertRequestHandler) sign_request(rw http.ResponseWriter, req *http.Request) {

	uri_vars := mux.Vars(req)
	request_id := uri_vars["request_id"]

	var request_data SigningRequest
	config, environment, err := h.form_boilerplate(req)
	request_data.config = config
	request_data.environment = environment
	if err != nil {
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}
	err = h.extract_cert_from_request(req, &request_data, config.AuthorizedSigners)
	if err != nil {
		log.Println("Invalid certificate signing request received, ignoring")
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	signer_fp := ssh_ca.MakeFingerprint(request_data.cert.SignatureKey.Marshal())
	h.state[request_id].signatures[signer_fp] = true
	log.Printf("Signature for %s received from %s (%s) and determined valid\n", request_id, signer_fp, config.AuthorizedSigners[signer_fp])

	if len(h.state[request_id].signatures) >= config.NumberSignersRequired {
		log.Printf("Received %d signatures for %s, signing now.\n", len(h.state[request_id].signatures), request_id)
		signers, err := h.ssh_agent.Signers()
		var signer *ssh.Signer
		if err != nil {
			log.Println("No keys found.")
		} else {
			for i := range signers {
				fp := ssh_ca.MakeFingerprint(signers[i].PublicKey().Marshal())
				if fp == config.SigningKeyFingerprint {
					signer = &signers[i]
					break
				}
			}
		}
		if signer == nil {
			log.Printf("Couldn't find signing key for request %s, unable to sign request\n", request_id)
			http.Error(rw, "Couldn't find signing key, unable to sign. Sorry.", http.StatusNotFound)
			return
		}
		state_info := h.state[request_id]
		state_info.request.SignCert(rand.Reader, *signer)
		state_info.cert_signed = true
		// this is weird. see: https://code.google.com/p/go/issues/detail?id=3117
		h.state[request_id] = state_info
	}

}

func main() {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/"
	}
	config_path := home + "/.ssh_ca/sign_certd_config.json"
	flag.StringVar(&config_path, "config_path", config_path, "Path to config json.")
	flag.Parse()

	config, err := ssh_ca.LoadSignerdConfig(config_path)
	if err != nil {
		log.Println("Load Config failed:", err)
		os.Exit(1)
	}
	log.Println("Server started with config", config)
	log.Println("Using SSH agent at", os.Getenv("SSH_AUTH_SOCK"))

	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		log.Println("Dial failed:", err)
		os.Exit(1)
	}
	ssh_agent := agent.NewClient(conn)

	var request_handler CertRequestHandler
	request_handler.Config = config
	request_handler.state = make(map[string]CertRequest)
	request_handler.ssh_agent = ssh_agent

	r := mux.NewRouter()
	requests := r.Path("/cert/requests").Subrouter()
	requests.Methods("POST").HandlerFunc(request_handler.create_signing_request)
	requests.Methods("GET").HandlerFunc(request_handler.list_pending_requests)
	request := r.Path("/cert/requests/{request_id}").Subrouter()
	request.Methods("GET").HandlerFunc(request_handler.get_request_status)
	request.Methods("POST").HandlerFunc(request_handler.sign_request)
	http.ListenAndServe(":8080", r)
}
