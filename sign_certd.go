package main

import (
	"./ssh_ca"
	"crypto/rand"
	"encoding/base64"
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
}

var state = make(map[string]CertRequest)

type CertRequestHandler struct {
	Config map[string]ssh_ca.SignerConfig
}

type CertRequestForm struct {
	cert string
}

func (h *CertRequestHandler) create_signing_request(rw http.ResponseWriter, req *http.Request) {
	log.Println("create_signing_request", req)
	err := req.ParseForm()
	if err != nil {
		log.Println("Error parsing request form:", err)
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	if req.PostForm["environment"] == nil {
		http.Error(rw, "Must specify environment", http.StatusBadRequest)
		return
	}
	environment := req.PostForm["environment"][0]
	//if h.Config["environment"] == nil {
	//http.Error(rw, "Environment is not configured (is it valid?)", http.StatusBadRequest)
	//return
	//}

	config := h.Config[environment]

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
	log.Println("Signing key", cert.SignatureKey)
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

	var cert_request CertRequest
	cert_request.request = cert
	state[request_id_str] = cert_request

	rw.WriteHeader(http.StatusCreated)
	rw.Write([]byte(request_id_str))
	return
}
func (h *CertRequestHandler) list_pending_requests(rw http.ResponseWriter, req *http.Request) {
	log.Println("list_pending_requests", req)
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

	r := mux.NewRouter()
	requests := r.Path("/cert/requests").Subrouter()
	requests.Methods("POST").HandlerFunc(request_handler.create_signing_request)
	requests.Methods("GET").HandlerFunc(request_handler.list_pending_requests)
	request := r.Path("/cert/requests/{uuid}").Subrouter()
	request.Methods("GET").HandlerFunc(request_handler.get_request_status)
	request.Methods("POST").HandlerFunc(request_handler.sign_request)
	http.ListenAndServe(":8080", r)
}
