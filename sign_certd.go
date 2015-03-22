package main

import (
	"./ssh_ca"
	"bytes"
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
	// This struct tracks state for certificate requests. Imagine this one day
	// being stored in a persistent data store.
	request     *ssh.Certificate
	submitTime  time.Time
	environment string
	signatures  map[string]bool
	certSigned  bool
	reason      string
}

func newCertRequest() CertRequest {
	var cr CertRequest
	cr.submitTime = time.Now()
	cr.certSigned = false
	cr.signatures = make(map[string]bool)
	return cr
}

type CertRequestHandler struct {
	Config     map[string]ssh_ca.SignerdConfig
	state      map[string]CertRequest
	sshAgent   agent.Agent
	NextSerial chan uint64
}

type signingRequest struct {
	config      *ssh_ca.SignerdConfig
	environment string
	cert        *ssh.Certificate
}

func (h *CertRequestHandler) formBoilerplate(req *http.Request) (*ssh_ca.SignerdConfig, string, error) {
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

func (h *CertRequestHandler) createSigningRequest(rw http.ResponseWriter, req *http.Request) {
	var requestData signingRequest
	config, environment, err := h.formBoilerplate(req)
	requestData.config = config
	requestData.environment = environment
	if err != nil {
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}
	err = h.extractCertFromRequest(req, &requestData, config.AuthorizedUsers)
	if err != nil {
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	if req.Form["reason"][0] == "" {
		http.Error(rw, "You forgot to send in a reason", http.StatusBadRequest)
		return
	}

	requester_fp := ssh_ca.MakeFingerprint(requestData.cert.SignatureKey.Marshal())

	requestId := make([]byte, 15)
	rand.Reader.Read(requestId)
	requestIdStr := base32.StdEncoding.EncodeToString(requestId)
	requestData.cert.Serial = <-h.NextSerial

    // We override keyid here so that its a server controlled value. Instead of
    // letting a requester attempt to spoof it.
    requestData.cert.KeyId = config.AuthorizedUsers[requester_fp]

	certRequest := newCertRequest()
	certRequest.request = requestData.cert
	certRequest.environment = requestData.environment
	certRequest.reason = req.Form["reason"][0]
	h.state[requestIdStr] = certRequest

	rw.WriteHeader(http.StatusCreated)
	rw.Write([]byte(requestIdStr))
	log.Printf("Cert request serial %d id %s from %s (%s) principals %v valid from %d to %d for '%s'\n",
		requestData.cert.Serial, requestIdStr, requester_fp, config.AuthorizedUsers[requester_fp],
		requestData.cert.ValidPrincipals, requestData.cert.ValidAfter, requestData.cert.ValidBefore, certRequest.reason)
	return
}

func (h *CertRequestHandler) extractCertFromRequest(req *http.Request, requestData *signingRequest, authorized_signers map[string]string) error {

	if req.PostForm["cert"] == nil || len(req.PostForm["cert"]) == 0 {
		err := errors.New("Please specify exactly one cert request")
		return err
	}

	raw_certRequest, err := base64.StdEncoding.DecodeString(req.PostForm["cert"][0])
	if err != nil {
		err := errors.New("Unable to base64 decode cert request")
		return err
	}
	pub_key, err := ssh.ParsePublicKey(raw_certRequest)
	if err != nil {
		err := errors.New("Unable to parse cert request")
		return err
	}

	cert := pub_key.(*ssh.Certificate)
	requestData.cert = cert

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

func (h *CertRequestHandler) listPendingRequests(rw http.ResponseWriter, req *http.Request) {
	_, environment, err := h.formBoilerplate(req)
	if err != nil {
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	var certRequestId string
	certRequestIds, ok := req.Form["certRequestId"]
	if ok {
		certRequestId = certRequestIds[0]
	}

	found_something := false
	results := make(map[string]string)
	for k, v := range h.state {
		if v.environment == environment {
			encoded_cert := base64.StdEncoding.EncodeToString(v.request.Marshal())
			// Two ways to use this URL. If caller specified a certRequestId
			// then we return only that one. Otherwise everything.
			if certRequestId == "" {
				results[k] = encoded_cert
				found_something = true
			} else {
				if certRequestId == k {
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

func (h *CertRequestHandler) getRequestStatus(rw http.ResponseWriter, req *http.Request) {
	uri_vars := mux.Vars(req)
	requestId := uri_vars["requestId"]

	type Response struct {
		certSigned bool
		cert       string
	}
	if h.state[requestId].certSigned == true {
		rw.Write([]byte(h.state[requestId].request.Type()))
		rw.Write([]byte(" "))
		rw.Write([]byte(base64.StdEncoding.EncodeToString(h.state[requestId].request.Marshal())))
		rw.Write([]byte("\n"))
	} else {
		http.Error(rw, "Cert not signed yet.", http.StatusPreconditionFailed)
	}
}

func (h *CertRequestHandler) signRequest(rw http.ResponseWriter, req *http.Request) {

	uri_vars := mux.Vars(req)
	requestId := uri_vars["requestId"]

	_, ok := h.state[requestId]
	if !ok {
		http.Error(rw, "Unknown request id", http.StatusNotFound)
		return
	}

	var requestData signingRequest
	config, environment, err := h.formBoilerplate(req)
	requestData.config = config
	requestData.environment = environment
	if err != nil {
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	err = h.extractCertFromRequest(req, &requestData, config.AuthorizedSigners)
	if err != nil {
		log.Println("Invalid certificate signing request received, ignoring")
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	signerFp := ssh_ca.MakeFingerprint(requestData.cert.SignatureKey.Marshal())

	// Verifying that the cert being posted to us here matches the one in the
	// request. That is, that an attacker isn't use an old signature to sign a
	// new/different request id
	requestedCert := h.state[requestId].request
	requestData.cert.SignatureKey = requestedCert.SignatureKey
	requestData.cert.Signature = nil
	requestedCert.Signature = nil
	// Resetting the Nonce felt wrong. But it turns out that when the signer
	// signs the request the act of signing generates a new Nonce. So it will
	// never match.
	requestedCert.Nonce = []byte("")
	requestData.cert.Nonce = []byte("")
	if !bytes.Equal(requestedCert.Marshal(), requestData.cert.Marshal()) {
		log.Println("Signature was valid, but cert didn't match.")
		log.Printf("Orig req: %#v\n", requestedCert)
		log.Printf("Sign req: %#v\n", requestData.cert)
		http.Error(rw, "Signature was valid, but cert didn't match.", http.StatusBadRequest)
		return
	}

	h.state[requestId].signatures[signerFp] = true
	log.Printf("Signature for serial %d id %s received from %s (%s) and determined valid\n", requestData.cert.Serial, requestId, signerFp, config.AuthorizedSigners[signerFp])

	if len(h.state[requestId].signatures) >= config.NumberSignersRequired {
		log.Printf("Received %d signatures for %s, signing now.\n", len(h.state[requestId].signatures), requestId)
		signers, err := h.sshAgent.Signers()
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
			log.Printf("Couldn't find signing key for request %s, unable to sign request\n", requestId)
			http.Error(rw, "Couldn't find signing key, unable to sign. Sorry.", http.StatusNotFound)
			return
		}
		stateInfo := h.state[requestId]
		stateInfo.request.SignCert(rand.Reader, *signer)
		stateInfo.certSigned = true
		// this is weird. see: https://code.google.com/p/go/issues/detail?id=3117
		h.state[requestId] = stateInfo
	}

}

func main() {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/"
	}
	configPath := home + "/.ssh_ca/sign_certd_config.json"
	flag.StringVar(&configPath, "configPath", configPath, "Path to config json.")
	flag.Parse()

	config, err := ssh_ca.LoadSignerdConfig(configPath)
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
	sshAgent := agent.NewClient(conn)

	var requestHandler CertRequestHandler
	requestHandler.Config = config
	requestHandler.state = make(map[string]CertRequest)
	requestHandler.NextSerial = make(chan uint64)
	go func() {
		var serial uint64
		for serial = 1; ; serial++ {
			requestHandler.NextSerial <- serial
		}
	}()
	requestHandler.sshAgent = sshAgent

	r := mux.NewRouter()
	requests := r.Path("/cert/requests").Subrouter()
	requests.Methods("POST").HandlerFunc(requestHandler.createSigningRequest)
	requests.Methods("GET").HandlerFunc(requestHandler.listPendingRequests)
	request := r.Path("/cert/requests/{requestId}").Subrouter()
	request.Methods("GET").HandlerFunc(requestHandler.getRequestStatus)
	request.Methods("POST").HandlerFunc(requestHandler.signRequest)
	http.ListenAndServe(":8080", r)
}
