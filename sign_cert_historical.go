package main

import (
    "crypto/rand"
    "encoding/base64"
    "flag"
    "fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	//"io"
	"log"
	"net"
	"os"
    //"time"
    "./ssh_ca"
)

func main() {

    var cert_request string
    var request_sig string

    flag.StringVar(&cert_request, "cert-request", "", "b64 encoded cert")
    flag.StringVar(&request_sig, "request-sig", "", "b64 signature of cert")
    flag.Parse()

    raw_cert_request, err := base64.StdEncoding.DecodeString(cert_request)
    if err != nil {
        fmt.Println("cert request unhappy: %v", err)
        os.Exit(1)
    }
    raw_request_sig, err := base64.StdEncoding.DecodeString(request_sig)
    if err != nil {
        fmt.Println("cert sig unhappy: %v", err)
        os.Exit(1)
    }

	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		log.Println("Dial failed:", err)
		os.Exit(1)
	}
	ssh_agent := agent.NewClient(conn)

	signers, err := ssh_agent.Signers()
    var signer ssh.Signer
	if err != nil {
		log.Println("No keys found.")
	} else {
		for i := range signers {
			log.Println("-- Key", ssh_ca.MakeFingerprint(signers[i].PublicKey().Marshal()))
            //sig, err := signers[i].Sign(nil, []byte("Some data"))
            signer = signers[i]
		}
	}

    pub_key, err := ssh.ParsePublicKey(raw_cert_request)
    if err != nil {
        log.Println("Unable to parse certificate, sorry.", err)
        os.Exit(1)
    }
    //var cert *ssh_ca.SshCertificate
    cert := pub_key.(*ssh.Certificate)
    log.Println("Cert serial", cert.Serial)
    log.Println("Cert principals", cert.ValidPrincipals)
    log.Println("Signature", cert.SignatureKey)
    log.Println("Signature %q", raw_request_sig)


    var cert_checker ssh.CertChecker
    // XXX This needs to compare against a list of public keys that are allowed to use our systems
    cert_checker.IsAuthority = func(auth ssh.PublicKey) bool { return true }
    err = cert_checker.CheckCert(cert.ValidPrincipals[0], cert)
    if err != nil {
        log.Println("error on checkcert:", err)
        os.Exit(1)
    }

    err = cert.SignCert(rand.Reader, signer)
    if err != nil {
        log.Println("Error signing:", err)
    } else {
        log.Println("Signed cert:", cert.Type(), base64.StdEncoding.EncodeToString(cert.Marshal()))
    }

}
