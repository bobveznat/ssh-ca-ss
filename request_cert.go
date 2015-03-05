package main

import (
    "encoding/base64"
    "crypto/rand"
    //"flag"
    "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	//"io"
	"log"
	"net"
	"os"
    "time"
    "./ssh_ca"
)

func main() {

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
            //signing_key = signers[i]
		}
	}

    principals := make([]string, 1, 1)
    principals[0] = "ubuntu"
    var new_cert ssh_ca.SshCertificate
    new_cert.Nonce = make([]byte, 32)
    new_cert.Key = signer.PublicKey()
    new_cert.Serial = 0
    new_cert.CertType = ssh.UserCert
    new_cert.KeyId = "deadbeef"
    new_cert.ValidPrincipals = principals
    new_cert.ValidAfter = uint64(time.Now().Unix())
    new_cert.ValidBefore = uint64(new_cert.ValidAfter + 3600)

    err = new_cert.SignCert(rand.Reader, signer)
    if err != nil {
        log.Println("Error signing:", err)
    } else {
        log.Println("Signature fp:", ssh_ca.MakeFingerprint(new_cert.Signature.Blob))
        log.Println("Signature key:", new_cert.SignatureKey)
    }

    cert_request := new_cert.Marshal()
    log.Println("Cert request is:", base64.StdEncoding.EncodeToString(cert_request))

}
