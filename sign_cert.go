package main

import (
	"./ssh_ca"
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type CertRequestResponse map[string]string

func main() {
	var environment, cert_request_id string

	home := os.Getenv("HOME")
	if home == "" {
		home = "/"
	}
	config_path := home + "/.ssh_ca/signer_config.json"

	flag.StringVar(&environment, "environment", "", "The environment you want (e.g. prod).")
	flag.StringVar(&config_path, "config_path", config_path, "Path to config json.")
	flag.StringVar(&cert_request_id, "cert-request-id", cert_request_id, "ID of cert request.")
	flag.Parse()

	all_config, err := ssh_ca.LoadSignerConfig(config_path)
	if err != nil {
		fmt.Println("Load Config failed:", err)
		os.Exit(1)
	}

	if cert_request_id == "" {
		fmt.Println("Specify --cert-request-id")
		os.Exit(1)
	}

	if len(all_config) > 1 && environment == "" {
		fmt.Println("You must tell me which environment to use.", len(all_config))
		os.Exit(1)
	}
	if len(all_config) == 1 && environment == "" {
		for environment = range all_config {
			// lame way of extracting first and only key from a map?
		}
	}
	config := all_config[environment]

	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		fmt.Println("Dial failed:", err)
		os.Exit(1)
	}
	ssh_agent := agent.NewClient(conn)

	signers, err := ssh_agent.Signers()
	var signer ssh.Signer
	signer = nil
	if err != nil {
		fmt.Println("No keys found in agent, can't sign request, bailing.")
		fmt.Println("ssh-add the private half of the key you want to use.")
		os.Exit(1)
	} else {
		for i := range signers {
			signer_fingerprint := ssh_ca.MakeFingerprint(signers[i].PublicKey().Marshal())
			if signer_fingerprint == config.KeyFingerprint {
				signer = signers[i]
				break
			}
		}
	}
	if signer == nil {
		fmt.Println("ssh-add the private half of the key you want to use.")
		os.Exit(1)
	}

	request_parameters := make(url.Values)
	request_parameters["environment"] = make([]string, 1)
	request_parameters["environment"][0] = environment
	request_parameters["cert_request_id"] = make([]string, 1)
	request_parameters["cert_request_id"][0] = cert_request_id
	get_resp, err := http.Get(config.SignerUrl + "cert/requests?" + request_parameters.Encode())
	get_resp_buf := make([]byte, 4096)
	bytes_read, _ := get_resp.Body.Read(get_resp_buf)
	get_resp.Body.Close()
	if get_resp.StatusCode != 200 {
		fmt.Println("Error getting that request id:", string(get_resp_buf))
		os.Exit(1)
	}
	get_response := make(CertRequestResponse)
	err = json.Unmarshal(get_resp_buf[:bytes_read], &get_response)
	if err != nil {
		fmt.Println("Unable to unmarshall response", err)
		os.Exit(1)
	}
	parseable_cert := []byte("ssh-rsa-cert-v01@openssh.com " + get_response[cert_request_id])
	pub_key, _, _, _, err := ssh.ParseAuthorizedKey(parseable_cert)
	if err != nil {
		fmt.Println("Trouble parsing response", err)
		os.Exit(1)
	}
	cert := pub_key.(*ssh.Certificate)
	fmt.Println("Certificate data:")
	fmt.Printf("  Serial: %v\n", cert.Serial)
	fmt.Printf("  Key id: %v\n", cert.KeyId)
	fmt.Printf("  Valid for public key: %s\n", ssh_ca.MakeFingerprint(cert.Key.Marshal()))
	fmt.Printf("  Valid from %v - %v\n",
		time.Unix(int64(cert.ValidAfter), 0), time.Unix(int64(cert.ValidBefore), 0))
	fmt.Printf("Type 'yes' if you'd like to sign this cert request ")
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	if text != "yes" && text != "YES" {
		os.Exit(0)
	}

	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		fmt.Println("Error signing:", err)
		os.Exit(1)
	}

	signed_request := cert.Marshal()

	request_parameters = make(url.Values)
	request_parameters["cert"] = make([]string, 1)
	request_parameters["cert"][0] = base64.StdEncoding.EncodeToString(signed_request)
	request_parameters["environment"] = make([]string, 1)
	request_parameters["environment"][0] = environment
	resp, err := http.PostForm(config.SignerUrl+"cert/requests/"+cert_request_id, request_parameters)
	if err != nil {
		fmt.Println("Error sending request to signer daemon:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		fmt.Println("Signature accepted by server.")
	} else {
		fmt.Println("Cert signature not accepted.")
		fmt.Println("HTTP status", resp.Status)
		resp_buf := make([]byte, 1024)
		resp.Body.Read(resp_buf)
		fmt.Println(string(resp_buf))
		os.Exit(1)
	}

}
