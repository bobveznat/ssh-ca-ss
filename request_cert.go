package main

import (
    "encoding/base64"
    "crypto/rand"
    "flag"
    "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"log"
	"net"
	"os"
    "time"
    "strings"
    "./ssh_ca"
)

func main() {
    var principals_str, environment string
    var valid_before_dur, valid_after_dur time.Duration
    command_line_has_errors := false

    home := os.Getenv("HOME")
    if home == "" {
        home = "/"
    }
    config_path := home + "/.ssh_ca/requester_config.json"

    valid_before_dur, _ = time.ParseDuration("2h")
    valid_after_dur, _ = time.ParseDuration("0")

    flag.StringVar(&principals_str, "principals", "", "Valid usernames for login. Comma separated.")
    flag.StringVar(&environment, "environment", "", "The environment you want (e.g. prod).")
    flag.StringVar(&config_path, "config_path", config_path, "Path to config json.")
    flag.DurationVar(&valid_after_dur, "valid-after", valid_after_dur, "Relative time")
    flag.DurationVar(&valid_before_dur, "valid-before", valid_before_dur, "Relative time")
    flag.Parse()

    config, err := ssh_ca.LoadRequesterConfig(config_path)
	if err != nil {
		log.Println("Load Config failed:", err)
		os.Exit(1)
    }

    if len(config) > 1 && environment == "" {
        log.Println("You must tell me which environment to use.", len(config))
        os.Exit(1)
    }
    if len(config) == 1 && environment == "" {
        for environment = range config {
            // lame way of extracting first and only key from a map?
        }
    }

    time_now := time.Now().Unix()
    valid_after := uint64(time_now + int64(valid_after_dur.Seconds()))
    valid_before := uint64(time_now + int64(valid_before_dur.Seconds()))

    if valid_after >= valid_before {
        log.Printf("valid-after (%v) >= valid-before (%v). Which does not make sense.\n",
    time.Unix(int64(valid_after), 0), time.Unix(int64(valid_before), 0))
        command_line_has_errors = true
    }

    principals := strings.Split(strings.TrimSpace(principals_str), ",")
    if principals_str == "" {
        log.Println("You didn't specify any principals. This cert is worthless.")
        command_line_has_errors = true
    }

    if command_line_has_errors {
        log.Println("One or more command line flags are busted.")
        os.Exit(1)
    }

    pub_key_file, err := os.Open(config[environment].PublicKeyPath)
    if err != nil {
        log.Println("Trouble opening your public key file", pub_key_file, err)
        os.Exit(1)
    }
    buf := make([]byte, 1<<13)
    count, err := pub_key_file.Read(buf)
    if err != nil || count == 0 {
        log.Println("Trouble opening your public key file", pub_key_file, err)
        os.Exit(1)
    }
    pub_key, _, _, _, err := ssh.ParseAuthorizedKey(buf)
    if err != nil {
        log.Println("Trouble parsing your public key", err)
        os.Exit(1)
    }
    chosen_key_fingerprint := ssh_ca.MakeFingerprint(pub_key.Marshal())

	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		log.Println("Dial failed:", err)
		os.Exit(1)
	}
	ssh_agent := agent.NewClient(conn)

	signers, err := ssh_agent.Signers()
    var signer ssh.Signer
    signer = nil
	if err != nil {
		log.Println("No keys found in agent, can't sign request, bailing.")
		log.Println("ssh-add the private half of the key you want to use.")
        os.Exit(1)
	} else {
		for i := range signers {
            signer_fingerprint := ssh_ca.MakeFingerprint(signers[i].PublicKey().Marshal())
            if signer_fingerprint == chosen_key_fingerprint {
                signer = signers[i]
                break
            }
		}
	}
    if signer == nil {
		log.Println("ssh-add the private half of the key you want to use.")
        os.Exit(1)
    }

    var new_cert ssh_ca.SshCertificate
    new_cert.Nonce = make([]byte, 32)
    new_cert.Key = signer.PublicKey()
    new_cert.Serial = 0
    new_cert.CertType = ssh.UserCert
    new_cert.KeyId = "deadbeef"
    new_cert.ValidPrincipals = principals
    new_cert.ValidAfter = valid_after
    new_cert.ValidBefore = valid_before

    err = new_cert.SignCert(rand.Reader, signer)
    if err != nil {
        log.Println("Error signing:", err)
        os.Exit(1)
    }

    cert_request := new_cert.Marshal()
    log.Println("Cert request is:", base64.StdEncoding.EncodeToString(cert_request))
    log.Printf("And that is:\n%s\n", new_cert.GoString())
}
