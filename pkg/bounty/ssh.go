package bounty

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// ConfSSH describes the options for a ssh service
type ConfSSH struct {
	PrivateKey   string
	BindPort     uint16
	BindHost     string
	ServerConfig *ssh.ServerConfig
	shutdown     bool
	listener     net.Listener
	m            sync.Mutex
}

// IsShutdown checks to see if the service is shutting down
func (c *ConfSSH) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down
func (c *ConfSSH) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	c.shutdown = true
	c.listener.Close()
}

// NewConfSSH creates a default configuration for the SSH capture server
func NewConfSSH() *ConfSSH {
	return &ConfSSH{
		BindPort: 22,
		BindHost: "[::]",
		ServerConfig: &ssh.ServerConfig{
			PasswordCallback:  sshHandlePassword,
			PublicKeyCallback: sshHandlePubkey,
			ServerVersion:     "SSH-2.0-OpenSSH_7.6p1",
		},
	}
}

func sshHandlePassword(sshConn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	RecordCredential(
		"ssh",
		sshConn.RemoteAddr().String(),
		map[string]string{
			"username": sshConn.User(),
			"password": string(pass),
			"version":  string(sshConn.ClientVersion()),
			"method":   "password",
		},
	)
	return nil, fmt.Errorf("password collected for %q", sshConn.User())
}

func sshHandlePubkey(sshConn ssh.ConnMetadata, pubkey ssh.PublicKey) (*ssh.Permissions, error) {
	RecordCredential(
		"ssh",
		sshConn.RemoteAddr().String(),
		map[string]string{
			"username":      sshConn.User(),
			"pubkey-sha256": ssh.FingerprintSHA256(pubkey),
			"pubkey":        strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubkey))),
			"version":       string(sshConn.ClientVersion()),
			"method":        "pubkey",
		},
	)
	return nil, fmt.Errorf("pubkey collected for %q", sshConn.User())
}

// SpawnSSH starts a logging SSH server
func SpawnSSH(c *ConfSSH) error {

	if c.PrivateKey == "" {
		pkey, err := sshGenerateRSAKey(2048)
		if err != nil {
			return fmt.Errorf("failed to generate private key: %q", err)
		}
		c.PrivateKey = string(pkey)
	}

	// Configure the ssh server
	pk, err := ssh.ParsePrivateKey([]byte(c.PrivateKey))
	if err != nil {
		return fmt.Errorf("failed to parse private key")
	}
	c.ServerConfig.AddHostKey(pk)

	// Create the TCP listener
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort))
	if err != nil {
		return fmt.Errorf("failed to listen on %s:%d (%s)", c.BindHost, c.BindPort, err)
	}
	c.listener = listener

	// Start the ssh handler
	go sshStart(c)

	return nil
}

func sshStart(c *ConfSSH) {
	log.Debugf("ssh is listening on %s:%d", c.BindHost, c.BindPort)
	for {
		if c.IsShutdown() {
			log.Debugf("ssh server is shutting down")
			break
		}
		tcpConn, err := c.listener.Accept()
		if err != nil {
			log.Printf("ssh failed to accept incoming connection (%s)", err)
			continue
		}

		go sshHandleConn(tcpConn, c)
	}
}

func sshHandleConn(tcpConn net.Conn, c *ConfSSH) {
	// Ensure the socket is closed
	defer tcpConn.Close()

	// Negotiate the session
	sshConn, _, _, err := ssh.NewServerConn(tcpConn, c.ServerConfig)
	if err != nil {
		return
	}

	// Until we support authenticated sessions, this is unused

	// Ensure the ssh session is closed
	defer sshConn.Close()
}

func sshGenerateRSAKey(bits int) ([]byte, error) {
	pkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	err = pkey.Validate()
	if err != nil {
		return nil, err
	}

	pkeyDER := x509.MarshalPKCS1PrivateKey(pkey)
	pkeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   pkeyDER,
	}

	pkeyPEM := pem.EncodeToMemory(&pkeyBlock)

	return pkeyPEM, nil
}
