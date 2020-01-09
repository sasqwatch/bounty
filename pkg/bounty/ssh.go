package bounty

import (
	"encoding/hex"
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"net"
	"sync"
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

// DefaultPrivateKey provides a built-in key for testing
var DefaultPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAt7kW3Tbs3JqXK4hjQ3yJ4JvuMtWajIxczQLRe6ygPW+6UddW
lNKzzr+dbNQn/Aa60yoww0dEZ5YAdu7OmJFj4K7znSKH1Wnj+RlVLbjTOBduym7C
OU7CPEoL/Lk1VrB1r93z76gd2+j8i6mAinEXw5qaw9UY8ZZsladGHOrkzrPyo7uq
pN5ka31qBT4ECFdYJyWUoz0koZouWG9eofAs4i8KBueJi1v5qZeNzAKWld6A8gzK
qgOJmOQDeSluV8EnrkJoJqMPYPH1xe1tfX58f+QfsYvWxE9bE19he/LuqUTBXn7J
CSqMe8oklLo3NTZtzp2OrawxDTM2PcfRU6fnlQIDAQABAoIBACtPFWW2YeWrB4G6
l/O7suDgwSj4k4MYP3QQewNVcTyqTtimE4HnnX1aTCjwZjCSAY5vvqj57tUgViGz
L75lX48Cjuj2z+BuItCAuUSa8ieh1nsf2ucZes4tgl/j5P/3fvajMrLHBarmZEoj
/eokuL5ifqM1Y7jnhddNZEjC0ocrG3r7R6UPZSmBW/teFqAoHRC0B06TJZjMqCRl
1hSispK4394iXiQnRBUUh4G6lM+FTzv9dV4TVSDHavX+rSievw6SpaSK//QR92pM
xr11IiXvn2MZBnQ49anoFLeSLHqcW6aaVI0kY3fRIjh2rvrtX/JqTsmJ/zFPpBmr
LptVPQ0CgYEA8CmD2rEzD9Itv66KbtQI3WgTQotqQALzuG2mCgitGtg6uTyUxFJK
yu56v/x9G8g//cDDOHScuQXxxlN/Hh/Bec6RqYUAUpY8IibfjSwaAN6WPZkGvQIA
jkr3B1RZs2xi4ZTm3sL5syPAgGjDPO8DKm+0iGFge0yus9vpKqpeTHsCgYEAw9bA
pHK/uao4n8VoqsI40WW4lyZIT1Gs5BgwvW7xuL/PUfM7e+wbNDGIZ27QSYl2TK/K
9yXt+mm+GGc1TjE0053PdovAdP1zb8Mb2DpDEQNsQHhkEPB3f9S5Tlh3m9Trtno8
pDSku+k4QQDIgZR9niXz5D91Aiu3RmQzlm4Zhy8CgYEAkrO5YIB3wYVQ/tL+qv6I
v76QbUi+SYXEHPeVwnFUVJ6bGIYCFf5yw41znAz+21ayiC4U0kqhZYBVFSHx95PM
WrytS9D7xncRGoeGbTTwWXGectgkPpaXglQWm/qRpMFjkYqkkJSndR80uvvDr1gN
JgIAVIKvLgJEgYem4bIaUjsCgYBtpY5ERG7t7802PxvEB2wyaSZ5khiIOG15Y8Xe
OgCidNoJwwo57s6oYVdCuftqQMl4VDBqQdVFD/E7zoU82zX9iWy/ra06kzEPkQjE
/pHQM79nNUCpb0kozBxYLhYBrKuwhi3vrf3Rq9kwI9UfH9lZM1yjHZhQd9NsWOu9
PLWURwKBgAK8jwEvFniwa7u5pIkJfMi3bHU9OwaRLxByovOY2LkHdDMBYItu7IHp
cTeLJCwu0cDacJf8QFSGUFmWcN6vGwPOWWHQTOHBXUYljXG3f8v3ekt6JdIiZw9L
i53xQKPYRa6nirk1zSZYBnWJM3Ms1aypW6pe0YoO2P3nMs6rpMgn
-----END RSA PRIVATE KEY-----
`

// NewConfSSH creates a default configuration for the SSH capture server
func NewConfSSH() *ConfSSH {
	return &ConfSSH{
		PrivateKey: DefaultPrivateKey,
		BindPort:   22,
		BindHost:   "[::]",
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
			"username":    sshConn.User(),
			"pubkey_type": pubkey.Type(),
			"pubkey_hash": ssh.FingerprintSHA256(pubkey),
			"pubkey_data": hex.EncodeToString(pubkey.Marshal()),
			"version":     string(sshConn.ClientVersion()),
			"method":      "pubkey",
		},
	)
	return nil, fmt.Errorf("pubkey collected for %q", sshConn.User())
}

// SpawnSSH starts a logging SSH server
func SpawnSSH(c *ConfSSH) error {

	// Configure the ssh server
	pk, err := ssh.ParsePrivateKey([]byte(c.PrivateKey))
	if err != nil {
		return fmt.Errorf("ssh server failed to parse private key")
	}
	c.ServerConfig.AddHostKey(pk)

	// Create the TCP listener
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort))
	if err != nil {
		return fmt.Errorf("ssh server failed to listen on %s:%d (%s)", c.BindHost, c.BindPort, err)
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
