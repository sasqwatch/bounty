package cmd

import (
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/hdm/bounty/pkg/bounty"
	log "github.com/sirupsen/logrus"
)

func startCapture(cmd *cobra.Command, args []string) {
	done := false
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done = true
	}()

	// TODO: Process CLI arguments

	// TODO: Configure output actions

	// Setup protocol listeners

	// SSH

	sshHostKey := ""
	if params.SSHHostKey != "" {
		data, err := ioutil.ReadFile(params.SSHHostKey)
		if err != nil {
			log.Fatalf("failed to read ssh host key %s: %s", params.SSHHostKey, err)
		}
		sshHostKey = string(data)
	}
	if sshHostKey == "" {
		// TODO: Generate a ssh host key on the fly
	}

	// Create a listener for each port
	sshPorts, err := bounty.CrackPorts(params.SSHPorts)
	if err != nil {
		log.Fatalf("failed to process ssh ports %s: %s", params.SSHPorts, err)
	}
	for _, port := range sshPorts {
		port := port
		sshConf := bounty.NewConfSSH()
		sshConf.PrivateKey = sshHostKey
		sshConf.BindPort = uint16(port)
		if err := bounty.SpawnSSH(sshConf); err != nil {
			log.Fatalf("failed to start ssh server: %q", err)
		}
	}

	// Loop until service is terminated
	for {
		if done {
			log.Printf("shutting down...")
			break
		}
		time.Sleep(time.Second)
	}
}
