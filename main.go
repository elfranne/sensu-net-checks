package main

import (
	"fmt"
	"log"
	"os"

	"github.com/sensu/sensu-go/types"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

// Config represents the check plugin config.
type Config struct {
	sensu.PluginConfig
	State              string
	Udp                bool
	Tcp                bool
	Warning            int
	Critical           int
}

var (
	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "http-check",
			Short:    "HTTP Status/String Check",
			Keyspace: "sensu.io/plugins/net-checks/config",
		},
	}

	options = []*sensu.PluginConfigOption{
		{
			Path:      "state",
			Env:       "STATE",
			Argument:  "state",
			Shorthand: "s",
			Default:   "established",
			Usage:     "Connection state",
			Value:     &plugin.State,
		},
		{
			Path:      "search-string",
			Env:       "CHECK_SEARCH_STRING",
			Argument:  "search-string",
			Shorthand: "s",
			Default:   "",
			Usage:     "String to search for, if not provided do status check only",
			Value:     &plugin.SearchString,
		},
		{
			Path:      "insecure-skip-verify",
			Env:       "",
			Argument:  "insecure-skip-verify",
			Shorthand: "i",
			Default:   false,
			Usage:     "Skip TLS certificate verification (not recommended!)",
			Value:     &plugin.InsecureSkipVerify,
		},
		{
			Path:      "trusted-ca-file",
			Env:       "",
			Argument:  "trusted-ca-file",
			Shorthand: "t",
			Default:   "",
			Usage:     "TLS CA certificate bundle in PEM format",
			Value:     &plugin.TrustedCAFile,
		},
		{
			Path:      "redirect-ok",
			Env:       "",
			Argument:  "redirect-ok",
			Shorthand: "r",
			Default:   false,
			Usage:     "Allow redirects",
			Value:     &plugin.RedirectOK,
		},
		{
			Path:      "timeout",
			Env:       "",
			Argument:  "timeout",
			Shorthand: "T",
			Default:   15,
			Usage:     "Request timeout in seconds",
			Value:     &plugin.Timeout,
		},
		{
			Path:      "header",
			Env:       "",
			Argument:  "header",
			Shorthand: "H",
			Default:   []string{},
			Usage:     "Additional header(s) to send in check request",
			Value:     &plugin.Headers,
		},
		{
			Path:      "mtls-key-file",
			Env:       "",
			Argument:  "mtls-key-file",
			Shorthand: "K",
			Default:   "",
			Usage:     "Key file for mutual TLS auth in PEM format",
			Value:     &plugin.MTLSKeyFile,
		},
		{
			Path:      "mtls-cert-file",
			Env:       "",
			Argument:  "mtls-cert-file",
			Shorthand: "C",
			Default:   "",
			Usage:     "Certificate file for mutual TLS auth in PEM format",
			Value:     &plugin.MTLSCertFile,
		},
	}
)


func main() {
	useStdin := false
	fi, err := os.Stdin.Stat()
	if err != nil {
		fmt.Printf("Error check stdin: %v\n", err)
		panic(err)
	}
	//Check the Mode bitmask for Named Pipe to indicate stdin is connected
	if fi.Mode()&os.ModeNamedPipe != 0 {
		log.Println("using stdin")
		useStdin = true
	}

	check := sensu.NewGoCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, useStdin)
	check.Execute()
}

func checkArgs(event *types.Event) (int, error) {
	if len(plugin.Example) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--example or CHECK_EXAMPLE environment variable is required")
	}
	return sensu.CheckStateOK, nil
}

func executeCheck(event *types.Event) (int, error) {
	log.Println("executing check with --example", plugin.Example)
	return sensu.CheckStateOK, nil
}
