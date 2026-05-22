package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/hadamrd/ghostrun/internal/policy"
)

type stringList []string

func (s *stringList) String() string {
	return fmt.Sprint([]string(*s))
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type config struct {
	Policy  policy.Options
	JSON    bool
	Command []string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cfg, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	p, err := policy.New(cfg.Policy)
	if err != nil {
		fmt.Fprintf(stderr, "invalid policy: %v\n", err)
		return 2
	}
	if p.Empty() {
		fmt.Fprintln(stderr, "refusing to run without at least one --deny-write or --deny-connect policy")
		return 2
	}

	if cfg.JSON {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"status":  "not_implemented",
			"message": "kernel enforcement is not wired yet",
			"command": cfg.Command,
		})
		return 1
	}
	fmt.Fprintln(stderr, "kernel enforcement is not wired yet")
	return 1
}

func parseArgs(args []string) (config, error) {
	var deniedWrites stringList
	var deniedConnects stringList
	cfg := config{}

	flags := flag.NewFlagSet("ghostrun", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Var(&deniedWrites, "deny-write", "deny writes under path prefix")
	flags.Var(&deniedConnects, "deny-connect", "deny connects to CIDR")
	flags.BoolVar(&cfg.JSON, "json", false, "write JSON output")
	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	cfg.Policy = policy.Options{
		DeniedWritePrefixes: []string(deniedWrites),
		DeniedConnectCIDRs:  []string(deniedConnects),
	}
	cfg.Command = flags.Args()
	if len(cfg.Command) == 0 {
		return config{}, errors.New("missing command; usage: ghostrun [policy flags] -- command [args...]")
	}
	return cfg, nil
}
