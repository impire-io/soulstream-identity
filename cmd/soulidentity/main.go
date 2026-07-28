// Command soulidentity runs and talks to the SoulIdentity agent: an ssh-agent
// for personas. `serve` is the daemon; every other subcommand is a client of
// the agent's socket.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/impire-io/soulidentity/client"
	"github.com/impire-io/soulidentity/internal/agent"
	"github.com/impire-io/soulidentity/internal/registry"
	"github.com/impire-io/soulidentity/internal/vault"
	"github.com/impire-io/soulidentity/internal/version"
)

const usage = `soulidentity — an ssh-agent for personas

Usage:
  soulidentity serve    [--data DIR] [--socket PATH]     run the agent
  soulidentity status   [--socket PATH]                  probe the agent
  soulidentity key import --name N --kind K (--seed-file F | --seed-stdin)
  soulidentity key ls
  soulidentity identity add --account A --user U [--personas p1,p2] [--role R]
  soulidentity identity ls
  soulidentity mint     --account A --user U [--creds]
  soulidentity version

Kinds: nats-account-signing-key | nats-user-key | persona-signing-key
Defaults: data dir <user-config-dir>/soulidentity, socket <data>/agent.sock.
--creds prints a creds file: the seed LEAVES the vault — an explicit custody
escape for external tools, not the normal path (see hq/02-DESIGN/agent.md D7).
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errw io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(errw, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(rest, errw)
	case "status":
		err = cmdStatus(rest, out)
	case "key":
		err = cmdKey(rest, out)
	case "identity":
		err = cmdIdentity(rest, out)
	case "mint":
		err = cmdMint(rest, out)
	case "version":
		fmt.Fprintln(out, version.Version)
	case "help", "-h", "--help":
		fmt.Fprint(out, usage)
	default:
		fmt.Fprintf(errw, "soulidentity: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(errw, "soulidentity:", err)
		return 1
	}
	return 0
}

func defaultDataDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "soulidentity"
	}
	return filepath.Join(dir, "soulidentity")
}

func socketFlag(fs *flag.FlagSet) *string {
	return fs.String("socket", client.DefaultSocket(), "agent socket path")
}

func cmdServe(args []string, errw io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	data := fs.String("data", defaultDataDir(), "data directory (vault + registry)")
	socket := fs.String("socket", "", "socket path (default <data>/agent.sock)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *socket == "" {
		*socket = filepath.Join(*data, "agent.sock")
	}
	v, err := vault.Open(filepath.Join(*data, "vault"))
	if err != nil {
		return err
	}
	reg, err := registry.Open(filepath.Join(*data, "registry.json"))
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(errw, nil))
	a := agent.New(v, reg, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("agent serving", "socket", *socket, "data", *data, "version", version.Version)
	return agent.Serve(ctx, *socket, a.Handler())
}

func cmdStatus(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	socket := socketFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ver, err := client.New(*socket).Status()
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "agent %s at %s\n", ver, *socket)
	return nil
}

func cmdKey(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("key needs a subcommand: import | ls")
	}
	switch args[0] {
	case "import":
		fs := flag.NewFlagSet("key import", flag.ContinueOnError)
		socket := socketFlag(fs)
		name := fs.String("name", "", "vault name for the key")
		kind := fs.String("kind", "", "key kind")
		seedFile := fs.String("seed-file", "", "file holding the seed")
		seedStdin := fs.Bool("seed-stdin", false, "read the seed from stdin")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		var secret string
		switch {
		case *seedFile != "":
			data, err := os.ReadFile(*seedFile)
			if err != nil {
				return err
			}
			secret = strings.TrimSpace(string(data))
		case *seedStdin:
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}
			secret = strings.TrimSpace(string(data))
		default:
			return fmt.Errorf("key import needs --seed-file or --seed-stdin (never a flag: seeds do not belong in shell history)")
		}
		entry, err := client.New(*socket).ImportKey(*name, *kind, secret)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "imported %s (%s) %s\n", entry.Name, entry.Kind, entry.PublicKey)
		return nil
	case "ls":
		fs := flag.NewFlagSet("key ls", flag.ContinueOnError)
		socket := socketFlag(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		keys, err := client.New(*socket).Keys()
		if err != nil {
			return err
		}
		for _, k := range keys {
			fmt.Fprintf(out, "%s\t%s\t%s\n", k.Name, k.Kind, k.PublicKey)
		}
		return nil
	default:
		return fmt.Errorf("unknown key subcommand %q", args[0])
	}
}

func cmdIdentity(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("identity needs a subcommand: add | ls")
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("identity add", flag.ContinueOnError)
		socket := socketFlag(fs)
		account := fs.String("account", "", "NATS account public key (A…)")
		user := fs.String("user", "", "user name within the account")
		personas := fs.String("personas", "", "comma-separated personas this identity may act as")
		role := fs.String("role", "", "vault name of the account signing key that mints for this identity")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		id := client.Identity{Account: *account, User: *user, Role: *role}
		if *personas != "" {
			for _, p := range strings.Split(*personas, ",") {
				id.Personas = append(id.Personas, strings.TrimSpace(p))
			}
		}
		if err := client.New(*socket).PutIdentity(id); err != nil {
			return err
		}
		fmt.Fprintf(out, "declared %s/%s\n", id.Account, id.User)
		return nil
	case "ls":
		fs := flag.NewFlagSet("identity ls", flag.ContinueOnError)
		socket := socketFlag(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		ids, err := client.New(*socket).Identities()
		if err != nil {
			return err
		}
		for _, id := range ids {
			fmt.Fprintf(out, "%s/%s\tpersonas=%s\trole=%s\n",
				id.Account, id.User, strings.Join(id.Personas, ","), id.Role)
		}
		return nil
	default:
		return fmt.Errorf("unknown identity subcommand %q", args[0])
	}
}

func cmdMint(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("mint", flag.ContinueOnError)
	socket := socketFlag(fs)
	account := fs.String("account", "", "NATS account public key (A…)")
	user := fs.String("user", "", "user name within the account")
	creds := fs.Bool("creds", false, "ALSO print a creds file — the seed leaves the vault (custody escape)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c := client.New(*socket)
	if *creds {
		res, err := c.MintCreds(*account, *user)
		if err != nil {
			return err
		}
		fmt.Fprint(out, res.Creds)
		return nil
	}
	res, err := c.Mint(*account, *user)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s\n", res.JWT)
	return nil
}
