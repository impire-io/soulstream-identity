// Command soulstream-identity runs and talks to the SoulIdentity service: the
// identity plane of the Soulstream ecosystem, served over NATS
// (../soul-hq/02-DESIGN/soulstream-identity/nats-surface.md). `serve` is the daemon; every other
// subcommand is a NATS client of the service's sealed surface, speaking as
// the principal named by --as.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/synadia-io/orbit.go/natscontext"

	"github.com/impire-io/soulstream-identity/client"
	"github.com/impire-io/soulstream-identity/embed"
	"github.com/impire-io/soulstream-identity/internal/service"
	"github.com/impire-io/soulstream-identity/internal/version"
)

const usage = `soulstream-identity — the identity plane, served over NATS

Usage:
  soulstream-identity serve    [conn] [--bucket NAME]                       run the service
                        [--callout-creds F | --callout-context C]    …as callout issuer (M4):
                        [--auth-key NAME] [--token-bucket NAME] [--callout-ttl DUR]
  soulstream-identity keygen                              mint an xkey seed (seed on stdout)
  soulstream-identity status   [conn]                     probe the service
  soulstream-identity key import   [conn] --as A/U --name N --kind K (--seed-file F | --seed-stdin)
                            [--account A] [--user U]   the binding (role / persona owner, D24/D25)
  soulstream-identity key ls       [conn] --as A/U
  soulstream-identity mint         [conn] --as A/U [--account A --user U] [--creds]
                            | --role R --user-key U... --ttl DUR [--user U] [--tag k:v]...
                              ephemeral, role by name (D28): your key, JWT only
  soulstream-identity token create [conn] --as A/U --account A --user U [--label L] [--ttl DUR]
  soulstream-identity token ls     [conn] --as A/U
  soulstream-identity token revoke [conn] --as A/U --digest D
  soulstream-identity sentinel     [conn] --as A/U        mint the sentinel creds (stdout)
  soulstream-identity grant link   [conn] --as A/U --resource R      begin an outbound link: consent URL (D30)
                            | --link-id ID --code C      complete it — custody begins (D31)
  soulstream-identity grant access [conn] --as A/U --resource R      your derived access token, stdout (D32)
  soulstream-identity grant ls     [conn] --as A/U
  soulstream-identity grant revoke [conn] --as A/U --resource R      delete custody; upstream best-effort
  soulstream-identity version

Conn: --context NAME (a NATS CLI context) or --url URL [--creds-file FILE].
--as is the principal (<account-public-key>/<user>) the connection is
authenticated as; the server refuses mismatched prefixes (D15). The same
enforcement gates the ops themselves: management (keys.*, tokens.*, mint,
sentinel) is reachable only for credentials whose permission template
grants those op subjects — represented users get sign.record, keys.public
and (on grants-enabled deployments) grants.> on their own prefix, nothing
more (D25/D30).
Serve reads its xkey seeds from SOULIDENTITY_FIRST_KEY,
SOULIDENTITY_SURFACE_KEY and (callout, optional) SOULIDENTITY_CALLOUT_KEY;
the matching flags are accepted but argv is visible in the process table —
prefer the environment (D13). The callout connection (--callout-creds /
--callout-context) authenticates in the AUTH account (D21); its presence
enables the issuer and the token/sentinel ops.
Kinds: nats-account-signing-key | nats-user-key | persona-signing-key
--creds prints a creds file: the seed LEAVES the vault — the explicit custody
escape (../soul-hq/02-DESIGN/soulstream-identity/agent.md D7) and the way onto the bypass lane (D12).
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
	case "keygen":
		err = cmdKeygen(out, errw)
	case "status":
		err = cmdStatus(rest, out)
	case "key":
		err = cmdKey(rest, out)
	case "mint":
		err = cmdMint(rest, out)
	case "token":
		err = cmdToken(rest, out)
	case "sentinel":
		err = cmdSentinel(rest, out)
	case "grant":
		err = cmdGrant(rest, out)
	case "version":
		fmt.Fprintln(out, version.Version)
	case "help", "-h", "--help":
		fmt.Fprint(out, usage)
	default:
		fmt.Fprintf(errw, "soulstream-identity: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(errw, "soulstream-identity:", err)
		return 1
	}
	return 0
}

// connFlags registers the connection flags shared by every NATS-speaking
// subcommand, plus the deployment's shared subject prefix (D14 as amended):
// --prefix, defaulting to SOULSTREAM_PREFIX — one value across the whole
// soulstream ecosystem so components find each other.
type connFlags struct {
	context, url, creds, prefix *string
}

func addConnFlags(fs *flag.FlagSet) connFlags {
	return connFlags{
		context: fs.String("context", "", "NATS CLI context name (github.com/synadia-io/orbit.go/natscontext)"),
		url:     fs.String("url", "", "NATS server URL (default "+nats.DefaultURL+")"),
		creds:   fs.String("creds-file", "", "creds file for the connection (the bypass lane, D12)"),
		prefix:  fs.String("prefix", os.Getenv("SOULSTREAM_PREFIX"), "shared ecosystem subject prefix (default $SOULSTREAM_PREFIX)"),
	}
}

func (c connFlags) connect() (*nats.Conn, error) {
	if *c.context != "" {
		nc, _, err := natscontext.Connect(*c.context, nats.Name("soulstream-identity"))
		if err != nil {
			return nil, fmt.Errorf("context %q: %w", *c.context, err)
		}
		return nc, nil
	}
	url := *c.url
	if url == "" {
		url = nats.DefaultURL
	}
	opts := []nats.Option{nats.Name("soulstream-identity")}
	if *c.creds != "" {
		opts = append(opts, nats.UserCredentials(*c.creds))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", url, err)
	}
	return nc, nil
}

// asFlag parses the principal: <account-public-key>/<user>.
func asFlag(fs *flag.FlagSet) *string {
	return fs.String("as", "", "principal this connection speaks as: <account-public-key>/<user>")
}

func parseAs(as string) (account, user string, err error) {
	account, user, ok := strings.Cut(as, "/")
	if !ok || account == "" || user == "" {
		return "", "", errors.New("--as must be <account-public-key>/<user>")
	}
	return account, user, nil
}

func newClient(cf connFlags, as string) (*client.Client, func(), error) {
	account, user, err := parseAs(as)
	if err != nil {
		return nil, nil, err
	}
	if err := service.ValidatePrefix(*cf.prefix); err != nil {
		return nil, nil, err
	}
	nc, err := cf.connect()
	if err != nil {
		return nil, nil, err
	}
	return client.New(nc, account, user, client.WithPrefix(*cf.prefix)), nc.Close, nil
}

// seedFromFlagOrEnv resolves an xkey seed: flag first (accepted, but argv is
// world-visible), environment as the documented home (D13).
func seedFromFlagOrEnv(flagVal, envName string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if v := os.Getenv(envName); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("no seed: set %s (or --%s)", envName, strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(envName, "SOULIDENTITY_"), "_", "-")))
}

// stringFromFlagOrEnv resolves optional configuration: flag first, then the
// environment; empty means unset.
func stringFromFlagOrEnv(flagVal, envName string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv(envName)
}

func cmdServe(args []string, errw io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cf := addConnFlags(fs)
	bucket := fs.String("bucket", "SOULIDENTITY_VAULT", "KV bucket holding the sealed vault")
	firstKey := fs.String("first-key", "", "vault first key seed (SX…); prefer SOULIDENTITY_FIRST_KEY")
	surfaceKey := fs.String("surface-key", "", "surface xkey seed (SX…); prefer SOULIDENTITY_SURFACE_KEY")
	calloutCreds := fs.String("callout-creds", "", "creds file for the AUTH-account callout connection (enables the issuer, D21)")
	calloutContext := fs.String("callout-context", "", "NATS CLI context for the AUTH-account callout connection")
	authKey := fs.String("auth-key", "auth/issuer", "vault name of the AUTH account signing key (callout responses, sentinels)")
	authAccount := fs.String("auth-account", "", "AUTH account public key (A…) — sentinels name it as issuer_account")
	tokenBucket := fs.String("token-bucket", "SOULIDENTITY_TOKENS", "KV bucket holding API token digests")
	calloutTTL := fs.Duration("callout-ttl", 15*time.Minute, "issued-JWT lifetime — the revocation propagation bound (D22)")
	calloutKey := fs.String("callout-key", "", "callout xkey seed (SX…); prefer SOULIDENTITY_CALLOUT_KEY")
	oidcIssuer := fs.String("oidc-issuer", "", "OIDC issuer URL for the external-JWT lane (D23); or SOULIDENTITY_OIDC_ISSUER")
	oidcAudience := fs.String("oidc-audience", "", "OIDC audience (the app registration's client ID); or SOULIDENTITY_OIDC_AUDIENCE")
	grantsCatalog := fs.String("grants-catalog", "", "JSON file declaring outbound-grant resources (D34); enables the grants.* ops")
	grantsBucket := fs.String("grants-bucket", "SOULIDENTITY_GRANTS", "KV bucket holding sealed grant custody (D31)")
	secretsBucket := fs.String("secrets-bucket", "SOULIDENTITY_SECRETS", "KV bucket holding the sealed general secret store (D36)")
	enableGuardrail := fs.Bool("guardrail", false, "put the evaluator on the op path (D37); rules load live via guardrail.load")
	guardrailRules := fs.String("guardrail-rules", "", "JSON file with the starting rule set [{name, when, effect}]")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var grantResources []embed.GrantResource
	if *grantsCatalog != "" {
		raw, err := os.ReadFile(*grantsCatalog)
		if err != nil {
			return fmt.Errorf("grants catalog: %w", err)
		}
		if err := json.Unmarshal(raw, &grantResources); err != nil {
			return fmt.Errorf("grants catalog %s: %w", *grantsCatalog, err)
		}
	}
	var startingRules []embed.GuardrailRule
	if *guardrailRules != "" {
		raw, err := os.ReadFile(*guardrailRules)
		if err != nil {
			return fmt.Errorf("guardrail rules: %w", err)
		}
		if err := json.Unmarshal(raw, &startingRules); err != nil {
			return fmt.Errorf("guardrail rules %s: %w", *guardrailRules, err)
		}
	}
	firstSeed, err := seedFromFlagOrEnv(*firstKey, "SOULIDENTITY_FIRST_KEY")
	if err != nil {
		return err
	}
	surfaceSeed, err := seedFromFlagOrEnv(*surfaceKey, "SOULIDENTITY_SURFACE_KEY")
	if err != nil {
		return err
	}
	// The callout xkey is optional: only deployments whose AUTH account
	// declares authorization.xkey need it.
	calloutSeed := *calloutKey
	if calloutSeed == "" {
		calloutSeed = os.Getenv("SOULIDENTITY_CALLOUT_KEY")
	}

	nc, err := cf.connect()
	if err != nil {
		return err
	}
	defer nc.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The callout half: a second connection, authenticated in the AUTH
	// account (D21); its presence enables the issuer and the token ops.
	var ncCallout *nats.Conn
	if *calloutCreds != "" || *calloutContext != "" {
		if *authAccount == "" {
			return errors.New("callout needs --auth-account (the AUTH account public key)")
		}
		calloutCF := connFlags{context: calloutContext, url: cf.url, creds: calloutCreds}
		ncCallout, err = calloutCF.connect()
		if err != nil {
			return fmt.Errorf("callout connection: %w", err)
		}
		defer ncCallout.Close()
	}

	// One assembly, two entrypoints (D29): the daemon parses flags and
	// owns its connections; the plane itself is the public embed package.
	err = embed.Run(ctx, embed.Options{
		Conn:            nc,
		CalloutConn:     ncCallout,
		VaultBucket:     *bucket,
		TokenBucket:     *tokenBucket,
		FirstKey:        firstSeed,
		SurfaceKey:      surfaceSeed,
		CalloutKey:      calloutSeed,
		AuthKeyName:     *authKey,
		AuthAccount:     *authAccount,
		CalloutTTL:      *calloutTTL,
		Prefix:          *cf.prefix,
		OIDCIssuer:      stringFromFlagOrEnv(*oidcIssuer, "SOULIDENTITY_OIDC_ISSUER"),
		OIDCAudience:    stringFromFlagOrEnv(*oidcAudience, "SOULIDENTITY_OIDC_AUDIENCE"),
		GrantResources:  grantResources,
		GrantsBucket:    *grantsBucket,
		SecretsBucket:   *secretsBucket,
		EnableGuardrail: *enableGuardrail,
		GuardrailRules:  startingRules,
		Logger:          slog.New(slog.NewTextHandler(errw, nil)),
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	// The daemon owns its connections (the embed contract drains only its
	// own subscriptions): drain them on the way out, as before.
	if ncCallout != nil {
		_ = ncCallout.Drain()
	}
	return nc.Drain()
}

func cmdToken(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("token needs a subcommand: create | ls | revoke")
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("token create", flag.ContinueOnError)
		cf := addConnFlags(fs)
		as := asFlag(fs)
		account := fs.String("account", "", "identity's account public key (A…)")
		user := fs.String("user", "", "identity's user name")
		label := fs.String("label", "", "label for the audit trail")
		ttl := fs.Duration("ttl", 0, "token lifetime (0 = no expiry)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		c, done, err := newClient(cf, *as)
		if err != nil {
			return err
		}
		defer done()
		res, err := c.CreateToken(*account, *user, *label, *ttl)
		if err != nil {
			return err
		}
		// The plaintext appears once, on stdout; the digest is the handle.
		fmt.Fprintln(out, res.Token)
		fmt.Fprintf(os.Stderr, "digest (revocation handle): %s\n", res.Digest)
		return nil
	case "ls":
		fs := flag.NewFlagSet("token ls", flag.ContinueOnError)
		cf := addConnFlags(fs)
		as := asFlag(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		c, done, err := newClient(cf, *as)
		if err != nil {
			return err
		}
		defer done()
		tokens, err := c.Tokens()
		if err != nil {
			return err
		}
		for _, tk := range tokens {
			fmt.Fprintf(out, "%s\t%s/%s\t%s\t%s\n", tk.Digest, tk.Account, tk.User, tk.Label, tk.Expires)
		}
		return nil
	case "revoke":
		fs := flag.NewFlagSet("token revoke", flag.ContinueOnError)
		cf := addConnFlags(fs)
		as := asFlag(fs)
		digest := fs.String("digest", "", "the token's digest handle (from create or ls)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		c, done, err := newClient(cf, *as)
		if err != nil {
			return err
		}
		defer done()
		if err := c.RevokeToken(*digest); err != nil {
			return err
		}
		fmt.Fprintf(out, "revoked %s (open connections end at JWT expiry)\n", *digest)
		return nil
	default:
		return fmt.Errorf("unknown token subcommand %q", args[0])
	}
}

func cmdSentinel(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("sentinel", flag.ContinueOnError)
	cf := addConnFlags(fs)
	as := asFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, done, err := newClient(cf, *as)
	if err != nil {
		return err
	}
	defer done()
	res, err := c.MintSentinel()
	if err != nil {
		return err
	}
	fmt.Fprint(out, res.Creds)
	return nil
}

// cmdGrant is the outbound-grants ceremony from the caller's own prefix
// (D30–D32): every verb reaches only the caller's grants — the transport
// enforces that, not this command.
func cmdGrant(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("grant needs a subcommand: link | access | ls | revoke")
	}
	switch args[0] {
	case "link":
		fs := flag.NewFlagSet("grant link", flag.ContinueOnError)
		cf := addConnFlags(fs)
		as := asFlag(fs)
		resource := fs.String("resource", "", "declared resource name (begins a ceremony)")
		linkID := fs.String("link-id", "", "ceremony id from the begin step")
		code := fs.String("code", "", "authorization code from the consent redirect (completes the ceremony)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		c, done, err := newClient(cf, *as)
		if err != nil {
			return err
		}
		defer done()
		if *code != "" {
			if *linkID == "" {
				return errors.New("--code completes a ceremony: --link-id is required")
			}
			if err := c.GrantLinkComplete(*linkID, *code); err != nil {
				return err
			}
			fmt.Fprintln(out, "linked — custody begins; the refresh token never leaves the service")
			return nil
		}
		if *resource == "" {
			return errors.New("--resource begins a ceremony (--link-id with --code completes one)")
		}
		res, err := c.GrantLinkStart(*resource)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, res.AuthorizeURL)
		fmt.Fprintf(os.Stderr, "open the URL, consent, then: soulstream-identity grant link --link-id %s --code <code>\n", res.LinkID)
		return nil
	case "access":
		fs := flag.NewFlagSet("grant access", flag.ContinueOnError)
		cf := addConnFlags(fs)
		as := asFlag(fs)
		resource := fs.String("resource", "", "declared resource name")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		c, done, err := newClient(cf, *as)
		if err != nil {
			return err
		}
		defer done()
		res, err := c.GrantAccessToken(*resource)
		if err != nil {
			return err
		}
		// The derived token alone on stdout — pipeable; provenance on stderr.
		fmt.Fprintln(out, res.AccessToken)
		if res.ExpiresAt != "" {
			fmt.Fprintf(os.Stderr, "expires %s\n", res.ExpiresAt)
		}
		return nil
	case "ls":
		fs := flag.NewFlagSet("grant ls", flag.ContinueOnError)
		cf := addConnFlags(fs)
		as := asFlag(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		c, done, err := newClient(cf, *as)
		if err != nil {
			return err
		}
		defer done()
		infos, err := c.Grants()
		if err != nil {
			return err
		}
		for _, g := range infos {
			fmt.Fprintf(out, "%s\t%s\t%s\n", g.Resource, strings.Join(g.Scopes, " "), g.LinkedAt)
		}
		return nil
	case "revoke":
		fs := flag.NewFlagSet("grant revoke", flag.ContinueOnError)
		cf := addConnFlags(fs)
		as := asFlag(fs)
		resource := fs.String("resource", "", "declared resource name")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		c, done, err := newClient(cf, *as)
		if err != nil {
			return err
		}
		defer done()
		if err := c.GrantRevoke(*resource); err != nil {
			return err
		}
		fmt.Fprintf(out, "revoked %s (custody deleted; upstream revocation best-effort)\n", *resource)
		return nil
	default:
		return fmt.Errorf("unknown grant subcommand %q", args[0])
	}
}

func cmdKeygen(out, errw io.Writer) error {
	kp, err := nkeys.CreateCurveKeys()
	if err != nil {
		return err
	}
	seed, err := kp.Seed()
	if err != nil {
		return err
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return err
	}
	// Seed on stdout (pipe it into the secret store), public half on stderr.
	fmt.Fprintln(out, string(seed))
	fmt.Fprintln(errw, "public key:", pub)
	return nil
}

func cmdStatus(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	cf := addConnFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := service.ValidatePrefix(*cf.prefix); err != nil {
		return err
	}
	nc, err := cf.connect()
	if err != nil {
		return err
	}
	defer nc.Close()
	// Status is an open op: no principal needed.
	ver, err := client.New(nc, "", "", client.WithPrefix(*cf.prefix)).Status()
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "service %s\n", ver)
	return nil
}

func cmdKey(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("key needs a subcommand: import | ls")
	}
	switch args[0] {
	case "import":
		fs := flag.NewFlagSet("key import", flag.ContinueOnError)
		cf := addConnFlags(fs)
		as := asFlag(fs)
		name := fs.String("name", "", "vault name for the key")
		kind := fs.String("kind", "", "key kind")
		account := fs.String("account", "", "binding account public key (A…): the account a signing key signs for (D24), or a persona key's owner account (D25)")
		user := fs.String("user", "", "binding user name: a persona key's owner within --account (D25)")
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
		c, done, err := newClient(cf, *as)
		if err != nil {
			return err
		}
		defer done()
		entry, err := c.ImportKey(*name, *kind, secret, *account, *user)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "imported %s (%s) %s\n", entry.Name, entry.Kind, entry.PublicKey)
		return nil
	case "ls":
		fs := flag.NewFlagSet("key ls", flag.ContinueOnError)
		cf := addConnFlags(fs)
		as := asFlag(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		c, done, err := newClient(cf, *as)
		if err != nil {
			return err
		}
		defer done()
		keys, err := c.Keys()
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

// tagsFlag collects repeatable --tag values.
type tagsFlag []string

func (t *tagsFlag) String() string { return strings.Join(*t, ",") }

func (t *tagsFlag) Set(v string) error {
	*t = append(*t, v)
	return nil
}

func cmdMint(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("mint", flag.ContinueOnError)
	cf := addConnFlags(fs)
	as := asFlag(fs)
	account := fs.String("account", "", "target account public key (default: the principal's)")
	user := fs.String("user", "", "target user (default: the principal)")
	creds := fs.Bool("creds", false, "ALSO print a creds file — the seed leaves the vault (custody escape)")
	role := fs.String("role", "", "mint EPHEMERAL against this declared role by name (D28) — needs --user-key and --ttl")
	userKey := fs.String("user-key", "", "the caller-generated user PUBLIC key (U…) the ephemeral JWT is for")
	ttl := fs.Duration("ttl", 0, "ephemeral JWT lifetime — the revocation propagation bound (D22)")
	var tags tagsFlag
	fs.Var(&tags, "tag", "tag stamped into the ephemeral user claims (repeatable), e.g. topic:planning-x7")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, done, err := newClient(cf, *as)
	if err != nil {
		return err
	}
	defer done()
	if *role != "" {
		if *account != "" || *creds {
			return fmt.Errorf("mint --role is the ephemeral lane: no --account, and no creds escape exists (the user key is yours, not the vault's)")
		}
		_, tUser, err := parseAs(*as)
		if err != nil {
			return err
		}
		if *user != "" {
			tUser = *user
		}
		token, err := c.MintEphemeral(*role, tUser, *userKey, *ttl, tags)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\n", token)
		return nil
	}
	if *userKey != "" || *ttl != 0 || len(tags) > 0 {
		return fmt.Errorf("--user-key, --ttl and --tag belong to the ephemeral lane: name its role with --role")
	}
	tAccount, tUser, err := parseAs(*as)
	if err != nil {
		return err
	}
	if *account != "" {
		tAccount = *account
	}
	if *user != "" {
		tUser = *user
	}
	if *creds {
		res, err := c.MintCreds(tAccount, tUser)
		if err != nil {
			return err
		}
		fmt.Fprint(out, res.Creds)
		return nil
	}
	res, err := c.Mint(tAccount, tUser)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s\n", res.JWT)
	return nil
}
