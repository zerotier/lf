/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package main

import (
	"bytes"
	secrand "crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"sort"
	"strings"

	"../../pkg/lf"
)

var clientConfigFile = "client.json"

var defaultNodeUrls = []string{}

var lfDefaultPath = func() string {
	if os.Getuid() == 0 {
		return "/var/lib/lf"
	}
	h := os.Getenv("HOME")
	if len(h) > 0 {
		return path.Join(h, ".lf")
	}
	return "./lf"
}()

// ConfigOwner contains info about an owner.
type ConfigOwner struct {
	Owner        []byte
	OwnerPrivate []byte
	Default      bool
}

// Config is the format of the JSON client configuration stored on disk
type Config struct {
	Urls   []string                // URLs of full nodes and/or proxies
	Owners map[string]*ConfigOwner // Owners by name

	dirty bool // internal flag that causes client config to get written
}

func (c *Config) load(path string) error {
	d, err := ioutil.ReadFile(path)
	if err == nil && len(d) > 0 {
		err = json.Unmarshal(d, c)
	}
	if c.Owners == nil {
		c.Owners = make(map[string]*ConfigOwner)
	}
	c.dirty = false

	// If the file didn't exist, init config with defaults.
	if err != nil && os.IsNotExist(err) {
		c.Urls = defaultNodeUrls
		owner, _ := lf.NewOwner(lf.OwnerTypeEd25519)
		dflName := "default"
		u, _ := user.Current()
		if u != nil && len(u.Username) > 0 {
			dflName = u.Username
		}
		c.Owners[dflName] = &ConfigOwner{
			Owner:        owner.Bytes(),
			OwnerPrivate: owner.PrivateBytes(),
			Default:      true,
		}
		c.dirty = true
		err = nil
	}

	return err
}

func (c *Config) save(path string) error {
	// Make sure there is one and only one default owner.
	if len(c.Owners) > 0 {
		haveDfl := false
		var names []string
		for n, o := range c.Owners {
			names = append(names, n)
			if haveDfl {
				if o.Default {
					o.Default = false
				}
			} else if o.Default {
				haveDfl = true
			}
		}
		if !haveDfl {
			sort.Strings(names)
			c.Owners[names[0]].Default = true
		}
	}

	d, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path, d, 0600) // 0600 since this file contains secrets
	if err == nil {
		c.dirty = false
		return nil
	}
	return err
}

func jsonP(obj interface{}) {
	jb, _ := json.MarshalIndent(obj, "", "  ")
	if len(jb) > 0 {
		os.Stdout.Write(jb)
		os.Stdout.Write([]byte{'\n'})
	}
}

//////////////////////////////////////////////////////////////////////////////

func printHelpHdr() {
	fmt.Print(`LF Global Key/Value Store ` + lf.VersionStr + `
(c)2018 ZeroTier, Inc.  https://www.zerotier.com/
MIT License

Usage: lf [-global options] <command> [-command options] [...]

Global options:
  -path <path>                             Override default home directory
  -use <url>                               Override default node/proxy URL(s)
  -verbose                                 Generate verbose output to stderr
  -json                                    Output raw JSON for API queries
`)
}

func printHelp(cmd string) {
	printHelpHdr()

	if len(cmd) > 0 {
		switch cmd {

		default:
			fmt.Printf("\nThe '%s' command has no additional help.\n", cmd)

		case "selftest":
			fmt.Print(`
The 'selftest' command can run the following tests:
  core                                     Test core functions and data types
  wharrgarbl                               Test and benchmark work function
  database                                 Test database and graph algorithms

Use 'all' to run all tests.
`)

		}
		return
	}

	fmt.Print(`
Commands:
  help                                     Display help about a command
  version                                  Display version information
  selftest [<test>]                        Show tests or run an internal test
  node-start                               Start a full node
  proxy-start                              Start a local record creation proxy
  use <url>                                Add a node URL for client/proxy
  drop <url>                               Remove a node URL for client/proxy
  set [options] [<key> ...] <value>        Set a new entry
      [-owner <owner>]                     - Use this specific owner
      [-file]                              - Value is a file, not a literal
  owner <operation> [...]                  Owner management commands
        list                               - List owners
        new <name>                         - Create a new owner
        default <name>                     - Set default owner
        delete <name>                      - Delete an owner (PERMANENT)
        rename <old name> <new name>       - Rename an owner

Configuration and other data is stored in LF's home directory. The default
location for the current user on this system is:

  ` + lfDefaultPath + `

This can be overridden if the -path option is used before the command. This
directory will be created and initialized the first time LF is used if it does
not already exist.
`)
}

//////////////////////////////////////////////////////////////////////////////

func doNodeStart(cfg *Config, basePath string, jsonOutput bool, urlOverride string, verboseOutput bool, args []string) {
}

func doProxyStart(cfg *Config, basePath string, jsonOutput bool, urlOverride string, verboseOutput bool, args []string) {
}

func doUse(cfg *Config, basePath string, jsonOutput bool, urlOverride string, verboseOutput bool, args []string) {
}

func doDrop(cfg *Config, basePath string, jsonOutput bool, urlOverride string, verboseOutput bool, args []string) {
}

func doSet(cfg *Config, basePath string, jsonOutput bool, urlOverride string, verboseOutput bool, args []string) {
}

func doOwner(cfg *Config, basePath string, jsonOutput bool, urlOverride string, verboseOutput bool, args []string) {
	if len(args) == 0 {
		printHelp("")
		return
	}

	switch args[0] {

	case "list":
		if jsonOutput {
			jsonP(&cfg.Owners)
		} else {
			var names []string
			for n := range cfg.Owners {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				o := cfg.Owners[n]
				dfl := " "
				if o.Default {
					dfl = "*"
				}
				fmt.Printf("%-24s %s %s\n", n, dfl, o.Owner)
			}
		}

	case "new":
		if len(args) < 2 {
			printHelp("")
			return
		}
		name := strings.TrimSpace(args[1])
		if _, have := cfg.Owners[name]; have {
			fmt.Println("ERROR: an owner named '" + args[1] + "' already exists.")
			return
		}
		owner, _ := lf.NewOwner(lf.OwnerTypeEd25519)
		isDfl := len(cfg.Owners) == 0
		cfg.Owners[name] = &ConfigOwner{
			Owner:        owner.Bytes(),
			OwnerPrivate: owner.PrivateBytes(),
			Default:      isDfl,
		}
		cfg.dirty = true
		fmt.Printf("%-24s %s\n", name, owner.Bytes())

	case "default":
		if len(args) < 2 {
			printHelp("")
			return
		}
		name := strings.TrimSpace(args[1])
		if _, have := cfg.Owners[name]; !have {
			fmt.Println("ERROR: an owner named '" + args[1] + "' does not exist.")
			return
		}
		for n, o := range cfg.Owners {
			o.Default = (n == name)
		}
		cfg.dirty = true
		fmt.Printf("%-24s %s\n", name, cfg.Owners[name].Owner)

	case "delete":
		if len(args) < 2 {
			printHelp("")
			return
		}

	case "rename":
		if len(args) < 3 {
			printHelp("")
			return
		}

	default:
		printHelp("")
	}
}

func doMakeGenesis(cfg *Config, basePath string, jsonOutput bool, urlOverride string, verboseOutput bool, args []string) {
	var nwKey [32]byte
	secrand.Read(nwKey[:])
	g := lf.Genesis{
		Name:                 "Sol",
		Contact:              "",
		Comment:              "",
		CAs:                  nil,
		BannedWorkAlgorithms: []uint{uint(lf.RecordWorkAlgorithmNone)},
		Key:                  nwKey[:],
		TimestampFloor:       lf.TimeSec(),
		RecordMinLinks:       3,
		RecordMaxValueSize:   1024,
		RecordMaxSize:        lf.RecordMaxSize,
		SettingsAmendable:    false,
		CAsAmendable:         false,
	}

	gJSON, _ := json.MarshalIndent(g, "", "  ")
	fmt.Printf("Genesis parameters:\n\n%s\n\nCreating %d genesis records...\n", gJSON, g.RecordMinLinks)

	genesisRecords, genesisOwner, err := lf.CreateGenesisRecords(lf.OwnerTypeEd25519, &g)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		os.Exit(-1)
		return
	}

	var grData bytes.Buffer
	for i := 0; i < len(genesisRecords); i++ {
		rJSON, _ := json.MarshalIndent(genesisRecords[i], "", "  ")
		fmt.Printf("%s\n", rJSON)
		err = genesisRecords[i].MarshalTo(&grData)
		if err != nil {
			fmt.Printf("ERROR: %s\n", err.Error())
			os.Exit(-1)
			return
		}
	}

	ioutil.WriteFile("genesis.lf", grData.Bytes(), 0644)
	ioutil.WriteFile("genesis.go", []byte(fmt.Sprintf("/*\n%s\n*/\n%#v", gJSON, grData.Bytes())), 0644)
	if g.SettingsAmendable || g.CAsAmendable {
		ioutil.WriteFile("genesis.secret", genesisOwner.PrivateBytes(), 0600)
	}

	fmt.Printf("\nWrote genesis.lf, genesis.go, and genesis.secret (if amendable) to current directory.\n")
}

//////////////////////////////////////////////////////////////////////////////

func main() {
	globalOpts := flag.NewFlagSet("global", flag.ContinueOnError)
	basePath := globalOpts.String("path", lfDefaultPath, "")
	urlOverride := globalOpts.String("url", "", "")
	verboseOutput := globalOpts.Bool("verbose", false, "")
	jsonOutput := globalOpts.Bool("json", false, "")
	err := globalOpts.Parse(os.Args)
	if err != nil {
		printHelp("")
		return
	}
	args := globalOpts.Args()
	if len(args) <= 1 {
		printHelp("")
		return
	}
	var cmdArgs []string
	if len(args) >= 3 {
		cmdArgs = args[2:]
	}

	os.MkdirAll(*basePath, 0755)

	cfgPath := path.Join(*basePath, clientConfigFile)
	var cfg Config
	err = cfg.load(cfgPath)
	if err != nil {
		fmt.Printf("ERROR: cannot read or parse %s: %s\n", cfgPath, err.Error())
		os.Exit(-1)
		return
	}

	switch args[1] {

	case "help":
		if len(args) >= 3 {
			printHelp(args[2])
		} else {
			printHelp("")
		}

	case "version":
		fmt.Println(lf.VersionStr)

	case "selftest":
		test := ""
		if len(cmdArgs) == 1 {
			test = cmdArgs[0]
		} else {
			printHelp("selftest")
		}
		switch test {
		case "all":
			lf.TestCore(os.Stdout)
			fmt.Println()
			lf.TestDatabase("./lf-db-test", os.Stdout)
			fmt.Println()
			lf.TestWharrgarbl(os.Stdout)
			fmt.Println()
		case "core":
			lf.TestCore(os.Stdout)
		case "wharrgarbl":
			lf.TestWharrgarbl(os.Stdout)
		case "database":
			lf.TestDatabase("./lf-db-test", os.Stdout)
		default:
			printHelp("")
		}

	case "node-start":
		doNodeStart(&cfg, *basePath, *jsonOutput, *urlOverride, *verboseOutput, cmdArgs)

	case "proxy-start":
		doProxyStart(&cfg, *basePath, *jsonOutput, *urlOverride, *verboseOutput, cmdArgs)

	case "use":
		doUse(&cfg, *basePath, *jsonOutput, *urlOverride, *verboseOutput, cmdArgs)

	case "drop":
		doDrop(&cfg, *basePath, *jsonOutput, *urlOverride, *verboseOutput, cmdArgs)

	case "set":
		doSet(&cfg, *basePath, *jsonOutput, *urlOverride, *verboseOutput, cmdArgs)

	case "owner":
		doOwner(&cfg, *basePath, *jsonOutput, *urlOverride, *verboseOutput, cmdArgs)

	case "makegenesis":
		doMakeGenesis(&cfg, *basePath, *jsonOutput, *urlOverride, *verboseOutput, cmdArgs)

	default:
		printHelp("")

	}
}
