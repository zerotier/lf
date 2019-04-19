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
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path"
	"sort"
	"strings"
	"syscall"

	"../../pkg/lf"
)

var (
	clientConfigFile = "client-config.json"

	lfDefaultPath = func() string {
		if os.Getuid() == 0 {
			return "/var/lib/lf"
		}
		h := os.Getenv("HOME")
		if len(h) > 0 {
			return path.Join(h, ".lf")
		}
		return "./lf"
	}()
)

func printHelp(cmd string) {
	fmt.Print(`LF Global Key/Value Store ` + lf.VersionStr + `
(c)2018-2019 ZeroTier, Inc.  https://www.zerotier.com/
MIT License

Usage: lf [-...] <command> [...]

Global options:
  -path <path>                               Override default home path
  -url <url>                                 Override configured URL(s)

Commands:
  help                                       Display help about a command
  version                                    Display version information
  selftest [test name]
    core                                     Test core systems (default)
    wharrgarbl                               Test proof of work (long!)
    database                                 Test database core
  node-start                                 Start a full node
  proxy-start                                Start a proxy
  status                                     Get status from remote node/proxy
  set [-...] <name[#ord]> [...] <value>      Set a value in the data store
    -file                                    Value is a file path, not literal
    -mask <key>                              Encrypt value using masking key
    -owner <owner>                           Use this owner instead of default
  get [-...] <name[#ord]>[,name[#ord]] [...] Get value(s) by selector or range
    -unmask <key>                            Decrypt value(s) with masking key
    -time <start>[,end]                      Get after time or in range
  owner <operation> [...]
    list                                     List owners
    new <name>                               Create a new owner
    default <name>                           Set default owner
    delete <name>                            Delete an owner (PERMANENT)
    rename <old name> <new name>             Rename an owner

Times for time range queries are in Unix time (seconds since epoch).
Default home path is ` + lfDefaultPath + ` unless -path is used.
Binary or special character selector names currently require direct API use.

`)
}

//////////////////////////////////////////////////////////////////////////////

func doNodeStart(cfg *Config, basePath string, urls []string, verboseOutput bool, args []string) {
	osSignalChannel := make(chan os.Signal, 2)
	signal.Notify(osSignalChannel, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT)
	stdoutLogger := log.New(os.Stdout, "", log.LstdFlags)
	node, err := lf.NewNode(basePath, lf.DefaultP2PPort, lf.DefaultHTTPPort, stdoutLogger, lf.LogLevelTrace)
	if err != nil {
		fmt.Printf("ERROR: unable to start node: %s\n", err.Error())
		os.Exit(-1)
		return
	}
	_ = <-osSignalChannel
	node.Stop()
}

func doProxyStart(cfg *Config, basePath string, urls []string, verboseOutput bool, args []string) {
}

func doSet(cfg *Config, owner *ConfigOwner, basePath string, urls []string, maskKey string, verboseOutput bool, args []string) {
	var err error

	if len(args) < 1 {
		printHelp("")
		return
	}
	if owner == nil {
		fmt.Printf("ERROR: no owners specified and no default owner\n")
		return
	}

	var mk lf.Blob
	if len(maskKey) > 0 {
		mk = []byte(maskKey)
	}

	var selectors []lf.APINewSelector
	for i := 0; i < len(args)-1; i++ {
		sel := args[i]
		var ord string
		ordSepIdx := strings.LastIndex(sel, "#")
		if ordSepIdx >= 0 {
			if ordSepIdx < (len(sel) - 1) {
				ord = sel[ordSepIdx+1:]
			}
			sel = sel[0:ordSepIdx]
		}
		selectors = append(selectors, lf.APINewSelector{
			Name:    []byte(sel),
			Ordinal: []byte(ord),
		})
	}

	value := []byte(args[len(args)-1])

	ts := lf.TimeSec()
	req := lf.APINew{
		Selectors:       selectors,
		MaskingKey:      mk,
		OwnerPrivateKey: owner.OwnerPrivate,
		Links:           nil,
		Value:           value,
		Timestamp:       &ts,
	}
	var rec *lf.Record
	for _, u := range urls {
		rec, err = req.Run(u)
		if err == nil {
			break
		}
	}

	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}
	fmt.Printf("%#v\n", rec)
}

func doOwner(cfg *Config, basePath string, urls []string, verboseOutput bool, args []string) {
	if len(args) == 0 {
		printHelp("")
		return
	}

	switch args[0] {

	case "list":
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
			fmt.Printf("%-24s %s %x\n", n, dfl, o.Owner)
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
		dfl := " "
		if isDfl {
			dfl = "*"
		}
		fmt.Printf("%-24s %s %x\n", name, dfl, owner.Bytes())

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
		fmt.Printf("%-24s * %x\n", name, cfg.Owners[name].Owner)

	case "delete":
		if len(args) < 2 {
			printHelp("")
			return
		}
		name := strings.TrimSpace(args[1])
		if _, have := cfg.Owners[name]; !have {
			fmt.Println("ERROR: an owner named '" + args[1] + "' does not exist.")
			return
		}
		delete(cfg.Owners, name)
		hasDfl := false
		for _, o := range cfg.Owners {
			if o.Default {
				hasDfl = true
				break
			}
		}
		if !hasDfl {
			for _, o := range cfg.Owners {
				o.Default = true
				break
			}
		}
		cfg.dirty = true
		fmt.Printf("%s deleted.\n", name)

	case "rename":
		if len(args) < 3 {
			printHelp("")
			return
		}

	default:
		printHelp("")
	}
}

func doMakeGenesis(cfg *Config, basePath string, urls []string, verboseOutput bool, args []string) {
	var nwKey [32]byte
	secrand.Read(nwKey[:])
	g := lf.GenesisParameters{
		Name:                      "Sol",
		Comment:                   "Global Public LF Data Store",
		CertificateRequired:       false,
		WorkRequired:              true,
		LinkKey:                   nwKey,
		TimestampFloor:            lf.TimeSec(),
		RecordMinLinks:            3,
		RecordMaxValueSize:        4096,
		RecordMaxSize:             lf.RecordMaxSize,
		RecordMaxForwardTimeDrift: 15,
	}

	fmt.Printf("Genesis parameters:\n%s\nCreating %d genesis records...\n", lf.PrettyJSON(&g), g.RecordMinLinks)

	genesisRecords, genesisOwner, err := lf.CreateGenesisRecords(lf.OwnerTypeEd25519, &g)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		os.Exit(-1)
		return
	}

	var grData bytes.Buffer
	for i := 0; i < len(genesisRecords); i++ {
		fmt.Printf("%s\n", lf.PrettyJSON(genesisRecords[i]))
		err = genesisRecords[i].MarshalTo(&grData)
		if err != nil {
			fmt.Printf("ERROR: %s\n", err.Error())
			os.Exit(-1)
			return
		}
	}

	ioutil.WriteFile("genesis.lf", grData.Bytes(), 0644)
	ioutil.WriteFile("genesis.go", []byte(fmt.Sprintf("/*\n%s\n*/\n%#v", lf.PrettyJSON(g), grData.Bytes())), 0644)
	if len(g.AmendableFields) > 0 {
		ioutil.WriteFile("genesis.secret", genesisOwner.PrivateBytes(), 0600)
	}

	fmt.Printf("\nWrote genesis.lf, genesis.go, and genesis.secret (if amendable) to current directory.\n")
}

func main() {
	globalOpts := flag.NewFlagSet("global", flag.ContinueOnError)
	basePath := globalOpts.String("path", lfDefaultPath, "")
	urlOverride := globalOpts.String("url", "", "")
	ownerOverride := globalOpts.String("owner", "", "")
	maskKey := globalOpts.String("mask", "", "")
	verboseOutput := globalOpts.Bool("verbose", false, "")
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

	var owner *ConfigOwner
	if len(*ownerOverride) > 0 {
		owner = cfg.Owners[*ownerOverride]
		if owner == nil {
			fmt.Printf("ERROR: owner '%s' not found\n", *ownerOverride)
			os.Exit(-1)
			return
		}
	}
	for _, o := range cfg.Owners {
		if o.Default {
			owner = o
			break
		}
	}

	var urls []string
	if len(*urlOverride) > 0 {
		urls = append(urls, *urlOverride)
	} else {
		urls = cfg.Urls
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
			test = "core"
		}
		switch test {
		case "all":
			lf.TestCore(os.Stdout)
			fmt.Println()
			lf.TestDatabase("./lf-db-test", os.Stdout)
			fmt.Println()
			//lf.TestWharrgarbl(os.Stdout)
			//fmt.Println()
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
		doNodeStart(&cfg, *basePath, urls, *verboseOutput, cmdArgs)

	case "proxy-start":
		doProxyStart(&cfg, *basePath, urls, *verboseOutput, cmdArgs)

	case "set":
		doSet(&cfg, owner, *basePath, urls, *maskKey, *verboseOutput, cmdArgs)

	case "owner":
		doOwner(&cfg, *basePath, urls, *verboseOutput, cmdArgs)

	case "_makegenesis":
		doMakeGenesis(&cfg, *basePath, urls, *verboseOutput, cmdArgs)

	default:
		printHelp("")

	}

	if cfg.dirty {
		err = cfg.save(cfgPath)
		if err != nil {
			fmt.Printf("ERROR: cannot write %s: %s\n", cfgPath, err.Error())
			os.Exit(-1)
			return
		}
	}

	os.Exit(0)
}
