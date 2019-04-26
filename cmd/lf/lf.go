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
	"strconv"
	"strings"
	"syscall"
	"time"

	"../../pkg/lf"
)

var (
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

func parseCLITime(t string) uint64 {
	if len(t) > 0 {
		timeInt, err := strconv.ParseUint(t, 10, 64)
		if timeInt > 0 && err == nil {
			return timeInt
		}
		tp, err := time.Parse(time.RFC1123, t)
		if err == nil {
			return uint64(tp.Unix())
		}
	}
	return 0
}

func tokenizeStringWithEsc(s string, sep, escape rune) (tokens []string) {
	var runes []rune
	inEscape := false
	for _, r := range s {
		switch {
		case inEscape:
			inEscape = false
			fallthrough
		default:
			runes = append(runes, r)
		case r == escape:
			inEscape = true
		case r == sep:
			tokens = append(tokens, string(runes))
			runes = runes[:0]
		}
	}
	tokens = append(tokens, string(runes))
	return
}

func printHelp(cmd string) {
	fmt.Print(`LF Global Key/Value Store ` + lf.VersionStr + `
(c)2018-2019 ZeroTier, Inc.  https://www.zerotier.com/
MIT License

Usage: lf [-...] <command> [...]

Global options:
  -path <path>                            Override default home path
  -url <url>                              Override configured URL(s)

Commands:
  help                                    Display help about a command
  version                                 Display version information
  selftest [test name]
    core                                  Test core systems (default)
    wharrgarbl                            Test proof of work (long!)
    database                              Test database core
  node-start                              Start a full node
  proxy-start                             Start a proxy
  status                                  Get status from remote node/proxy
  set [-...] <name[#ord]> [...] <value>   Set a value in the data store
    -file                                 Value is a file path not a literal
    -mask <key>                           Encrypt value using masking key
    -owner <owner>                        Use this owner instead of default
    -remote                               Remote encrypt/PoW (reveals keys)
    -tryremote                            Try remote encrypt/PoW first
  get [-...] <name[#start[#end]]> [...]   Find by selector (optional range)
    -unmask <key>                         Decrypt value(s) with masking key
    -tstart <time>                        Constrain to after this time
    -tend <time>                          Constrain to before this time
  owner <operation> [...]
    list                                  List owners
    new <name>                            Create a new owner
    default <name>                        Set default owner
    delete <name>                         Delete an owner (PERMANENT)
    rename <old name> <new name>          Rename an owner

Time can be specified in either RFC1123 format or as numeric Unix time.
RFC1123 format looks like "Mon Jan 2 15:04:05 PST 2018".

Default home path is ` + lfDefaultPath + ` unless -path is used.

`)
}

func doNodeStart(cfg *lf.ClientConfig, basePath string, urls []string, args []string) {
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

func doProxyStart(cfg *lf.ClientConfig, basePath string, urls []string, args []string) {
}

func doStatus(cfg *lf.ClientConfig, basePath string, urls []string, args []string) {
	if len(args) != 0 {
		printHelp("")
		return
	}
	var stat *lf.APIStatusResult
	var err error
	for _, u := range urls {
		stat, err = lf.APIStatusGet(u)
		if err == nil {
			break
		}
	}
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		return
	}
	fmt.Println(lf.PrettyJSON(stat))
}

func doGet(cfg *lf.ClientConfig, basePath string, urls []string, args []string) {
	getOpts := flag.NewFlagSet("get", flag.ContinueOnError)
	unmaskKey := getOpts.String("unmask", "", "")
	tStart := getOpts.String("tstart", "", "")
	tEnd := getOpts.String("tend", "", "")
	err := getOpts.Parse(args)
	if err != nil {
		printHelp("")
		return
	}
	args = getOpts.Args()
	if len(args) < 1 {
		printHelp("")
		return
	}

	var mk []byte
	if len(*unmaskKey) > 0 {
		mk = []byte(*unmaskKey)
	}

	tr := []uint64{0, 9223372036854775807}
	if len(*tStart) > 0 {
		tr[0] = parseCLITime(*tStart)
	}
	if len(*tEnd) > 0 {
		tr[1] = parseCLITime(*tEnd)
	}

	var ranges []lf.APIQueryRange
	for i := 0; i < len(args); i++ {
		tord := tokenizeStringWithEsc(args[i], '#', '\\')
		if len(tord) == 1 {
			ranges = append(ranges, lf.APIQueryRange{KeyRange: []lf.Blob{lf.MakeSelectorKey([]byte(tord[0]), nil)}})
		} else if len(tord) == 2 {
			ranges = append(ranges, lf.APIQueryRange{KeyRange: []lf.Blob{lf.MakeSelectorKey([]byte(tord[0]), []byte(tord[1]))}})
		} else if len(tord) == 3 {
			ranges = append(ranges, lf.APIQueryRange{KeyRange: []lf.Blob{
				lf.MakeSelectorKey([]byte(tord[0]), []byte(tord[1])),
				lf.MakeSelectorKey([]byte(tord[0]), []byte(tord[2])),
			}})
		} else {
			fmt.Printf("ERROR: selector or selector ordinal range invalid")
			return
		}
	}

	req := &lf.APIQuery{
		Range:      ranges,
		TimeRange:  tr,
		MaskingKey: mk,
	}

	var res lf.APIQueryResults
	for _, u := range urls {
		res, err = req.Run(u)
		if err == nil {
			break
		}
	}

	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		return
	}
	fmt.Println(lf.PrettyJSON(res))
}

func doSet(cfg *lf.ClientConfig, basePath string, urls []string, args []string) {
	setOpts := flag.NewFlagSet("set", flag.ContinueOnError)
	ownerName := setOpts.String("owner", "", "")
	maskKey := setOpts.String("mask", "", "")
	valueIsFile := setOpts.Bool("file", false, "")
	remote := setOpts.Bool("remote", false, "")
	tryRemote := setOpts.Bool("tryremote", false, "")
	err := setOpts.Parse(args)
	if err != nil {
		printHelp("")
		return
	}
	args = setOpts.Args()
	if len(args) < 2 { // must have at least one selector and a value
		printHelp("")
		return
	}

	var owner *lf.ClientConfigOwner
	if len(*ownerName) > 0 {
		owner = cfg.Owners[*ownerName]
		if owner == nil {
			fmt.Printf("ERROR: owner '%s' not found\n", *ownerName)
			return
		}
	}
	for _, o := range cfg.Owners {
		if o.Default {
			owner = o
			break
		}
	}
	if owner == nil {
		fmt.Printf("ERROR: owner not found and no default specified\n")
		return
	}

	var mk []byte
	if len(*maskKey) > 0 {
		mk = []byte(*maskKey)
	}

	var plainTextSelectorNames, selectorOrdinals [][]byte
	var selectors []lf.APINewSelector
	for i := 0; i < len(args)-1; i++ {
		selOrd := tokenizeStringWithEsc(args[i], '#', '\\')
		if len(selOrd) > 0 {
			sel := []byte(selOrd[0])
			var ord []byte
			if len(selOrd) == 2 {
				ord = []byte(selOrd[1])
			}
			plainTextSelectorNames = append(plainTextSelectorNames, sel)
			selectorOrdinals = append(selectorOrdinals, ord)
			selectors = append(selectors, lf.APINewSelector{
				Name:    sel,
				Ordinal: ord,
			})
		}
	}

	value := []byte(args[len(args)-1])
	if *valueIsFile {
		vdata, err := ioutil.ReadFile(string(value))
		if err != nil {
			fmt.Println("ERROR: file '" + err.Error() + "' not found")
			return
		}
		value = vdata
	}

	var links [][32]byte
	var rec *lf.Record
	ts := lf.TimeSec()

	// Get links for record
	for _, u := range urls {
		links, err = lf.APIGetLinks(u, 0)
		if err == nil {
			break
		}
	}
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		return
	}

	// If remote delegated record creation is preferred, try that first.
	var lazies []string
	if *remote || *tryRemote {
		req := lf.APINew{
			Selectors:       selectors,
			MaskingKey:      mk,
			OwnerPrivateKey: owner.OwnerPrivate,
			Links:           links,
			Value:           value,
			Timestamp:       &ts,
		}
		for _, u := range urls {
			rec, err = req.Run(u)
			if err == nil {
				lazies = nil
				break
			}
			apiErr, isAPIErr := err.(lf.APIError)
			if isAPIErr && apiErr.Code == lf.APIErrorLazy {
				lazies = append(lazies, u)
			}
		}
	} else {
		lazies = urls
	}

	// If not delegating or trial remote delgation failed, make record locally.
	if len(lazies) > 0 && !*remote {
		var o *lf.Owner
		o, err = owner.GetOwner()
		if err == nil {
			rec, err = lf.NewRecord(value, links, mk, plainTextSelectorNames, selectorOrdinals, nil, ts, lf.NewWharrgarblr(lf.RecordDefaultWharrgarblMemory, 0), 0, o)
			if err == nil {
				rb := rec.Bytes()
				for _, u := range lazies {
					err = lf.APIPostRecord(u, rb)
					if err == nil {
						break
					}
				}
			}
		}
	}

	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		return
	}
	fmt.Println(lf.PrettyJSON(rec))
}

func doOwner(cfg *lf.ClientConfig, basePath string, urls []string, args []string) {
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
		cfg.Owners[name] = &lf.ClientConfigOwner{
			Owner:        owner.Bytes(),
			OwnerPrivate: owner.PrivateBytes(),
			Default:      isDfl,
		}
		cfg.Dirty = true
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
		cfg.Dirty = true
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
		cfg.Dirty = true
		fmt.Printf("%-24s deleted\n", name)

	case "rename":
		if len(args) < 3 {
			printHelp("")
			return
		}

	default:
		printHelp("")
	}
}

func doMakeGenesis(cfg *lf.ClientConfig, basePath string, urls []string, args []string) {
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
		RecordMaxValueSize:        1024,
		RecordMaxSize:             lf.RecordMaxSize,
		RecordMaxForwardTimeDrift: 15,
	}

	fmt.Printf("Genesis parameters:\n%s\nCreating %d genesis records...\n", lf.PrettyJSON(&g), g.RecordMinLinks)

	genesisRecords, genesisOwner, err := lf.CreateGenesisRecords(lf.OwnerTypeNistP384, &g)
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

	cfgPath := path.Join(*basePath, lf.ClientConfigName)
	var cfg lf.ClientConfig
	err = cfg.Load(cfgPath)
	if err != nil {
		fmt.Printf("ERROR: cannot read or parse %s: %s\n", cfgPath, err.Error())
		os.Exit(-1)
		return
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
		doNodeStart(&cfg, *basePath, urls, cmdArgs)

	case "proxy-start":
		doProxyStart(&cfg, *basePath, urls, cmdArgs)

	case "status":
		doStatus(&cfg, *basePath, urls, cmdArgs)

	case "set":
		doSet(&cfg, *basePath, urls, cmdArgs)

	case "get":
		doGet(&cfg, *basePath, urls, cmdArgs)

	case "owner":
		doOwner(&cfg, *basePath, urls, cmdArgs)

	case "_makegenesis":
		doMakeGenesis(&cfg, *basePath, urls, cmdArgs)

	default:
		printHelp("")

	}

	if cfg.Dirty {
		err = cfg.Save(cfgPath)
		if err != nil {
			fmt.Printf("ERROR: cannot write %s: %s\n", cfgPath, err.Error())
			os.Exit(-1)
			return
		}
	}

	os.Exit(0)
}
