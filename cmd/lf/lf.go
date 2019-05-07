/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"../../pkg/lf"
)

//#if defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
//static inline int fork() { return -1; }
//#else
//#include <stdlib.h>
//#include <unistd.h>
//#endif
import "C"

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

	troo = true

	lfDefaultP2PPortStr  = strconv.FormatUint(uint64(lf.DefaultP2PPort), 10)
	lfDefaultHTTPPortStr = strconv.FormatUint(uint64(lf.DefaultHTTPPort), 10)

	logger = log.New(os.Stderr, "", 0)
)

func parseCLITime(t string) uint64 {
	if len(t) > 0 {
		looksLikeNumber := true
		for _, c := range t {
			if c < 48 || c > 57 {
				looksLikeNumber = false
				break
			}
		}
		if looksLikeNumber {
			timeInt, err := strconv.ParseUint(t, 10, 64)
			if timeInt > 0 && err == nil {
				return timeInt
			}
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

func escapeOrdinal(ord []byte) string {
	if len(ord) == 0 {
		return ""
	}
	jstr, _ := json.Marshal(string(ord))
	if len(jstr) < 2 {
		return ""
	}
	var sb strings.Builder
	for _, c := range string(jstr[1 : len(jstr)-1]) {
		if c == '#' || c == '\\' {
			sb.WriteRune('\\')
		}
		sb.WriteRune(c)
	}
	return sb.String()
}

func stickAForkInIt() {
	if strings.HasPrefix(runtime.GOOS, "windows") {
		log.Printf("FATAL: fork not supported on Windows")
		os.Exit(-1)
	}
	fr := int(C.fork())
	if fr < 0 {
		log.Printf("FATAL: fork into background failed")
		os.Exit(-1)
	} else if fr > 0 {
		os.Exit(0)
	}
}

func printHelp(cmd string) {
	// NOTE: When editing make sure your editor doesn't indent help with
	// tabs, otherwise it will format funny on a console. Also try to keep
	// this 80 column just for legacy/standard reasons.
	fmt.Print(`LF Global Key/Value Store ` + lf.VersionStr + `
(c)2018-2019 ZeroTier, Inc.  https://www.zerotier.com/
MIT License

Usage: lf [-...] <command> [...]

Global options:
  -path <path>                            Override default home path
  -json                                   Raw JSON output where applicable

Commands:
  help                                    Show this
  version                                 Display version information
  selftest [test name]
    core                                  Test core systems (default)
    wharrgarbl                            Test proof of work (long!)
    database                              Test DAG and database (long!)
  node-start [-...]                       Start a full LF node
    -p2p <port>                           P2P TCP port (default: ` + lfDefaultP2PPortStr + `)
    -http <port>                          HTTP TCP port (default: ` + lfDefaultHTTPPortStr + `)
    -commentary                           Use spare CPU to publish commentary
    -loglevel <normal|verbose|trace>      Node log level
    -logstderr                            Log to stderr, not HOME/node.log
    -fork                                 Fork into background (if supported)
  node-connect <ip> <port> [<key>]        Tell node to try a P2P endpoint
  proxy-start                             Start a proxy
  status                                  Get status from remote node/proxy
  set [-...] <name[#ord]> [...] <value>   Set a value in the data store
    -file                                 Value is a file path not a literal
    -mask <key>                           Encrypt value using masking key
    -owner <owner>                        Use this owner instead of default
    -url <url[,url,...]>                  Override configured node/proxy URLs
    -remote                               Remote encrypt/PoW (shares mask key)
    -tryremote                            Try remote encrypt/PoW, then local
  get [-...] <name[#start[#end]]> [...]   Find by selector (optional range)
    -mask <key>                           Decrypt value(s) with masking key
    -url <url[,url,...]>                  Override configured node/proxy URLs
    -tstart <time>                        Constrain to after this time
    -tend <time>                          Constrain to before this time
  owner <operation> [...]
    list                                  List owners
    new <name>                            Create a new owner
    default <name>                        Set default owner
    delete <name>                         Delete an owner (PERMANENT)
    rename <old name> <new name>          Rename an owner

Global options must precede commands, while command options must come after
the command name.

Selector names and ordinals are decoded using the same string escaping rules
as JSON strings (without the enclosing quotes). In addition a # sign can be
included in a selector name or ordinal by double-escaping it: '\\#'. The
double backslash is required to first escape the backslash for the JSON string
format decoder. Note that in shells something like '\\\\#' may be needed.

Time can be specified in either RFC1123 format or as numeric Unix time.
RFC1123 format looks like "` + time.Now().Format(time.RFC1123) + `" while
Unix time is a decimal number indicating seconds since the Unix epoch.

Default home path is ` + lfDefaultPath + ` unless overriden with -path.

`)
}

func doNodeStart(cfg *lf.ClientConfig, basePath string, args []string) {
	var logFile *os.File
	defer func() {
		e := recover()
		if e != nil {
			log.Printf("FATAL: caught unexpected panic in doNodeStart(): %s", e)
		}
		if logFile != nil {
			logFile.Close()
		}
	}()

	nodeOpts := flag.NewFlagSet("node-start", flag.ContinueOnError)
	p2pPort := nodeOpts.Int("p2p", lf.DefaultP2PPort, "")
	httpPort := nodeOpts.Int("http", lf.DefaultHTTPPort, "")
	commentary := nodeOpts.Bool("commentary", false, "")
	logLevel := nodeOpts.String("loglevel", "verbose", "")
	logToStderr := nodeOpts.Bool("logstderr", false, "")
	forkToBackground := nodeOpts.Bool("fork", false, "")
	nodeOpts.SetOutput(ioutil.Discard)
	err := nodeOpts.Parse(args)
	if err != nil {
		printHelp("")
		return
	}
	args = nodeOpts.Args()
	if len(args) != 0 {
		printHelp("")
		return
	}

	ll := lf.LogLevelVerbose
	switch *logLevel {
	case "normal":
		ll = lf.LogLevelNormal
	case "verbose":
		ll = lf.LogLevelVerbose
	case "trace":
		ll = lf.LogLevelTrace
	default:
		printHelp("")
		return
	}

	if *logToStderr {
		logger = log.New(os.Stderr, "", log.LstdFlags)
	} else {
		logFile, err = os.OpenFile(path.Join(basePath, "node.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("FATAL: cannot open node.log: %s\n", err.Error())
			return
		}
		logger = log.New(logFile, "", log.LstdFlags)
	}

	// This must happen before gorountines are launched. It's only supported on *nix platforms.
	if *forkToBackground {
		stickAForkInIt()
	}

	osSignalChannel := make(chan os.Signal, 2)
	signal.Notify(osSignalChannel, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGBUS)
	signal.Ignore(syscall.SIGUSR1, syscall.SIGUSR2)

	node, err := lf.NewNode(basePath, *p2pPort, *httpPort, logger, ll)
	if err != nil {
		log.Printf("FATAL: unable to start node: %s\n", err.Error())
		return
	}
	node.SetCommentaryEnabled(*commentary)

	sig := <-osSignalChannel
	if sig == syscall.SIGBUS {
		// SIGBUS can happen if mmap'd I/O fails, such as if we are running over a network
		// drive (not recommended for this reason) or a path is forcibly unmounted. The mmap
		// code is in C but this should in theory get caught here.
		log.Println("FATAL: received SIGBUS, shutting down (likely I/O problem, database may be corrupt!)")
	}
	node.Stop()
}

func doNodeConnect(cfg *lf.ClientConfig, basePath string, args []string) {
	if len(args) != 3 {
		printHelp("")
		return
	}
	ip := net.ParseIP(args[0])
	if !ip.IsGlobalUnicast() && !ip.IsLoopback() {
		printHelp("")
		return
	}
	port, err := strconv.ParseUint(args[1], 10, 64)
	if port == 0 || port > 65535 || err != nil {
		printHelp("")
		return
	}
	urls := cfg.Urls
	for _, u := range urls {
		err = lf.APIPostConnect(u, ip, int(port), args[2])
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Printf("ERROR: cannot send connect command to node: %s\n", err.Error())
		return
	}
}

func doProxyStart(cfg *lf.ClientConfig, basePath string, args []string) {
	log.Printf("ERROR: not implemented yet!")
	return
}

func doStatus(cfg *lf.ClientConfig, basePath string, args []string) {
	if len(args) != 0 {
		printHelp("")
		return
	}
	var stat *lf.APIStatusResult
	var err error
	urls := cfg.Urls
	for _, u := range urls {
		stat, err = lf.APIStatusGet(u)
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Printf("ERROR: status query failed: %s\n", err.Error())
		return
	}
	fmt.Println(lf.PrettyJSON(stat))
}

func doGet(cfg *lf.ClientConfig, basePath string, args []string, jsonOutput bool) {
	getOpts := flag.NewFlagSet("get", flag.ContinueOnError)
	maskKey := getOpts.String("mask", "", "")
	tStart := getOpts.String("tstart", "", "")
	tEnd := getOpts.String("tend", "", "")
	urlOverride := getOpts.String("url", "", "")
	getOpts.SetOutput(ioutil.Discard)
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
	if len(*maskKey) > 0 {
		mk = []byte(*maskKey)
	}

	urls := cfg.Urls
	if len(*urlOverride) > 0 {
		urls = tokenizeStringWithEsc(*urlOverride, ',', '\\')
	}
	if len(urls) == 0 {
		log.Println("ERROR: get query failed: no URLs configured!")
		return
	}

	tr := []uint64{0, 9223372036854775807}
	if len(*tStart) > 0 {
		tr[0] = parseCLITime(*tStart)
	}
	if len(*tEnd) > 0 {
		tr[1] = parseCLITime(*tEnd)
	}

	var ranges []lf.APIQueryRange
	var selectorNames []string
	for i := 0; i < len(args); i++ {
		var unesc string
		json.Unmarshal([]byte("\""+args[i]+"\""), &unesc) // use JSON string escaping for selector arguments
		if len(unesc) > 0 {
			tord := tokenizeStringWithEsc(unesc, '#', '\\')
			if len(tord) == 1 {
				ranges = append(ranges, lf.APIQueryRange{KeyRange: [][]byte{lf.MakeSelectorKey([]byte(tord[0]), nil)}})
			} else if len(tord) == 2 {
				ranges = append(ranges, lf.APIQueryRange{KeyRange: [][]byte{lf.MakeSelectorKey([]byte(tord[0]), []byte(tord[1]))}})
			} else if len(tord) == 3 {
				ranges = append(ranges, lf.APIQueryRange{KeyRange: [][]byte{
					lf.MakeSelectorKey([]byte(tord[0]), []byte(tord[1])),
					lf.MakeSelectorKey([]byte(tord[0]), []byte(tord[2])),
				}})
			} else {
				fmt.Printf("ERROR: get query failed: selector or selector ordinal range invalid")
				return
			}
			selectorNames = append(selectorNames, tord[0])
		}
	}

	req := &lf.APIQuery{
		Range:     ranges,
		TimeRange: tr,
	}
	if !jsonOutput {
		req.Limit = 1
	}

	var results lf.APIQueryResults
	for _, u := range urls {
		results, err = req.Run(u)
		if err == nil {
			break
		}
	}

	if err != nil {
		log.Printf("ERROR: get query failed: %s\n", err.Error())
		return
	}

	for _, ress := range results {
		for _, res := range ress {
			res.Value, err = res.Record.GetValue(mk)
			if err != nil {
				res.Value = nil
				res.UnmaskingFailed = &troo
			}
		}
	}

	if jsonOutput {
		if len(results) > 0 {
			fmt.Println(lf.PrettyJSON(results))
		} else {
			fmt.Println("[]")
		}
	} else {
		for _, ress := range results {
			if len(ress) > 0 {
				res := &ress[0]
				if len(res.Value) > 0 {
					jstr, _ := json.Marshal(string(res.Value)) // use JSON's string escaping
					fmt.Print(string(jstr[1 : len(jstr)-1]))
				} else if res.UnmaskingFailed != nil && *res.UnmaskingFailed {
					fmt.Print("<unmasking failed>")
				} else {
					fmt.Print("<empty>")
				}
				for i := range selectorNames {
					fmt.Print("\t")
					for si := range res.Record.Selectors {
						sn := []byte(selectorNames[i])
						if res.Record.SelectorIs(sn, si) {
							fmt.Print(selectorNames[i])
							if len(res.Record.Selectors[si].Ordinal) > 0 {
								fmt.Print("#")
								fmt.Print(escapeOrdinal(res.Record.Selectors[si].Ordinal))
							}
						}
					}
				}
				fmt.Println("")
			}
		}
	}
}

func doSet(cfg *lf.ClientConfig, basePath string, args []string, jsonOutput bool) {
	setOpts := flag.NewFlagSet("set", flag.ContinueOnError)
	ownerName := setOpts.String("owner", "", "")
	maskKey := setOpts.String("mask", "", "")
	valueIsFile := setOpts.Bool("file", false, "")
	remote := setOpts.Bool("remote", false, "")
	tryRemote := setOpts.Bool("tryremote", false, "")
	urlOverride := setOpts.String("url", "", "")
	setOpts.SetOutput(ioutil.Discard)
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
			log.Printf("ERROR: set failed: owner '%s' not found\n", *ownerName)
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
		log.Println("ERROR: set failed: owner not found and no default specified")
		return
	}

	var mk []byte
	if len(*maskKey) > 0 {
		mk = []byte(*maskKey)
	}

	var plainTextSelectorNames, selectorOrdinals [][]byte
	var selectors []lf.APINewSelector
	for i := 0; i < len(args)-1; i++ {
		var unesc string
		json.Unmarshal([]byte("\""+args[i]+"\""), &unesc) // use JSON string escaping for selector arguments
		if len(unesc) > 0 {
			selOrd := tokenizeStringWithEsc(unesc, '#', '\\')
			if len(selOrd) > 0 {
				if len(selOrd) > 2 {
					log.Println("ERROR: set failed: invalid selector#ordinal: \"" + args[i] + "\"")
				}
				sel := []byte(selOrd[0])
				var ord []byte
				if len(selOrd) == 2 {
					ord = []byte(selOrd[1])
				}
				if len(ord) > lf.SelectorMaxOrdinalSize {
					log.Println("ERROR: set failed: invalid selector#ordinal: \"" + args[i] + "\" (max ordinal size is 31 bytes)")
				}
				plainTextSelectorNames = append(plainTextSelectorNames, sel)
				selectorOrdinals = append(selectorOrdinals, ord)
				selectors = append(selectors, lf.APINewSelector{
					Name:    sel,
					Ordinal: ord,
				})
			}
		}
	}

	value := []byte(args[len(args)-1])
	if *valueIsFile {
		if string(value) == "-" {
			value, err = ioutil.ReadAll(os.Stdin)
			if err != nil {
				log.Println("ERROR: set failed: error reading data from stdin (\"-\" specified as input file)")
				return
			}
		}
		vdata, err := ioutil.ReadFile(string(value))
		if err != nil {
			log.Println("ERROR: set failed: file '" + err.Error() + "' not found")
			return
		}
		value = vdata
	}

	var links []lf.HashBlob
	var rec *lf.Record
	ts := lf.TimeSec()

	urls := cfg.Urls
	if len(*urlOverride) > 0 {
		urls = tokenizeStringWithEsc(*urlOverride, ',', '\\')
	}
	if len(urls) == 0 {
		log.Println("ERROR: set failed: no URLs configured!")
		return
	}

	// Get links for record
	for _, u := range urls {
		links, err = lf.APIGetLinks(u, 0)
		if err == nil {
			break
		}
	}
	if err != nil {
		fmt.Printf("ERROR: set failed: cannot get links: %s\n", err.Error())
		return
	}

	// If remote delegated record creation is preferred, try that first.
	var submitDirectly []string
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
				submitDirectly = nil
				break
			}
			apiErr, isAPIErr := err.(lf.APIError)
			if isAPIErr && apiErr.Code == lf.APIErrorLazy {
				submitDirectly = append(submitDirectly, u)
			}
		}
	} else {
		submitDirectly = urls
	}

	// If not delegating or trial remote delgation failed, make record locally.
	if len(submitDirectly) > 0 && !*remote {
		go lf.WharrgarblInitTable(path.Join(basePath, "wharrgarbl-table.bin"))
		var o *lf.Owner
		o, err = owner.GetOwner()
		if err == nil {
			lnks := make([][32]byte, 0, len(links))
			for _, l := range links {
				lnks = append(lnks, l)
			}
			rec, err = lf.NewRecord(lf.RecordTypeDatum, value, lnks, mk, plainTextSelectorNames, selectorOrdinals, nil, ts, lf.NewWharrgarblr(lf.RecordDefaultWharrgarblMemory, 0), o)
			if err == nil {
				rb := rec.Bytes()
				for _, u := range submitDirectly {
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

	if jsonOutput {
		fmt.Println(lf.PrettyJSON(rec))
	} else {
		rh := rec.Hash()
		fmt.Printf("=%s\n", lf.Base58Encode(rh[:]))
	}
}

func doOwner(cfg *lf.ClientConfig, basePath string, args []string) {
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
			fmt.Printf("%-24s %s @%s\n", n, dfl, lf.Base58Encode(o.Owner))
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
		fmt.Printf("%-24s %s @%s\n", name, dfl, lf.Base58Encode(owner.Bytes()))

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
		fmt.Printf("%-24s * @%s\n", name, lf.Base58Encode(cfg.Owners[name].Owner))

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

// doMakeGenesis is currently code for making the default genesis records and isn't very useful to anyone else.
func doMakeGenesis(cfg *lf.ClientConfig, basePath string, args []string) {
	g := &lf.SolGenesisParameters
	fmt.Printf("Genesis parameters:\n%s\nCreating %d genesis records...\n", lf.PrettyJSON(g), g.RecordMinLinks)

	genesisRecords, genesisOwner, err := lf.CreateGenesisRecords(lf.OwnerTypeNistP384, g)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		os.Exit(-1)
		return
	}

	var grData bytes.Buffer
	for i := 0; i < len(genesisRecords); i++ {
		fmt.Printf("%s\n", lf.PrettyJSON(genesisRecords[i]))
		err = genesisRecords[i].MarshalTo(&grData, false)
		if err != nil {
			fmt.Printf("ERROR: %s\n", err.Error())
			os.Exit(-1)
			return
		}
	}

	ioutil.WriteFile("genesis.lf", grData.Bytes(), 0644)
	ioutil.WriteFile("genesis.go", []byte(fmt.Sprintf("var SolGenesisRecords = %#v\n", grData.Bytes())), 0644)
	if len(g.AmendableFields) > 0 {
		ioutil.WriteFile("genesis.secret", genesisOwner.PrivateBytes(), 0600)
	}

	fmt.Printf("\nWrote genesis.lf, genesis.go, and genesis.secret (if amendable) to current directory.\n")
}

func main() {
	globalOpts := flag.NewFlagSet("global", flag.ContinueOnError)
	basePath := globalOpts.String("path", lfDefaultPath, "")
	jsonOutput := globalOpts.Bool("json", false, "")
	globalOpts.SetOutput(ioutil.Discard)
	err := globalOpts.Parse(os.Args[1:])
	if err != nil {
		printHelp("")
		return
	}
	args := globalOpts.Args()
	if len(args) < 1 {
		printHelp("")
		return
	}
	var cmdArgs []string
	if len(args) > 1 {
		cmdArgs = args[1:]
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

	switch args[0] {

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
		case "core":
			lf.TestCore(os.Stdout)
		case "wharrgarbl":
			go lf.WharrgarblInitTable(path.Join(*basePath, "wharrgarbl-table.bin"))
			lf.TestWharrgarbl(os.Stdout)
		case "database":
			lf.TestDatabase("./lf-db-test", os.Stdout)
		default:
			printHelp("")
		}

	case "node-start":
		doNodeStart(&cfg, *basePath, cmdArgs)

	case "node-connect":
		doNodeConnect(&cfg, *basePath, cmdArgs)

	case "proxy-start":
		doProxyStart(&cfg, *basePath, cmdArgs)

	case "status":
		doStatus(&cfg, *basePath, cmdArgs)

	case "set":
		doSet(&cfg, *basePath, cmdArgs, *jsonOutput)

	case "get":
		doGet(&cfg, *basePath, cmdArgs, *jsonOutput)

	case "owner":
		doOwner(&cfg, *basePath, cmdArgs)

	case "_makegenesis":
		doMakeGenesis(&cfg, *basePath, cmdArgs)

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
