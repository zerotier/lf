/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
 */

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	secrand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/crypto/acme/autocert"

	"lf/pkg/lf"
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
		return "./lf" // fallback under weird conditions
	}()

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

func prompt(prompt string, required bool, dfl string) string {
	var b [1]byte
	var s strings.Builder
	fmt.Print(prompt)
	for {
		n, err := os.Stdin.Read(b[:])
		if err != nil || n != 1 {
			return dfl
		}
		if b[0] == '\n' {
			ss := strings.TrimSpace(s.String())
			if len(ss) == 0 {
				if required {
					fmt.Print(prompt)
					s.Reset()
				} else {
					return dfl
				}
			}
			return ss
		} else if b[0] == '\b' {
			ss := s.String()
			s.Reset()
			if len(ss) > 1 {
				s.WriteString(ss[0 : len(ss)-2])
			}
		} else if b[0] != '\r' {
			s.WriteByte(b[0])
		}
	}
}

func printHelp(cmd string) {
	// NOTE: When editing make sure your editor doesn't indent help with
	// tabs, otherwise it will format funny on a console. Also try to keep
	// this 80 column just for legacy/standard reasons.
	fmt.Print(`LF Global Key/Value Store ` + lf.VersionStr + `
(c)2018-2019 ZeroTier, Inc.  https://www.zerotier.com/
Licensed under the GNU GPLv3

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
    -oracle                               Use spare CPU to publish commentary
    -loglevel <normal|verbose|trace>      Node log level
    -logstderr                            Log to stderr, not HOME/node.log
    -letsencrypt <host[,host]>            Run LetsEncrypt HTTPS on port 443
  node-connect <ip> <port> <identity>     Tell node to try a P2P endpoint
  status                                  Get status from remote node/proxy
  set [-...] <name[#ord]> [...] <value>   Set a value in the data store
    -file                                 Value is a file path ("-" for stdin)
    -mask <key>                           Override default masking key
    -owner <owner>                        Use this owner instead of default
    -url <url[,url,...]>                  Override configured node/proxy URLs
  get [-...] <name[#start[#end]]> [...]   Find by selector (optional range)
    -mask <key>                           Override default masking key
    -tstart <time>                        Constrain to after this time
    -tend <time>                          Constrain to before this time
    -url <url[,url,...]>                  Override configured node/proxy URLs
  owner <operation> [...]
    list                                  List owners
    new <name> [p224|p384|ed25519]        Create a new owner
    default <name>                        Set default owner
    delete <name>                         Delete an owner (PERMANENT)
    rename <old name> <new name>          Rename an owner
  url <operation> [...]
    list                                  Show client URLs
    add <url>                             Add a URL
    delete <url>                          Delete a URL
    default <url>                         Move URL to front (first to try)

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

//////////////////////////////////////////////////////////////////////////////

func doNodeStart(cfg *lf.ClientConfig, basePath string, args []string) {
	var logFile *os.File
	defer func() {
		e := recover()
		if e != nil {
			logger.Printf("FATAL: caught unexpected panic in doNodeStart(): %s", e)
		}
		if logFile != nil {
			logFile.Close()
		}
	}()

	nodeOpts := flag.NewFlagSet("node-start", flag.ContinueOnError)
	p2pPort := nodeOpts.Int("p2p", lf.DefaultP2PPort, "")
	httpPort := nodeOpts.Int("http", lf.DefaultHTTPPort, "")
	oracle := nodeOpts.Bool("oracle", false, "")
	logLevel := nodeOpts.String("loglevel", "verbose", "")
	logToStderr := nodeOpts.Bool("logstderr", false, "")
	letsEncrypt := nodeOpts.String("letsencrypt", "", "")
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
			logger.Printf("FATAL: cannot open node.log: %s\n", err.Error())
			return
		}
		logger = log.New(logFile, "", log.LstdFlags)
	}

	var letsEncryptDomains []string
	var letsEncryptServer *http.Server
	var letsEncryptShuttingDown uint32
	if len(*letsEncrypt) > 0 {
		letsEncryptDomains = strings.Split(*letsEncrypt, ",")
		for i := range letsEncryptDomains {
			letsEncryptDomains[i] = strings.TrimSpace(letsEncryptDomains[i])
		}

		letsEncryptCachePath := path.Join(basePath, "letsencrypt")
		os.MkdirAll(letsEncryptCachePath, 0700)

		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(letsEncryptDomains...),
			Cache:      autocert.DirCache(letsEncryptCachePath),
		}

		letsEncryptServer = &http.Server{
			Addr:           ":https",
			IdleTimeout:    10 * time.Second,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   30 * time.Second,
			ErrorLog:       logger,
			MaxHeaderBytes: 4096,
			TLSConfig:      certManager.TLSConfig(),
		}

		go func() {
			err := letsEncryptServer.ListenAndServeTLS("", "")
			if err != nil && atomic.LoadUint32(&letsEncryptShuttingDown) == 0 {
				logger.Printf("WARNING: LetsEncrypt SSL server for [%v] failed to start: %s", letsEncryptDomains, err.Error())
			}
		}()
	}

	osSignalChannel := make(chan os.Signal, 2)
	signal.Notify(osSignalChannel, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGBUS)
	signal.Ignore(syscall.SIGUSR1, syscall.SIGUSR2)

	node, err := lf.NewNode(basePath, *p2pPort, *httpPort, logger, ll)
	if err != nil {
		logger.Printf("FATAL: unable to start node: %s\n", err.Error())
		return
	}
	node.SetCommentaryEnabled(*oracle)

	if letsEncryptServer != nil {
		letsEncryptServer.Handler = node.GetHTTPHandler()
	}

	sig := <-osSignalChannel
	if sig == syscall.SIGBUS {
		// SIGBUS can happen if mmap'd I/O fails, such as if we are running over a network
		// drive (not recommended for this reason) or a path is forcibly unmounted. The mmap
		// code is in C but this should in theory get caught here.
		logger.Println("FATAL: received SIGBUS, shutting down (likely I/O problem, database may be corrupt!)")
	}
	node.Stop()

	if letsEncryptServer != nil {
		atomic.StoreUint32(&letsEncryptShuttingDown, 1)
		letsEncryptServer.Close()
	}
}

//////////////////////////////////////////////////////////////////////////////

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
	urls := cfg.URLs
	for _, u := range urls {
		err = lf.APIPostConnect(u, ip, int(port), args[2])
		if err == nil {
			break
		}
	}
	if err != nil {
		logger.Printf("ERROR: cannot send connect command to node: %s\n", err.Error())
		return
	}
}

func doStatus(cfg *lf.ClientConfig, basePath string, args []string) {
	if len(args) != 0 {
		printHelp("")
		return
	}
	var stat *lf.APIStatusResult
	var err error
	urls := cfg.URLs
	for _, u := range urls {
		stat, err = lf.APIStatusGet(u)
		if err == nil {
			break
		}
	}
	if err != nil {
		logger.Printf("ERROR: status query failed: %s\n", err.Error())
		return
	}
	fmt.Println(lf.PrettyJSON(stat))
}

//////////////////////////////////////////////////////////////////////////////

var one = 1

func doGet(cfg *lf.ClientConfig, basePath string, args []string, jsonOutput bool) {
	getOpts := flag.NewFlagSet("get", flag.ContinueOnError)
	maskKey := getOpts.String("mask", "", "")
	tStart := getOpts.String("tstart", "", "")
	tEnd := getOpts.String("tend", "", "")
	urlOverride := getOpts.String("url", "", "")
	json2 := getOpts.Bool("json", jsonOutput, "") // allow -json after get for convenience
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
	jsonOutput = *json2

	var mk []byte
	if len(*maskKey) > 0 {
		mk = []byte(*maskKey)
	}

	urls := cfg.URLs
	if len(*urlOverride) > 0 {
		urls = tokenizeStringWithEsc(*urlOverride, ',', '\\')
	}
	if len(urls) == 0 {
		logger.Println("ERROR: get query failed: no URLs configured!")
		return
	}

	tr := []uint64{0, 9223372036854775807}
	if len(*tStart) > 0 {
		tr[0] = parseCLITime(*tStart)
	}
	if len(*tEnd) > 0 {
		tr[1] = parseCLITime(*tEnd)
	}

	var ranges []lf.QueryRange
	var selectorNames []string
	for i := 0; i < len(args); i++ {
		var unesc string
		json.Unmarshal([]byte("\""+args[i]+"\""), &unesc) // use JSON string escaping for selector arguments
		if len(unesc) > 0 {
			tord := tokenizeStringWithEsc(unesc, '#', '\\')
			if len(tord) >= 1 && len(mk) == 0 {
				mk = []byte(tord[0])
			}
			if len(tord) == 1 {
				ranges = append(ranges, lf.QueryRange{KeyRange: []lf.Blob{lf.MakeSelectorKey([]byte(tord[0]), 0)}})
			} else if len(tord) == 2 {
				if len(tord[1]) == 0 {
					ranges = append(ranges, lf.QueryRange{KeyRange: []lf.Blob{lf.MakeSelectorKey([]byte(tord[0]), 0), lf.MakeSelectorKey([]byte(tord[0]), 0xffffffffffffffff)}})
				} else {
					ord0, _ := strconv.ParseUint(tord[1], 10, 64)
					ranges = append(ranges, lf.QueryRange{KeyRange: []lf.Blob{lf.MakeSelectorKey([]byte(tord[0]), ord0)}})
				}
			} else if len(tord) == 3 {
				ord0, _ := strconv.ParseUint(tord[1], 10, 64)
				ord1, _ := strconv.ParseUint(tord[2], 10, 64)
				ranges = append(ranges, lf.QueryRange{KeyRange: []lf.Blob{
					lf.MakeSelectorKey([]byte(tord[0]), ord0),
					lf.MakeSelectorKey([]byte(tord[0]), ord1),
				}})
			} else {
				fmt.Printf("ERROR: get query failed: selector or selector ordinal range invalid")
				return
			}
			selectorNames = append(selectorNames, tord[0])
		}
	}

	req := &lf.Query{
		Range:     ranges,
		TimeRange: tr,
	}
	if !jsonOutput {
		req.Limit = &one
	}

	var results lf.QueryResults
	for _, u := range urls {
		results, err = req.ExecuteRemote(u)
		if err == nil {
			break
		}
	}

	if err != nil {
		logger.Printf("ERROR: get query failed: %s\n", err.Error())
		return
	}

	for _, ress := range results {
		for rii, res := range ress {
			res.Value, err = res.Record.GetValue(mk)
			if err != nil {
				res.Value = nil
			}
			ress[rii] = res
		}
	}

	if jsonOutput {
		if len(results) > 0 {
			fmt.Println(lf.PrettyJSON(results))
		} else {
			fmt.Println("[]")
		}
	} else {
		maxStrLen := 2
		resultStrings := make([]string, 0, len(results))
		resultStringLengths := make([]int, 0, len(results))

		for _, ress := range results {
			if len(ress) > 0 {
				res := &ress[0]
				if len(res.Value) > 0 {
					rs := string(res.Value)
					var sb strings.Builder
					sl := 0
					for _, c := range rs {
						if unicode.IsPrint(c) {
							sb.WriteRune(c)
							sl++
						}
					}
					rs = sb.String()
					if sl > maxStrLen {
						maxStrLen = sl
					}
					resultStrings = append(resultStrings, rs)
					resultStringLengths = append(resultStringLengths, sl)
				} else {
					resultStrings = append(resultStrings, "-")
					resultStringLengths = append(resultStringLengths, 1)
				}
			}
		}

		for ri, ress := range results {
			if len(ress) > 0 {
				res := &ress[0]
				fmt.Print(resultStrings[ri])
				for s := 0; s < maxStrLen-resultStringLengths[ri]; s++ {
					fmt.Print(" ")
				}
				fmt.Print(" | ")
				for i := range selectorNames {
					sn := []byte(selectorNames[i])
					if res.Record.SelectorIs(sn, i) {
						fmt.Printf("%s#%d", selectorNames[i], res.Record.Selectors[i].Ordinal.Get(sn))
						if i != len(res.Record.Selectors)-1 {
							fmt.Print(" ")
						}
					}
				}
				for i := len(selectorNames); i < len(res.Record.Selectors); i++ {
					sk := lf.Base62Encode(res.Record.SelectorKey(i))
					if i != len(res.Record.Selectors)-1 {
						fmt.Printf("?%s ", sk)
					} else {
						fmt.Printf("?%s", sk)
					}
				}
				fmt.Println("")
			}
		}
	}
}

//////////////////////////////////////////////////////////////////////////////

func doSet(cfg *lf.ClientConfig, basePath string, args []string) {
	go lf.WharrgarblInitTable(path.Join(basePath, "wharrgarbl-table.bin"))

	setOpts := flag.NewFlagSet("set", flag.ContinueOnError)
	ownerName := setOpts.String("owner", "", "")
	maskKey := setOpts.String("mask", "", "")
	valueIsFile := setOpts.Bool("file", false, "")
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
			logger.Printf("ERROR: set failed: owner '%s' not found\n", *ownerName)
			return
		}
	}
	if owner == nil {
		for _, o := range cfg.Owners {
			if o.Default {
				owner = o
				break
			}
		}
	}
	if owner == nil {
		logger.Println("ERROR: set failed: owner not found and no default specified")
		return
	}

	var mk []byte
	if len(*maskKey) > 0 {
		mk = []byte(*maskKey)
	}

	var plainTextSelectorNames [][]byte
	var plainTextSelectorOrdinals []uint64
	for i := 0; i < len(args)-1; i++ {
		var unesc string
		json.Unmarshal([]byte("\""+args[i]+"\""), &unesc) // use JSON string escaping for selector arguments
		if len(unesc) > 0 {
			selOrd := tokenizeStringWithEsc(unesc, '#', '\\')
			if len(selOrd) > 0 {
				if len(selOrd) > 2 {
					logger.Println("ERROR: set failed: invalid selector#ordinal: \"" + args[i] + "\"")
				}
				sel := []byte(selOrd[0])
				var ord uint64
				if len(selOrd) == 2 {
					ord, _ = strconv.ParseUint(selOrd[1], 10, 64)
				}
				plainTextSelectorNames = append(plainTextSelectorNames, sel)
				plainTextSelectorOrdinals = append(plainTextSelectorOrdinals, ord)
			}
		}
	}

	vstr := args[len(args)-1]
	value := []byte(vstr)
	if *valueIsFile {
		if vstr == "-" {
			value, err = ioutil.ReadAll(os.Stdin)
			if err != nil {
				logger.Println("ERROR: set failed: error reading data from stdin (\"-\" specified as input file)")
				return
			}
		} else {
			value, err = ioutil.ReadFile(vstr)
			if err != nil {
				logger.Println("ERROR: set failed: file '" + vstr + "' not found or not readable (" + err.Error() + ")")
				return
			}
		}
	}

	var links []lf.HashBlob
	var rec *lf.Record
	ts := lf.TimeSec()

	urls := cfg.URLs
	if len(*urlOverride) > 0 {
		urls = tokenizeStringWithEsc(*urlOverride, ',', '\\')
	}
	if len(urls) == 0 {
		logger.Println("ERROR: set failed: no URLs configured!")
		return
	}

	for _, u := range urls {
		var serverTimestamp int64
		links, serverTimestamp, err = lf.APIGetLinks(u, 0)
		if err == nil {
			break
		}
		if serverTimestamp > 0 {
			myClock := time.Now().Unix()
			if ((serverTimestamp > myClock) && (serverTimestamp-myClock) > 10) || ((myClock > serverTimestamp) && (myClock-serverTimestamp) > 10) {
				logger.Printf("ERROR: server clock %d is more than 10 seconds off from our clock %d, can cause record rejection or reduced reputation", serverTimestamp, myClock)
			}
		}
	}
	if err != nil {
		fmt.Printf("ERROR: set failed: unable to get links for new record: %s\n", err.Error())
		return
	}

	var o *lf.Owner
	o, err = owner.GetOwner()
	if err == nil {
		lnks := make([][32]byte, 0, len(links))
		for _, l := range links {
			lnks = append(lnks, l)
		}
		rec, err = lf.NewRecord(lf.RecordTypeDatum, value, lnks, mk, plainTextSelectorNames, plainTextSelectorOrdinals, nil, ts, lf.NewWharrgarblr(lf.RecordDefaultWharrgarblMemory, 0), o)
		if err == nil {
			rb := rec.Bytes()
			for _, u := range urls {
				for trials := 0; trials < 2; trials++ {
					err = lf.APIPostRecord(u, rb)
					if err == nil {
						break
					}
				}
				if err == nil {
					break
				}
			}
		}
	}

	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		return
	}

	rh := rec.Hash()
	fmt.Printf("%s =%s\n", o.String(), lf.Base62Encode(rh[:]))
}

//////////////////////////////////////////////////////////////////////////////

func doOwner(cfg *lf.ClientConfig, basePath string, args []string) {
	cmd := "list"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {

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
			fmt.Printf("%-24s %s %-7s %s\n", n, dfl, o.Public.TypeString(), o.Public.String())
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
		ownerType := lf.OwnerTypeNistP224
		if len(args) > 2 {
			if args[2] == "p244" {
				ownerType = lf.OwnerTypeNistP224
			} else if args[2] == "p384" {
				ownerType = lf.OwnerTypeNistP384
			} else if args[2] == "ed25519" {
				ownerType = lf.OwnerTypeEd25519
			} else {
				fmt.Println("ERROR: unrecognized owner type")
				return
			}
		}
		owner, _ := lf.NewOwner(ownerType)
		isDfl := len(cfg.Owners) == 0
		priv, _ := owner.PrivateBytes()
		cfg.Owners[name] = &lf.ClientConfigOwner{
			Public:  owner.Public,
			Private: priv,
			Default: isDfl,
		}
		cfg.Dirty = true
		dfl := " "
		if isDfl {
			dfl = "*"
		}
		fmt.Printf("%-24s %s %-7s %s\n", name, dfl, owner.TypeString(), owner.String())

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
		fmt.Printf("%-24s * %-7s %s\n", name, cfg.Owners[name].Public.TypeString(), cfg.Owners[name].Public.String())

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

//////////////////////////////////////////////////////////////////////////////

func doURL(cfg *lf.ClientConfig, basePath string, args []string) {
	cmd := "list"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "list":
		for _, u := range cfg.URLs {
			fmt.Println(u)
		}
	case "add":
		if len(args) < 2 {
			printHelp("")
			return
		}
		url := strings.TrimSpace(args[1])
		have := false
		for _, u := range cfg.URLs {
			if u == url {
				have = true
			}
		}
		if !have {
			cfg.URLs = append([]string{url}, cfg.URLs...)
			cfg.Dirty = true
		}
		for _, u := range cfg.URLs {
			fmt.Println(u)
		}
	case "delete":
		var u2 []string
		if len(args) < 2 {
			printHelp("")
			return
		}
		url := strings.TrimSpace(args[1])
		for _, u := range cfg.URLs {
			if u != url {
				u2 = append(u2, u)
			}
		}
		cfg.URLs = u2
		cfg.Dirty = true
		for _, u := range cfg.URLs {
			fmt.Println(u)
		}
	case "default":
		var u2 []string
		if len(args) < 2 {
			printHelp("")
			return
		}
		url := strings.TrimSpace(args[1])
		u2 = append(u2, url)
		for _, u := range cfg.URLs {
			if u != url {
				u2 = append(u2, u)
			}
		}
		cfg.URLs = u2
		cfg.Dirty = true
		for _, u := range cfg.URLs {
			fmt.Println(u)
		}
	default:
		printHelp("")
	}
}

//////////////////////////////////////////////////////////////////////////////

func atoUI(s string) uint {
	i, _ := strconv.ParseUint(s, 10, 64)
	return uint(i)
}

// doMakeGenesis is currently code for making the default genesis records and isn't very useful to anyone else.
func doMakeGenesis(cfg *lf.ClientConfig, basePath string, args []string) {
	var g lf.GenesisParameters
	g.Name = prompt("Network name: ", true, "")
	if g.Name == "~~~Sol" { // magic value used internally to make Sol, useless to others
		g = lf.GenesisParameters{
			ID:                 [32]byte{0x17, 0x55, 0x22, 0x2e, 0x7c, 0x33, 0xa8, 0x5f, 0xc9, 0x70, 0x59, 0x5b, 0xfa, 0x5b, 0x46, 0x3b, 0x2a, 0xa9, 0x35, 0xee, 0x3e, 0x46, 0xbe, 0xd3, 0x3b, 0x14, 0x14, 0x8d, 0xe3, 0xd8, 0x8d, 0x23},
			AmendableFields:    []string{"authcertificates", "seedpeers"},
			Name:               "Sol",
			Contact:            "https://www.zerotier.com/lf",
			Comment:            "Global Public LF Data Store",
			RecordMinLinks:     2,
			RecordMaxValueSize: 1024,
			RecordMaxTimeDrift: 60,
			SeedPeers: []lf.Peer{
				lf.Peer{ // ZeroTier LF node in Helsinki, Finland
					IP:       net.ParseIP("95.216.29.85"),
					Port:     9908,
					Identity: lf.Base62Decode("JrKNrBrauJsmnbeGRPYN6NmyM81yp32MjmLhNb2EQENd0NwilsR4Cxsdd4CdgkPMS"),
				},
				lf.Peer{ // ZeroTier LF node at our HQ in Los Angeles, California, USA
					IP:       net.ParseIP("174.136.102.98"),
					Port:     9908,
					Identity: lf.Base62Decode("Hcsqi4GP24UhaJL9poDM35k7KwvgvYzt1fMrYDr5EEAhTJ1ZnHu61xpDctypw66fh"),
				},
			},
		}
		fmt.Println("Using Sol network defaults...")
	} else {
		secrand.Read(g.ID[:])
		fmt.Printf("Network ID will be %x\n", g.ID)
		g.Contact = prompt("Network contact []: ", false, "")
		g.Comment = prompt("Network comment or description []: ", false, "")
		g.RecordMinLinks = atoUI(prompt("Record minimum links [2]: ", false, "2"))
		if g.RecordMinLinks < 2 {
			fmt.Println("ERROR: min links must be at least 2 or things won't work!")
			return
		}
		g.RecordMaxValueSize = atoUI(prompt("Record maximum value size [1024]: ", false, "1024"))
		if g.RecordMaxValueSize > lf.RecordMaxSize {
			fmt.Println("ERROR: record value sizee too large!")
			return
		}
		g.RecordMaxTimeDrift = atoUI(prompt("Record maximum time drift (seconds) [60]: ", false, "60"))
		for {
			err := g.SetAmendableFields(strings.Split(prompt("Amendable fields (comma separated) []: ", false, ""), ","))
			if err == nil {
				break
			}
		}
	}

	q := prompt("Create a record authorization certificate? [y/N]: ", false, "n")
	for {
		if q == "Y" || q == "y" || q == "1" {
			key, err := ecdsa.GenerateKey(elliptic.P384(), secrand.Reader)
			if err != nil {
				fmt.Printf("ERROR: unable to generate ECDSA key pair: %s\n", err.Error())
				return
			}

			s256 := sha256.New()
			s256.Write(key.PublicKey.X.Bytes())
			s256.Write(key.PublicKey.Y.Bytes())
			serialNo := s256.Sum(nil)
			serialNoStr := lf.Base62Encode(serialNo)

			ttl := atoUI(prompt("  Time to live in days [36500]: ", false, "36500"))
			if ttl <= 0 {
				fmt.Println("ERROR: invalid value: must be >0")
				return
			}

			var name pkix.Name
			name.Country = []string{prompt("  Country []: ", false, "")}
			name.Organization = []string{prompt("  Organization []: ", false, "")}
			name.OrganizationalUnit = []string{prompt("  Organizational unit []: ", false, "")}
			name.Locality = []string{prompt("  Locality []: ", false, "")}
			name.Province = []string{prompt("  Province []: ", false, "")}
			name.StreetAddress = []string{prompt("  Street address []: ", false, "")}
			name.PostalCode = []string{prompt("  Postal code []: ", false, "")}
			name.SerialNumber = serialNoStr
			name.CommonName = prompt("  Common name []: ", false, "")

			pseudoWork := prompt("  Pseudo-work value of signature (hex 0-ffffffff) [0]: ", false, "0")
			pseudoWorkInt, err := strconv.ParseInt(pseudoWork, 16, 64)
			if err != nil || pseudoWorkInt > 0xffffffff || pseudoWorkInt < 0 {
				fmt.Println("ERROR: invalid value: must be hex 0-ffffffff")
				return
			}
			pseudoWorkASN1V, err := asn1.Marshal(pseudoWorkInt)
			if err != nil {
				fmt.Printf("ERROR: ASN.1 marshal failed: %s\n", err.Error())
				return
			}

			now := time.Now()
			cert := &x509.Certificate{
				SerialNumber: new(big.Int).SetBytes(serialNo),
				Subject:      name,
				NotBefore:    now,
				NotAfter:     now.Add(time.Hour * time.Duration(24*ttl)),
				ExtraExtensions: []pkix.Extension{pkix.Extension{
					Id:       lf.AuthCertificateASN1PseudoWorkValue,
					Critical: false,
					Value:    pseudoWorkASN1V,
				}},
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
				KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				BasicConstraintsValid: true,
				IsCA:                  true,
			}

			certBytes, err := x509.CreateCertificate(secrand.Reader, cert, cert, &key.PublicKey, key)
			if err != nil {
				logger.Printf("ERROR: unable to create CA certificate: %s", err.Error())
				return
			}
			cert2, err := x509.ParseCertificate(certBytes)
			if err != nil {
				logger.Printf("ERROR: unable to create CA certificate (parsing test): %s", err.Error())
				return
			}
			if lf.GetAuthCertificatePseudoWork(cert2) != uint32(pseudoWorkInt) {
				logger.Printf("ERROR: unable to create CA certificate (parsing test): pseudo-work ints do not match")
				return
			}
			if cert.Subject.String() != cert2.Subject.String() {
				logger.Printf("ERROR: unable to create CA certificate (parsing test): subjects do not match")
				return
			}

			keyBytes, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				logger.Printf("ERROR: unable to x509 encode ECDSA private key: %s", err.Error())
				return
			}

			err = ioutil.WriteFile("genesis-auth-"+serialNoStr+"-secret.pem", []byte(pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: keyBytes})), 0600)
			if err != nil {
				logger.Printf("ERROR: unable to write cert key PEM: %s", err.Error())
				return
			}

			g.AuthCertificates = append(g.AuthCertificates, certBytes...)
		} else {
			break
		}
		q = prompt("Create another record authorization certificate? [y/N]: ", false, "n")
	}
	if len(g.AuthCertificates) > 0 {
		certs, err := g.GetAuthCertificates()
		if err != nil {
			logger.Printf("ERROR: unable to create CA certificate: %s", err.Error())
			return
		}
		fmt.Printf("  (%d authorization certificates, %d bytes)\n", len(certs), len(g.AuthCertificates))
		q = prompt("Authorization certificates required? [y/N]: ", false, "n")
		g.AuthRequired = q == "Y" || q == "y" || q == "1"
	}

	fmt.Printf("Genesis parameters:\n%s\nCreating %d genesis records...\n", lf.PrettyJSON(g), g.RecordMinLinks)

	genesisRecords, genesisOwner, err := lf.CreateGenesisRecords(lf.OwnerTypeNistP384, &g)
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
			logger.Printf("ERROR: %s", err.Error())
			os.Exit(-1)
			return
		}
	}

	err = ioutil.WriteFile("genesis.lf", grData.Bytes(), 0644)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		os.Exit(-1)
		return
	}
	ioutil.WriteFile("genesis.go", []byte(fmt.Sprintf("%#v\n", grData.Bytes())), 0644)
	if len(g.AmendableFields) > 0 {
		priv, _ := genesisOwner.PrivateBytes()
		ioutil.WriteFile("genesis-secret.pem", []byte(pem.EncodeToMemory(&pem.Block{Type: lf.OwnerPrivatePEMType, Bytes: priv})), 0600)
	}

	fmt.Printf("\nWrote genesis.* files to current directory.\n")
}

//////////////////////////////////////////////////////////////////////////////

func main() {
	globalOpts := flag.NewFlagSet("global", flag.ContinueOnError)
	basePath := globalOpts.String("path", lfDefaultPath, "")
	jsonOutput := globalOpts.Bool("json", false, "")
	globalOpts.SetOutput(ioutil.Discard)
	err := globalOpts.Parse(os.Args[1:])
	if err != nil {
		printHelp("")
		os.Exit(0)
		return
	}
	args := globalOpts.Args()
	if len(args) < 1 {
		printHelp("")
		os.Exit(0)
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
		os.Exit(0)
		return

	case "version":
		fmt.Println(lf.VersionStr)
		os.Exit(0)
		return

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
		os.Exit(0)
		return

	case "node-start":
		doNodeStart(&cfg, *basePath, cmdArgs)

	case "node-connect":
		doNodeConnect(&cfg, *basePath, cmdArgs)

	case "status":
		doStatus(&cfg, *basePath, cmdArgs)

	case "set":
		doSet(&cfg, *basePath, cmdArgs)

	case "get":
		doGet(&cfg, *basePath, cmdArgs, *jsonOutput)

	case "owner":
		doOwner(&cfg, *basePath, cmdArgs)

	case "url":
		doURL(&cfg, *basePath, cmdArgs)

	case "makegenesis":
		doMakeGenesis(&cfg, *basePath, cmdArgs)
		os.Exit(0)
		return

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
