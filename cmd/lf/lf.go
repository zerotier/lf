package main

import (
	"flag"
	"fmt"
	"os"
	"path"

	"../../pkg/lf"
)

//////////////////////////////////////////////////////////////////////////////

func printHelpHdr() {
	fmt.Print(`LF Global Key/Value Store ` + lf.VersionStr + `
(c)2018 ZeroTier, Inc.  https://www.zerotier.com/
MIT License

Usage: lf [-global options] <command> [-command options] [...]

Global options:
	-path <path>                       Override default home directory
	-use <url>                         Override configured full node URL(s)
	-verbose                           Generate verbose output to stderr
	-json                              Output raw JSON for API query commands
`)
}

func printHelp(cmd string) {
	printHelpHdr()

	switch cmd {
	case "version":
		fmt.Print("\nThe 'version' command has no options.\n")
		return
	case "selftest":
		fmt.Print(`
The 'selftest' command runs all tests if no test is specified. The following
tests are available:
	core                               Test core functions and data types
	wharrgarbl                         Test and benchmark work function (slow)
	database                           Test database and graph algorithms

`)
	case "node-start":
	case "proxy-start":
	case "config":
	case "set":
	case "get":
	case "find":
	case "owner":
	case "status":
		fmt.Print("\nThe 'status' command has no options.\n")
		return
	}

	fmt.Print(`
Commands:
	help [<command>]                   Display help on a specific command
	version                            Display version information
	selftest [test]                    Perform internal self-test and exit
	node-start                         Start a full node
	proxy-start                        Start a local record creation proxy
	config [variable] [value]          Display, get, and set config variables
	set <[~]key> <[~]value>            Set a key in the global key/value store
	get <[~]key>                       Get the value of a key
	find [-options]                    Find one or more keys by selector, etc.
	owner <subcommand> [<name>]        List, create, or remove an owner key pair
	status                             Query a full node and display its status

Many commands have options, so use 'help <command>' for details.

Configuration and other data is stored in LF's home directory. The default
location for the current user on this system is:

	` + lfDefaultPath + `

This can be overridden if the -path option is used before the command. This
directory will be created and initialized the first time LF is used if it does
not already exist.
`)
}

//////////////////////////////////////////////////////////////////////////////

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

func doNodeStart(path string, jsonOutput bool, verboseOutput bool, args []string) {
}

func doProxyStart(path string, jsonOutput bool, urlOverride string, verboseOutput bool, args []string) {
}

func doConfig(path string, jsonOutput bool, args []string) {
}

func doSet(path string, jsonOutput bool, urlOverride string, verboseOutput bool, args []string) {
}

func doGet(path string, jsonOutput bool, urlOverride string, verboseOutput bool, args []string) {
}

func doFind(path string, jsonOutput bool, urlOverride string, verboseOutput bool, args []string) {
}

func doOwner(path string, jsonOutput bool, verboseOutput bool, args []string) {
}

func doStatus(path string, jsonOutput bool, urlOverride string, verboseOutput bool, args []string) {
}

func main() {
	globalOpts := flag.NewFlagSet("global", flag.ContinueOnError)
	path := globalOpts.String("path", lfDefaultPath, "")
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

	switch args[1] {

	case "help":
		if len(args) == 3 {
			printHelp(args[2])
		} else {
			printHelp("")
		}

	case "version":
		fmt.Println(lf.VersionStr)

	case "node-start":
		doNodeStart(*path, *jsonOutput, *verboseOutput, cmdArgs)

	case "proxy-start":
		doProxyStart(*path, *jsonOutput, *urlOverride, *verboseOutput, cmdArgs)

	case "config":
		doConfig(*path, *jsonOutput, cmdArgs)

	case "set":
		doSet(*path, *jsonOutput, *urlOverride, *verboseOutput, cmdArgs)

	case "get":
		doGet(*path, *jsonOutput, *urlOverride, *verboseOutput, cmdArgs)

	case "find":
		doFind(*path, *jsonOutput, *urlOverride, *verboseOutput, cmdArgs)

	case "owner":
		doOwner(*path, *jsonOutput, *verboseOutput, cmdArgs)

	case "status":
		doStatus(*path, *jsonOutput, *urlOverride, *verboseOutput, cmdArgs)

	case "selftest":
		test := ""
		if len(cmdArgs) == 1 {
			test = cmdArgs[0]
		} else {
			printHelp("")
		}
		switch test {
		case "":
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

	default:
		printHelp("")

	}
}
