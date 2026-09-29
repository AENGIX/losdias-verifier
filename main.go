package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

var version = "0.1.0"

func main() {
	opt := options{}
	showVersion := false
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.StringVar(&opt.cdn, "cdn", defaultCDN, "CDN origin used when the argument is a broadcast id")
	flag.StringVar(&opt.pkg, "package", defaultPackage, "Android package the hardware attestation must name")
	flag.StringVar(&opt.appID, "app-id", defaultAppleID, "Apple team and bundle id, as TeamID.bundle")
	flag.StringVar(&opt.signingCert, "signing-cert", "", "PEM or DER app-signing certificate; its SHA-256 must be in the Android attestation")
	flag.BoolVar(&opt.json, "json", false, "print the report as JSON")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: losdias-verify [flags] <broadcast-id | validation.txt | url>\n\n")
		fmt.Fprintf(os.Stderr, "Checks a losdias spec 3.0.0 validation file: hardware attestation, segment hash chain,\n")
		fmt.Fprintf(os.Stderr, "assertion signatures, Cloudflare Roughtime, and capture continuity.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if showVersion {
		fmt.Printf("losdias-verify %s\n", version)
		return
	}
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	body, source, requestedID, err := loadInput(flag.Arg(0), opt.cdn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "losdias-verify: %s\n", err)
		os.Exit(1)
	}
	rep := verifyBroadcast(string(body), source, requestedID, opt)
	if opt.json {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(os.Stderr, "losdias-verify: %s\n", err)
			os.Exit(1)
		}
	} else {
		printReport(rep)
	}
	if !rep.OK {
		os.Exit(1)
	}
}

func loadInput(arg, cdn string) ([]byte, string, string, error) {
	if strings.Contains(arg, "://") {
		body, err := fetchBytes(arg)
		return body, arg, "", err
	}
	info, err := os.Stat(arg)
	if err == nil && !info.IsDir() {
		body, err := os.ReadFile(arg)
		return body, arg, "", err
	}
	if strings.ContainsAny(arg, `/\`) {
		return nil, "", "", fmt.Errorf("cannot read %s", arg)
	}
	source := strings.TrimRight(cdn, "/") + "/validations/" + arg + ".txt"
	body, err := fetchBytes(source)
	return body, source, arg, err
}

func printReport(rep report) {
	if rep.Broadcast != "" {
		fmt.Printf("%s  %s\n", paint("2", "broadcast"), rep.Broadcast)
	}
	if rep.Source != "" {
		fmt.Printf("%s  %s\n", paint("2", "source   "), rep.Source)
	}
	fmt.Println()
	for _, item := range rep.Checks {
		fmt.Printf("%s  %-16s  %s\n", paint(statusStyle(item.Status), fmt.Sprintf("%-4s", item.Status)), item.Name, item.Detail)
	}
	fmt.Println()
	if rep.OK {
		for _, item := range rep.Checks {
			if item.Status == "WARN" {
				fmt.Println(paint(statusStyle("WARN"), "result PASS, with warnings"))
				return
			}
		}
		fmt.Println(paint(statusStyle("PASS"), "result PASS"))
		return
	}
	fmt.Println(paint(statusStyle("FAIL"), "result FAIL"))
}

func statusStyle(status string) string {
	switch status {
	case "PASS":
		return "1;32"
	case "WARN":
		return "1;38;5;208"
	case "FAIL":
		return "1;31"
	case "NOTE":
		return "2"
	default:
		return ""
	}
}

func paint(style, text string) string {
	if style == "" || !stdoutColor() {
		return text
	}
	return "\033[" + style + "m" + text + "\033[0m"
}

func stdoutColor() bool {
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled {
		return false
	}
	if strings.EqualFold(os.Getenv("CLICOLOR_FORCE"), "1") || strings.EqualFold(os.Getenv("LOSDIAS_COLOR"), "always") {
		return true
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
