// Copyright 2017 github.com/DirkDuesentrieb
// license that can be found in the LICENSE file.

// a converter for FortiGate session logs to pcap files
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	globalHeader string = "d4c3b2a1020004000000000000000000ee05000001000000"
	info         string = "\nfgsniffer\n\nConvert text captures to pcap files. On the fortigate use\n\tdiagnose sniffer packet <interface> '<filter>' <3|6> <count> a\nto create a parsable dump.\n\n"
	unsafe       string = "[]{}/\\*"
)

type (
	pcaps struct {
		pcap map[string]int
	}
	packet struct {
		data     string // raw hex data
		size     int64
		secs, ms int64  // the packets timestamp
		port     string // the network port (verbose=6)
	}
)

func main() {
	var scanner *bufio.Scanner
	var p packet
	now := time.Now()

	if len(os.Args) == 2 {
		if os.Args[1] == "-?" || os.Args[1] == "-h" {
			fmt.Println(info)
			os.Exit(0)
		} else {
			f, err := os.Open(os.Args[1])
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			scanner = bufio.NewScanner(f)
		}
	} else {
		scanner = bufio.NewScanner(os.Stdin)
	}
	hexLine := regexp.MustCompile("^0x([0-9a-f]+)[ |\t]+(.*$)")
	// absolute time
	headLineA := regexp.MustCompile("^([0-9-]+ [0-9][0-9]:[0-9][0-9]:[0-9][0-9])\\.([0-9]+) .*$")
	// relative time
	headLineR := regexp.MustCompile("^([0-9]+)\\.([0-9]+) .*$")
	// verbose mode 6
	headLine6 := regexp.MustCompile("\\.[0-9]+ ([^ ]+) (in|out|--) ")

	pcps := pcaps{make(map[string]int)}

	for scanner.Scan() {
		date := ""
		mseconds := ""
		iface := ""
		match := false
		line := scanner.Text()
		hexData := hexLine.FindStringSubmatch(line)

		// packet header with absolute time
		header := headLineA.FindStringSubmatch(line)
		if len(header) == 3 {
			match = true
			date = header[1]
			mseconds = header[2]
		}
		// packet header with relative time
		header = headLineR.FindStringSubmatch(line)
		if len(header) == 3 {
			match = true
			sec, err := time.ParseDuration(header[1] + "s")
			if err != nil {
				fmt.Println("time.ParseDuration("+header[1]+")", err)
			}
			date = now.Add(sec).In(time.UTC).Format("2006-01-02 15:04:05")
			mseconds = header[2]
		}
		// verbose mode 6
		header = headLine6.FindStringSubmatch(line)
		if match && len(header) == 3 {
			iface = header[1]
		}
		if match {
			pcps.addPacket(p)
			p = newPacket(date, mseconds, iface)
		}

		// packet hex data
		if len(hexData) == 3 {
			p.addData(strings.Replace(hexData[2][:39], " ", "", -1))
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	// clean up
	pcps.addPacket(p)
	for name, packets := range pcps.pcap {
		fmt.Println("created output file", name, "with", packets, "packets.")
	}
}

// create file, add global header
func (pcps *pcaps) newPcap(name string) (err error) {
	err = ioutil.WriteFile(name, nil, 0644)
	if err != nil {
		fmt.Println(err)
	}
	err = appendStringToFile(name, globalHeader)
	if err != nil {
		fmt.Println(err)
	}
	return err
}

// create a new packet. We need some data from the header
func newPacket(date, mseconds, iface string) packet {
	t, _ := time.Parse("2006-01-02 15:04:05", date)
	ms, _ := strconv.ParseInt(mseconds, 10, 64)
	return packet{"", 0, t.Unix(), ms, iface}
}

// add a data line to the packet
func (p *packet) addData(data string) {
	p.size += int64(len(data) / 2)
	p.data += data
}

// all hex lines complete, write the packet to the pcap
func (pcps *pcaps) addPacket(p packet) {
	if p.size == 0 {
		return
	}
	fname := "fgsniffer"
	if p.port != "" {
		for i := 0; i < len(unsafe); i++ {
			p.port = strings.Replace(p.port, string(unsafe[i]), "_", -1)
		}
		fname += "-" + p.port
	}
	fname += ".pcap"
	_, found := pcps.pcap[fname]
	if !found {
		pcps.pcap[fname] = 0
		_ = pcps.newPcap(fname)
	}
	header := switchEndian(p.secs) + switchEndian(p.ms) + switchEndian(p.size) + switchEndian(p.size)
	err := appendStringToFile(fname, header+p.data)
	if err != nil {
		fmt.Println(err)
	}
	pcps.pcap[fname]++
}

// 11259375 -> 00abcdef -> efcdab00
func switchEndian(n int64) (r string) {
	b := fmt.Sprintf("%08x", n)
	for i := 0; i < 4; i++ {
		start := 6 - 2*i
		r = r + b[start:start+2]
	}
	return
}

// convert the hex data in string to binary and write it to file
func appendStringToFile(file, text string) error {
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		return err
	}
	defer f.Close()
	src := []byte(text)
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err = hex.Decode(dst, src)
	if err != nil {
		return err
	}
	_, err = f.Write(dst)
	if err != nil {
		return err
	}
	return nil
}
