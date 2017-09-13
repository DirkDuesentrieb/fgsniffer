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
	hexl         string = "^0x([0-9a-f]+)[ |\t]+(.*$)"
	headl3       string = "^([0-9-]+ [0-9][0-9]:[0-9][0-9]:[0-9][0-9])\\.([0-9]+) [0-9a-f.:]+ -> [0-9a-f.:]+: .*$"
	headl6       string = "^([0-9-]+ [0-9][0-9]:[0-9][0-9]:[0-9][0-9])\\.([0-9]+) ([a-zA-Z0-9_]+) (in|out) [0-9a-f.:]+ -> [0-9a-f.:]+: .*$"
	info         string = "\nfgsniffer\n\nConvert text captures to pcap files. On the fortigate use\n\tdiagnose sniffer packet <interface> '<filter>' <3|6> <count> a\nto create a parsable dump.\n\n"
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
	if len(os.Args) == 2 {
		if os.Args[1] == "-?" {
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
	hexLine := regexp.MustCompile(hexl)
	headLine3 := regexp.MustCompile(headl3)
	headLine6 := regexp.MustCompile(headl6)

	pcps := pcaps{make(map[string]int)}

	for scanner.Scan() {
		line := scanner.Text()
		hexData := hexLine.FindStringSubmatch(line)
		headData3 := headLine3.FindStringSubmatch(line)
		headData6 := headLine6.FindStringSubmatch(line)

		// packet header with verbose level 3 or 6
		if len(headData3) == 3 {
			pcps.addPacket(p)
			p = newPacket(headData3[1], headData3[2], "")
		}
		if len(headData6) == 5 {
			pcps.addPacket(p)
			p = newPacket(headData6[1], headData6[2], headData6[3])
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
	for name,_ := range pcps.pcap {
			fmt.Println("created output file",name)
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
