# fgsniffer
Convert Fortigates "diagnose sniffer" output to pcap files  

## The scope
Some FortiGate Models like the FG100E don't have a disk, so you can't use the WebUIs "Packet Capture" menu to create pcap files. The workaround is to use the CLI and create a verbose output and convert this with a Perl script. The Perl stuff didn't work for me so I created this tool. A compiled small binary converts session logs to pcap files that can be opened with wireshark.

## How to create a pcap
### 1 Create a log file
It depends on your ssh client how logs are created. 
#### Linux/openssh
Linux `tee` saves you step 3 and redirects the openssh output directly to the tool. I assume your fgsniffer binary lies in your current path. 10.10.10.1 is of course a placeholder for your firewall.
```
~ $ ssh 10.10.10.1 | tee >(./fgsniffer)
```
#### Linux/screen
`screen` has [a **log** command](https://www.gnu.org/software/screen/manual/html_node/Log.html) with the shortcut `Ctrl-a H`. The console output is saved into a file screenlog.X. Press `Ctrl-a H` again to stop logging.
#### Windows/Putty
In the settings look for Session/Logging. Check "Printable Output" and click "Browse" to save the putty.log to somewhere you find it.
Now connect to your firewall.
#### Windows/SecureCRT
Click in the menu "Options" the item "Session Options...". You find the "Log File" under "Teminal".
Now connect to your firewall.

### 2 Start the packet capture
On the firewall run the sniffer command with some special parameters. 
```
diagnose sniffer packet <interface> '<filter>' <3|6> <count> a
```
The options meanings are
- `<interface>` The interface name or 'any'
- `<filter>` A tcpdump compatible input filter 
- `<3|6>` The verbosity level. '6' adds the interface name. See below.
- `<count>` Stop after the amount of packets or '0'  
- `a` Output the absolute UTC time

#### Example
```
fw01 # diagnose sniffer packet any 'icmp' 6 10 a
interfaces=[any]
filters=[icmp]
2017-09-12 12:41:38.676846 inside in 10.134.190.2 -> 10.134.190.30: icmp: echo request
0x0000   0000 0000 0001 0023 e93e 7a38 0800 4500        .......#.>z8..E.
0x0010   0028 0000 4000 ff01 eaa7 0a86 be02 0a86        .(..@...........
 [cut]
```

### 3 Convert the output 
Go to the folder where you saved your session log. I assume fgsniffer lies here too.
```
fgsniffer putty.log
created output file fgsniffer.pcap
```

### 4 Open with wireshark
You find one ore more pcap files in your current path.

## The timestamp
It is a good idea to always add "a" to the sniffer options to have a proper time for your pcaps. Users who had forgotten this option where confused, why this tool isn't working for them. In the current version fgsniffer will accept relative times. The time shown in the pcap will be the current local time plus the deltas.  

## The verbosity level
If you limit your filter to one interface level '3' is fine. But if you need to follow a packet through the box you can use level '6' and the interface 'any'. fgsniffer will create a file for every interface so you don't loose this information. I recommend using '6' all of the time. 

## Installing fgsniffer
The tool is one statically linked binary. Installing is as simple as [download](https://github.com/DirkDuesentrieb/fgsniffer/releases), unzip and run.

## Compiling fgsniffer
If you haven't used GO before, please read https://golang.org/doc/install and set up the required GOPATH and GOBIN environment.
### Linux
```
go get github.com/DirkDuesentrieb/fgsniffer
go install $GOPATH/src/github.com/DirkDuesentrieb/fgsniffer/fgsniffer.go
```
### Windows (PowerShell)
```
go get github.com/DirkDuesentrieb/fgsniffer
go install $Env:GOPATH\src\github.com\DirkDuesentrieb\fgsniffer\fgsniffer.go
```
If your GOBIN is part of your global PATH you can run fgsniffer from anywhere in your filesystem.

### Fixing broken VPN captures
In some FortiOS versions captures on a VPN interface can not be parsed. The reason is a missing Ethernet-header. `fgsniffer` now has an option **-fixvpn** to create a dummy header.

## Review in 2020
fgsniffer still works with the latest firmware versions (currently 6.2), but the newer firmware versions have the feature to create pcaps directly via the GUI. That makes simple network debuggung much easier. 

Using fgsniffer is still necessary if you want to
- use an advanced capture filter (eg with `and` or `not`)
- capture more than 10000 packets
- capture on all interfaces
