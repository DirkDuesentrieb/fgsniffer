# fgsniffer
Convert Fortigates "diagnose sniffer" output to pcap files  

## The scope
Some FortiGate Models like the FG100E don't have a disk, so cou can't use the WebUIs "Packet Capture" menu to create pcap files. The workaround is to use the CLI and create a verbose output and convert this with a Perl script. That didn't work for me so I created this tool. The small binary converts session logs to pcap files that can be opened with wireshark.

## How to create a pcap
### 1 Create a log file
It depends on your ssh client how logs are created. 
#### Linux/openssh
Linux `tee` saves you step 3 and redirects the openssh output directly to the tool. I assume your fgsniffer binary lies in your current path.
```
ssh admin@10.10.10.1 | tee >(./fgsniffer)
```
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
```


### 3 Convert the output (Windows only)
Go to the folder where you saved your session log. I assume your fgsniffer.exe lies here too.
```
PS C:\Users\dirk\temp> fgsniffer putty.log
created output file fgsniffer.pcap
```
### 4 Open with wireshark
You find one ore more pcap files in your current path.

## The verbosity level
If you need to follow a packet through the box you can use level '6' and the interface 'any'. fgsniffer will create a file for every interface so you don't loose this information. 
