# fgsniffer
Convert Fortigates "diagnose sniffer" output to pcap files  

## The scope
Some FortiGate Models like the FG100E don't have a disk that is required to use the WebUIs "Packet Capture" menu that creates pcap files automatically. The workaround is to use the CLI and create a verbose output and convert this with a Perl script. That didn't work for me so I created this tool. The small binary converts session logs to pcap files that can be opened with wireshark.

## How to create a pcap
### Create a log file
It dependings on your ssh client how logs are created. 
#### Linux/openssh
Linux saves you the conversion step and redirects the openssh output directly to the tool. I assume your fgsniffer binary lies in your current path.
```
ssh admin@10.10.10.1 | tee >(./fgsniffer)
```
#### Windows/Putty
In the settings look for Session/Logging. Check "Printable Output" and click "Browse" to save the putty.log to somewhere you find it.
Now connect to your firewall.
#### SecureCRT
Click in the menu "Options" the item "Session Options...". You find the "Log File" under "Teminal".
Now connect to your firewall.

### On the FortiGate
We need to run the sniffer command with some special parameters in detail
`diagnose sniffer packet <interface> '<filter>' <3|6> <count> a`
The options meanings are
- `<interface>` The interface name or 'any'
- `<filter>` A tcpdump compatible input filter 
- `<3|6>` The verbosity level. '6' adds the interface name. See below.
- `<count>` Stop after the amount of packets or '0'  
- `a` Output the absolute UTC time

### Convert the output (Windows only)
Go to the folder where you saved your session log. I assume your fgsniffer.exe lies here too.
```
PS C:\Users\dirk\temp> fgsniffer putty.log
created output file fgsniffer.pcap
```
### Open with wireshark
You find one ore more pcap files in your current path.

## The verbosity level
If you need to follow a packet through the box you can use level '6' and the interface 'any'. fgsniffer will create a file for every interface so you don't loose this information. 
