# flyingroutes
![Python3.10](https://camo.githubusercontent.com/2eeb8947056ba0c1c3b1f9015ce807d0f0f462f99dce4c6acdcc7874f27b1820/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f707974686f6e2d332e31302d626c75652e737667)  
---  
A faster Python 3 implementation of the famous *traceroute* tool by using asynchronous TTL probing with either UDP, TCP or ICMP and from unprivileged users (no need to be root). 
  
You don't have to wait anymore for your *traceroute* command to end as you get instantaneous results!

## Requirements

Make sure you have [Python 3.10 or higher](https://www.python.org/downloads/) installed.

## Installation 

#### Clone the repository to your working directory 
```
$ git clone https://github.com/thibaut-probst/flyingroutes.git
$ cd flyingroutes/
```
#### Optional: on Linux systems (since 2.6.39), you might need to update the ICMP parameters to allow ICMP sockets creation (***flyingroutes*** uses SOCK_DGRAM ICMP sockets) for a given range of the groups ID as by default no group is allowed to do so
```
$ sudo sysctl -w "net.ipv4.ping_group_range= 0 2147483647"
```

## Usage 

You can display ***flyingroutes*** startup parameters information by using the --help argument: 

```
$ python3 flyingroutes.py --help
usage: flyingroutes.py [-h] [--number_of_hops NUMBER_OF_HOPS] [--protocol PROTOCOL] [--dest_port DEST_PORT] [--timeout TIMEOUT] [--repeat REPEAT] HOST

positional arguments:
  HOST                  target host

options:
  -h, --help            show this help message and exit
  --number_of_hops NUMBER_OF_HOPS, -n NUMBER_OF_HOPS
                        Max number of hops allowed to reach the target (default: 30)
  --protocol PROTOCOL, -p PROTOCOL
                        Protocol to use: ICMP, UDP or TCP (default: ICMP)
  --dest_port DEST_PORT, -d DEST_PORT
                        Port to use for UDP and TCP only (default: 33434), increased by 1 for each additional packets sent with the --repeat option
  --timeout TIMEOUT, -t TIMEOUT
                        Timeout for responses (default: 3s)
  --repeat REPEAT, -r REPEAT
                        Number of packets to repeat per TTL value increase using different destination ports (default: 3, max: 16)
```
            
## Examples
```
$ python3 flyingroutes.py thibautprobst.fr 
flyingroutes to thibautprobst.fr (52.222.158.89) with 30 hops max (3 packets per hop) on ICMP with a timeout of 3s 
thibautprobst.fr (52.222.158.89) reached in 15 hops 
Hop 1: 192.168.1.254
Hop 2: 80.10.237.205
Hop 3: 193.253.84.82
Hop 4: 193.253.83.242
Hop 5: 193.252.160.49
Hop 6: 193.252.137.18
Hop 7: 99.83.114.168
Hop 8: * * * * * * *
Hop 9: * * * * * * *
Hop 10: * * * * * * *
Hop 11: * * * * * * *
Hop 12: * * * * * * *
Hop 13: * * * * * * *
Hop 14: * * * * * * *
Hop 15: 52.222.158.89
```
```
$ python3 flyingroutes.py example.com -n 15 -p udp -r 2 -t 3
flyingroutes to example.com (93.184.216.34) with 15 hops max (2 packets per hop) on UDP port 33434 with a timeout of 3s
example.com (93.184.216.34) reached in 13 hops
Hop 1: 192.168.1.254
Hop 2: 80.10.237.205
Hop 3: 193.253.84.82
Hop 4: 193.253.83.242
Hop 5: 193.252.160.49
Hop 6: 193.252.137.18
Hop 7: * * * * * * *
Hop 8: 62.115.118.58, 62.115.118.62
Hop 9: 62.115.112.242, 62.115.122.159
Hop 10: 62.115.123.125, 62.115.123.123
Hop 11: 62.115.175.71
Hop 12: 152.195.64.129
Hop 13: 93.184.216.34
```
```
$ python3 flyingroutes.py thibautprobst.fr -p tcp -d 443 -n 20 -r 8
flyingroutes to thibautprobst.fr (52.222.158.37) with 20 hops max (8 packets per hop) on TCP port 443 with a timeout of 3s
thibautprobst.fr (52.222.158.37) reached in 14 hops
Hop 1: 192.168.1.254
Hop 2: * * * * * * *
Hop 3: * * * * * * *
Hop 4: 193.253.83.242
Hop 5: 193.252.160.49
Hop 6: 193.252.137.18
Hop 7: 99.83.114.168, 193.251.249.168, 193.251.248.38, 193.251.248.36, 193.251.248.148
Hop 8: * * * * * * *
Hop 9: * * * * * * *
Hop 10: * * * * * * *
Hop 11: * * * * * * *
Hop 12: * * * * * * *
Hop 13: * * * * * * *
Hop 14: 52.222.158.37
```
