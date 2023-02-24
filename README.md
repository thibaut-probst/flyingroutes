# flyingroutes
![Python3.10](https://camo.githubusercontent.com/2eeb8947056ba0c1c3b1f9015ce807d0f0f462f99dce4c6acdcc7874f27b1820/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f707974686f6e2d332e31302d626c75652e737667)  
---  
A faster Python 3 implementation of the famous *traceroute* tool by using asynchronous TTL probing with either UDP, TCP or ICMP. Unprivileged sockets are used when possible depending on the platform, otherwise privilege sockets are used. 
  
You don't have to wait anymore for your *traceroute* command to end as you get instantaneous results!  

Traditional ***traceroute***:  
![Traditional *traceroute*](traceroute.png?raw=true "Traditional *traceroute*")
 
***flyingroutes***:  
![Traditional *flyingroutes*](flyingroutes.png?raw=true "Traditional *flyingroutes*")

## Requirements

Make sure you have [Python 3.10 or higher](https://www.python.org/downloads/) installed.

## Installation 

#### Clone the repository to your working directory 
```
$ git clone https://github.com/thibaut-probst/flyingroutes.git
$ cd flyingroutes/
```
#### Optional: on Linux systems (since 2.6.39), you might need to update the ICMP parameters to allow ICMP sockets creation (***flyingroutes*** might use SOCK_DGRAM sockets to send UDP or ICMP messages) for a given range of the groups ID as by default no group is allowed to do so
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

You might need to run ***flyingroutes*** with high privileges depending on the platform and protocol.  
Note that the response time for each hop is only available for ICMP for now.

## Examples
```
$ python3 flyingroutes.py thibautprobst.fr 
flyingroutes to thibautprobst.fr (52.222.158.37) with 30 hops max on ICMP with a timeout of 3s
thibautprobst.fr (52.222.158.37) reached in 14 hops
Hop 1: 192.168.1.254 (3.96ms)
Hop 2: 80.10.237.205 (7.89ms)
Hop 3: 193.253.84.82 (9.61ms)
Hop 4: 193.253.83.242 (17.85ms)
Hop 5: 193.252.160.49 (17.8ms)
Hop 6: 193.252.137.18 (19.18ms)
Hop 7: 193.251.249.168 (19.08ms)
Hop 8: * * * * * * *
Hop 9: * * * * * * *
Hop 10: * * * * * * *
Hop 11: * * * * * * *
Hop 12: * * * * * * *
Hop 13: * * * * * * *
Hop 14: 52.222.158.37 (23.36ms)
```
```
$ python3 flyingroutes.py example.com -n 15 -p udp -r 2 -t 1
flyingroutes to example.com (93.184.216.34) with 15 hops max (2 packets per hop) on UDP port 33434 with a timeout of 1s
example.com (93.184.216.34) reached in 14 hops
Hop 1: 192.168.1.254 (4.12ms)
Hop 2: 80.10.237.205 (3.87ms)
Hop 3: 193.253.84.82 (6.31ms)
Hop 4: 193.253.83.242 (6.13ms)
Hop 5: 193.252.160.49 (13.98ms)
Hop 6: 193.252.160.46 (13.81ms)
Hop 7: 193.252.137.14 (19.29ms)
Hop 8: 129.250.66.141 (33.36ms)
Hop 9: 129.250.2.150 (19.13ms)
Hop 10: 129.250.6.6 (95.89ms)
Hop 11: 129.250.2.145 (97.77ms), 129.250.3.242 (95.77ms)
Hop 12: 129.250.192.86 (97.69ms), 128.241.1.90 (90.13ms)
Hop 13: 152.195.65.129 (98.28ms), 152.195.64.129 (97.56ms)
Hop 14: 93.184.216.34 (91.74ms)
```
```
$ python3 flyingroutes.py thibautprobst.fr -p tcp -d 443 -n 20 -r 8 -t 1
flyingroutes to thibautprobst.fr (52.222.158.37) with 20 hops max (8 packets per hop) on TCP port 443 with a timeout of 1s
thibautprobst.fr (52.222.158.37) reached in 13 hops
Hop 1: 192.168.1.254
Hop 2: * * * * * * *
Hop 3: * * * * * * *
Hop 4: 193.253.83.242
Hop 5: 193.252.160.49
Hop 6: 193.252.137.18
Hop 7: 99.83.114.168, 193.251.248.38, 193.251.248.148, 193.251.249.168, 193.251.248.36
Hop 8: * * * * * * *
Hop 9: * * * * * * *
Hop 10: * * * * * * *
Hop 11: * * * * * * *
Hop 12: * * * * * * *
Hop 13: 52.222.158.37
```
