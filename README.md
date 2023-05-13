# flyingroutes
![Python3.10](https://camo.githubusercontent.com/2eeb8947056ba0c1c3b1f9015ce807d0f0f462f99dce4c6acdcc7874f27b1820/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f707974686f6e2d332e31302d626c75652e737667)  
---  
A faster Python 3 implementation of the famous *traceroute* tool by using asynchronous TTL probing with either UDP, TCP or ICMP, or even all of them at the same time! Unprivileged sockets are used when possible depending on the platform, otherwise privilege sockets are used. 
  
You don't have to wait anymore for your *traceroute* command to end as you get instantaneous results!  
You can optimize your chances of better discovery with multiple protocols used at the same time!  

Traditional ***traceroute***:  
![Traditional *traceroute*](traceroute.png?raw=true "Traditional *traceroute*")
 
***flyingroutes***:  
![Traditional *flyingroutes*](flyingroutes.png?raw=true "Traditional *flyingroutes*")

## Features

* Asynchronous faster hop discovery.
* Support of the specification of the maximum number of hops to discover. 
* Support of ICMP, UDP and TCP protocols.
* Support of latency (response time) calculation per hop.
* Support of the usage all protocols (ICMP, UDP and TCP) used in parallel for better discovery.
* Support of the port specification for TCP and UDP.
* Support of multiple path discovery by sending multiple packets per hop.
* Support of timeout specification for hop discovery.
* Support of Linux and MacOS (Windows still under development).

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
$ python3 flyingroutes.py -h
usage: flyingroutes.py [-h] [--number_of_hops NUMBER_OF_HOPS] [--protocol PROTOCOL] [--dest_port DEST_PORT] [--timeout TIMEOUT] [--repeat REPEAT] HOST

positional arguments:
  HOST                  target host

options:
  -h, --help            show this help message and exit
  --number_of_hops NUMBER_OF_HOPS, -n NUMBER_OF_HOPS
                        Max number of hops allowed to reach the target (default: 30)
  --protocol PROTOCOL, -p PROTOCOL
                        Protocol to use: ICMP, UDP, TCP or ALL of them (default: ICMP)
  --dest_port DEST_PORT, -d DEST_PORT
                        Port to use for UDP and TCP only (default: 33434), increased by 1 for each additional packets sent with the --repeat option
  --timeout TIMEOUT, -t TIMEOUT
                        Timeout for responses (default: 3s for UDP, 5s for TCP)
  --repeat REPEAT, -r REPEAT
                        Number of packets to repeat per TTL value increase using different destination ports (default: 3, max: 16)
```

You might need to run ***flyingroutes*** with high privileges depending on the platform and protocol.  

## Examples
```
$ python3 flyingroutes.py thibautprobst.fr 
flyingroutes to thibautprobst.fr (99.86.91.20) with 30 hops max (3 packets per hop) on ICMP with a timeout of 3s
thibautprobst.fr (99.86.91.20) reached in 18 hops
Hop 1: 192.168.1.254 (4.28ms)
Hop 2: 80.10.237.205 (9.12ms)
Hop 3: 193.253.84.82 (13.97ms)
Hop 4: 193.253.83.242 (14.11ms)
Hop 5: 193.252.160.49 (18.49ms)
Hop 6: 193.252.137.18 (18.41ms)
Hop 7: 193.251.248.38 (20.59ms)
Hop 8: * * * * * * *
Hop 9: * * * * * * *
Hop 10: * * * * * * *
Hop 11: * * * * * * *
Hop 12: * * * * * * *
Hop 13: * * * * * * *
Hop 14: * * * * * * *
Hop 15: * * * * * * *
Hop 16: * * * * * * *
Hop 17: * * * * * * *
Hop 18: 99.86.91.20 (24.45ms)
```
```
$ python3 flyingroutes.py thibautprobst.fr -p all
flyingroutes to thibautprobst.fr (99.86.91.101) with 30 hops max (3 packets per hop) on ICMP, UDP port 33434 and TCP port 33434 with a timeout of 3s
thibautprobst.fr (99.86.91.101) reached in 18 hops
Hop 1: 192.168.1.254 (ICMP: 11.26ms, UDP: 14.64ms, TCP: 11.01ms)
Hop 2: 80.10.237.205 (ICMP: 13.71ms, UDP: 13.52ms)
Hop 3: 193.253.84.82 (ICMP: 9.47ms, UDP: 9.42ms)
Hop 4: 193.253.83.242 (ICMP: 36.95ms, UDP: 36.97ms, TCP: 36.67ms)
Hop 5: 193.252.160.49 (ICMP: 35.7ms, UDP: 35.68ms, TCP: 35.33ms)
Hop 6: 193.252.137.18 (ICMP: 34.43ms, UDP: 34.37ms, TCP: 34.17ms)
Hop 7: 193.251.248.148 (ICMP: 33.06ms, TCP: 32.81ms), 193.251.249.168 (UDP: 33.52ms), 99.83.114.168 (UDP: 33.22ms), 193.251.248.36 (TCP: 33.49ms), 193.251.248.38 (TCP: 33.24ms)
Hop 8: * * * * * * * (ICMP, UDP and TCP)
Hop 9: * * * * * * * (ICMP, UDP and TCP)
Hop 10: * * * * * * * (ICMP, UDP and TCP)
Hop 11: * * * * * * * (ICMP, UDP and TCP)
Hop 12: * * * * * * * (ICMP, UDP and TCP)
Hop 13: * * * * * * * (ICMP, UDP and TCP)
Hop 14: * * * * * * * (ICMP, UDP and TCP)
Hop 15: * * * * * * * (ICMP, UDP and TCP)
Hop 16: * * * * * * * (ICMP, UDP and TCP)
Hop 17: * * * * * * * (ICMP, UDP and TCP)
Hop 18: 99.86.91.101 (ICMP: 20.97ms)
```
```
$ python3 flyingroutes.py example.com -n 15 -p udp -r 2 -t 1
flyingroutes to example.com (93.184.216.34) with 15 hops max (2 packets per hop) on UDP port 33434 with a timeout of 1s
example.com (93.184.216.34) reached in 13 hops
Hop 1: 192.168.1.254 (3.93ms)
Hop 2: 80.10.237.205 (8.18ms)
Hop 3: 193.253.84.82 (8.05ms)
Hop 4: 193.253.83.242 (7.99ms)
Hop 5: 193.252.160.49 (13.19ms)
Hop 6: 193.252.137.18 (19.38ms)
Hop 7: 129.250.66.144 (19.32ms)
Hop 8: 129.250.2.178 (19.21ms)
Hop 9: 129.250.6.6 (97.17ms), 129.250.4.194 (92.56ms)
Hop 10: 129.250.6.97 (92.52ms), 129.250.3.51 (92.46ms)
Hop 11: 129.250.192.86 (96.93ms), 128.241.1.90 (92.37ms)
Hop 12: 152.195.65.129 (96.84ms), 152.195.68.131 (92.4ms)
Hop 13: 93.184.216.34 (96.43ms)
```
```
$ python3 flyingroutes.py example.com -n 15 -p all -r 2 -t 1
flyingroutes to example.com (93.184.216.34) with 15 hops max (2 packets per hop) on ICMP, UDP port 33434 and TCP port 33434 with a timeout of 1s
example.com (93.184.216.34) reached in 13 hops
Hop 1: 192.168.1.254 (ICMP: 5.63ms, UDP: 4.12ms, TCP: 3.92ms)
Hop 2: 80.10.237.205 (ICMP: 6.4ms, UDP: 6.37ms)
Hop 3: 193.253.84.82 (ICMP: 9.73ms, UDP: 9.72ms)
Hop 4: 193.253.83.242 (ICMP: 8.97ms, UDP: 8.98ms, TCP: 8.81ms)
Hop 5: 193.252.160.49 (ICMP: 14.87ms, UDP: 14.78ms, TCP: 14.69ms)
Hop 6: 193.252.137.18 (ICMP: 18.39ms, UDP: 18.33ms, TCP: 18.15ms)
Hop 7: 129.250.66.144 (ICMP: 19.39ms, UDP: 19.24ms, TCP: 19.21ms)
Hop 8: 129.250.2.178 (ICMP: 18.63ms, UDP: 18.6ms, TCP: 18.43ms), 129.250.2.106 (TCP: 18.26ms)
Hop 9: 129.250.3.46 (ICMP: 20.58ms, UDP: 20.54ms, TCP: 20.38ms), 129.250.6.6 (UDP: 99.43ms, TCP: 100.49ms)
Hop 10: 129.250.6.6 (ICMP: 99.5ms, UDP: 99.43ms), 129.250.3.242 (TCP: 103.45ms), 129.250.2.145 (TCP: 99.52ms)
Hop 11: 129.250.2.36 (ICMP: 98.03ms, TCP: 98.48ms), 129.250.192.86 (UDP: 102.15ms), 129.250.192.98 (TCP: 98.75ms)
Hop 12: 129.250.6.117 (ICMP: 94.04ms, TCP: 96.02ms), 152.195.64.129 (UDP: 93.82ms, TCP: 93.69ms)
Hop 13: 129.250.6.97 (ICMP: 95.91ms, TCP: 98.89ms), 93.184.216.34 (UDP: 96.66ms), 129.250.3.17 (TCP: 98.71ms)
```
```
$ python3 flyingroutes.py thibautprobst.fr -p tcp -d 443 -n 20 -r 8 -t 1
flyingroutes to thibautprobst.fr (99.86.91.20) with 20 hops max (8 packets per hop) on TCP port 443 with a timeout of 1s
thibautprobst.fr (99.86.91.20) reached in 18 hops
Hop 1: 192.168.1.254 (5.4ms)
Hop 2: * * * * * * *
Hop 3: * * * * * * *
Hop 4: 193.253.83.242 (10.04ms)
Hop 5: 193.252.160.49 (17.86ms)
Hop 6: 193.252.137.18 (19.95ms)
Hop 7: 193.251.248.38 (45.51ms), 193.251.248.148 (26.53ms), 193.251.248.36 (20.41ms), 193.251.249.168 (20.28ms), 99.83.114.168 (19.51ms)
Hop 8: * * * * * * *
Hop 9: * * * * * * *
Hop 10: * * * * * * *
Hop 11: * * * * * * *
Hop 12: * * * * * * *
Hop 13: * * * * * * *
Hop 14: * * * * * * *
Hop 15: * * * * * * *
Hop 16: * * * * * * *
Hop 17: * * * * * * *
Hop 18: 99.86.91.20
```
```
$ python3 flyingroutes.py thibautprobst.fr -p all -d 443 -n 20 -r 8 -t 1
flyingroutes to thibautprobst.fr (99.86.91.20) with 20 hops max (8 packets per hop) on ICMP, UDP port 443 and TCP port 443 with a timeout of 1s
thibautprobst.fr (99.86.91.20) reached in 18 hops
Hop 1: 192.168.1.254 (ICMP: 5.09ms, UDP: 5.0ms, TCP: 4.73ms)
Hop 2: 80.10.237.205 (ICMP: 10.23ms)
Hop 3: 193.253.84.82 (ICMP: 8.16ms)
Hop 4: 193.253.83.242 (ICMP: 9.21ms, UDP: 9.32ms, TCP: 8.91ms)
Hop 5: 193.252.160.49 (ICMP: 18.3ms, UDP: 18.01ms, TCP: 17.72ms)
Hop 6: 193.252.137.18 (ICMP: 23.86ms, UDP: 22.75ms, TCP: 22.31ms)
Hop 7: 193.251.248.38 (ICMP: 19.62ms, UDP: 22.89ms), 99.83.114.168 (UDP: 23.3ms, TCP: 23.08ms), 193.251.248.148 (UDP: 22.03ms, TCP: 21.86ms), 193.251.249.168 (UDP: 21.82ms, TCP: 21.09ms), 193.251.248.36 (UDP: 21.44ms, TCP: 21.3ms)
Hop 8: * * * * * * * (ICMP, UDP and TCP)
Hop 9: * * * * * * * (ICMP, UDP and TCP)
Hop 10: * * * * * * * (ICMP, UDP and TCP)
Hop 11: * * * * * * * (ICMP, UDP and TCP)
Hop 12: * * * * * * * (ICMP, UDP and TCP)
Hop 13: * * * * * * * (ICMP, UDP and TCP)
Hop 14: * * * * * * * (ICMP, UDP and TCP)
Hop 15: * * * * * * * (ICMP, UDP and TCP)
Hop 16: * * * * * * * (ICMP, UDP and TCP)
Hop 17: * * * * * * * (ICMP, UDP and TCP)
Hop 18: 99.86.91.20 (ICMP: 19.2ms, TCP)
```
