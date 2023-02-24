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
Note that the response time for each hop is only available for ICMP and UDP for now.

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
flyingroutes to thibautprobst.fr (99.86.91.20) with 30 hops max (3 packets per hop) on ICMP, UDP port 33434 and TCP port 33434 with a timeout of 3s
thibautprobst.fr (99.86.91.20) reached in 18 hops
Hop 1: 192.168.1.254 (ICMP: 4.14ms, UDP: 4.02ms, TCP)
Hop 2: 80.10.237.205 (ICMP: 8.64ms, UDP: 6.15ms)
Hop 3: 193.253.84.82 (ICMP: 10.09ms, UDP: 8.19ms)
Hop 4: 193.253.83.242 (ICMP: 9.84ms, UDP: 13.09ms, TCP)
Hop 5: 193.252.160.49 (ICMP: 20.04ms, UDP: 22.48ms, TCP)
Hop 6: 193.252.137.18 (ICMP: 19.76ms, UDP: 27.38ms, TCP)
Hop 7: 193.251.248.38 (ICMP: 21.87ms, UDP: 27.13ms), 193.251.248.148 (UDP: 35.59ms, TCP), 193.251.248.36 (UDP: 35.44ms), 193.251.249.168 (TCP), 99.83.114.168 (TCP)
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
Hop 18: 99.86.91.20 (ICMP: 24.95ms)
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
Hop 1: 192.168.1.254 (ICMP: 4.98ms, UDP: 4.8ms, TCP)
Hop 2: 80.10.237.205 (ICMP: 10.34ms, UDP: 10.31ms)
Hop 3: 193.253.84.82 (ICMP: 9.88ms, UDP: 9.76ms)
Hop 4: 193.253.83.242 (ICMP: 11.3ms, UDP: 11.19ms, TCP)
Hop 5: 193.252.160.49 (ICMP: 16.06ms, UDP: 15.38ms, TCP)
Hop 6: 193.252.137.18 (ICMP: 21.11ms, UDP: 19.33ms, TCP)
Hop 7: 129.250.66.144 (ICMP: 20.77ms, UDP: 19.02ms, TCP)
Hop 8: 129.250.2.178 (ICMP: 27.77ms, UDP: 27.71ms, TCP), 129.250.2.106 (TCP)
Hop 9: 129.250.4.194 (ICMP: 93.85ms, UDP: 93.93ms, TCP), 129.250.6.6 (UDP: 100.1ms, TCP)
Hop 10: 129.250.3.51 (ICMP: 93.37ms, UDP: 95.12ms), 129.250.2.145 (TCP), 129.250.3.242 (TCP)
Hop 11: 128.241.1.14 (ICMP: 93.07ms, UDP: 94.86ms), 129.250.192.86 (UDP: 101.59ms), 129.250.192.98 (TCP), 128.241.1.90 (TCP)
Hop 12: 152.195.68.131 (ICMP: 94.44ms), 152.195.64.129 (UDP: 98.92ms, TCP), 152.195.68.141 (TCP)
Hop 13: 93.184.216.34 (ICMP: 92.34ms, UDP: 93.93ms)
```
```
$ python3 flyingroutes.py thibautprobst.fr -p tcp -d 443 -n 20 -r 8 -t 1
flyingroutes to thibautprobst.fr (99.86.91.101) with 20 hops max (8 packets per hop) on TCP port 443 with a timeout of 1s
thibautprobst.fr (99.86.91.101) reached in 18 hops
Hop 1: 192.168.1.254
Hop 2: * * * * * * *
Hop 3: * * * * * * *
Hop 4: 193.253.83.242
Hop 5: 193.252.160.49
Hop 6: 193.252.137.18
Hop 7: 99.83.114.168, 193.251.249.168, 193.251.248.36, 193.251.248.148, 193.251.248.38
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
Hop 18: 99.86.91.101
```
```
$ python3 flyingroutes.py thibautprobst.fr -p all -d 443 -n 20 -r 8 -t 1
flyingroutes to thibautprobst.fr (99.86.91.127) with 20 hops max (8 packets per hop) on ICMP, UDP port 443 and TCP port 443 with a timeout of 1s
thibautprobst.fr (99.86.91.127) reached in 18 hops
Hop 1: 192.168.1.254 (ICMP: 4.76ms, UDP: 4.61ms, TCP)
Hop 2: 80.10.237.205 (ICMP: 7.7ms)
Hop 3: 193.253.84.82 (ICMP: 6.6ms)
Hop 4: 193.253.83.242 (ICMP: 11.86ms, UDP: 11.49ms, TCP)
Hop 5: 193.252.160.49 (ICMP: 15.61ms, UDP: 18.67ms, TCP)
Hop 6: 193.252.137.18 (ICMP: 21.33ms, UDP: 24.56ms, TCP)
Hop 7: 193.251.249.168 (ICMP: 22.63ms, UDP: 36.22ms, TCP), 99.83.114.168 (UDP: 36.26ms, TCP), 193.251.248.36 (UDP: 36.15ms, TCP), 193.251.248.38 (UDP: 34.43ms, TCP), 193.251.248.148 (UDP: 34.37ms)
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
Hop 18: 99.86.91.127 (ICMP: 24.07ms, TCP)
```
