---
noteId: "0b1f8f9014e811ee851bed8489314ff5"
tags: []

---

# flyingroutes
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11-blue)  
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
* Support of the option to specify of the maximum number of hops to discover.
* Support of latency (response time) calculation per hop.
* Support of name resolution displayed in results if available.
* Support of ICMP, UDP and TCP protocols.
* Support of the usage all protocols (ICMP, UDP and TCP) used in parallel for better discovery.
* Support of the option to specify the destination port for TCP and UDP.
* Support of multiple path discovery by allowing the sending multiple packets per hop.
* Support of the option to specify the timeout for hop discovery.
* Support of Windows, Linux and MacOS.

## Requirements

Make sure you have [Python 3.10 or higher](https://www.python.org/downloads/) and [pip](https://packaging.python.org/en/latest/tutorials/installing-packages/) installed.  

## Installation 

#### Clone the repository to your working directory 
```
$ git clone https://github.com/thibaut-probst/flyingroutes.git
$ cd flyingroutes/
```
#### Install the dependencies
```
$ pip install -r requirements.txt
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
                        Timeout for responses (default: 2s)
  --repeat REPEAT, -r REPEAT
                        Number of packets to repeat per TTL value increase using different destination ports (default: 3, max: 16)
```

You might need to run ***flyingroutes*** with high privileges depending on the platform and protocol.  

## Examples
```
$ python3 flyingroutes.py thibautprobst.fr 
flyingroutes to thibautprobst.fr (99.86.91.84) with 30 hops max (3 packets per hop) on ICMP with a timeout of 2.0s
thibautprobst.fr (99.86.91.84) reached in 20 hops
Hop 1:  192.168.1.254 (lan.home) - 4.08ms
Hop 2:  80.10.237.205 - 6.68ms
Hop 3:  193.253.84.82 (lag-10.neblc00z.rbci.orange.net) - 9.48ms
Hop 4:  193.253.83.242 (ae87-0.nctou201.rbci.orange.net) - 9.25ms
Hop 5:  193.252.160.49 (ae43-0.nipoi201.rbci.orange.net) - 13.84ms
Hop 6:  193.252.137.18 - 19.65ms
Hop 7:  193.251.249.168 - 19.52ms
Hop 8:  * * * * * * * *
Hop 9:  * * * * * * * *
Hop 10: * * * * * * * *
Hop 11: * * * * * * * *
Hop 12: * * * * * * * *
Hop 13: * * * * * * * *
Hop 14: * * * * * * * *
Hop 15: * * * * * * * *
Hop 16: * * * * * * * *
Hop 17: * * * * * * * *
Hop 18: * * * * * * * *
Hop 19: * * * * * * * *
Hop 20: 99.86.91.84 (server-99-86-91-84.cdg50.r.cloudfront.net) - 18.61ms
```
```
$ python3 flyingroutes.py thibautprobst.fr -p all
flyingroutes to thibautprobst.fr (54.230.112.104) with 30 hops max (1 packets per hop) on ICMP, UDP port 33434 and TCP port 33434 with a timeout of 2.0s
thibautprobst.fr (54.230.112.104) reached in 21 hops
Hop 1:  192.168.41.191 - ICMP: 39.92ms, UDP: 39.83ms, TCP: 39.59ms
Hop 2:  255.0.0.0 - ICMP: 57.34ms, UDP: 57.2ms, TCP: 56.93ms
Hop 3:  * * * * * * * * - ICMP, UDP and TCP
Hop 4:  255.0.0.1 - ICMP: 160.43ms, UDP: 160.27ms, TCP: 159.69ms
Hop 5:  255.0.0.2 - ICMP: 76.01ms
        255.0.0.4 - UDP: 132.48ms, TCP: 132.17ms
Hop 6:  255.0.0.3 - ICMP: 85.11ms
        10.216.10.65 - UDP: 169.85ms
Hop 7:  255.0.0.4 - ICMP: 68.35ms
        81.253.184.106 (ae31-760.ngesevir01.rbci.orange.net) - UDP: 150.83ms
Hop 8:  193.251.110.185 (ae31-0.nclyo201.rbci.orange.net) - UDP: 106.85ms
Hop 9:  193.252.101.145 (ae41-0.nilyo101.rbci.orange.net) - UDP: 108.51ms
Hop 10: 81.253.184.86 - UDP: 146.15ms
        193.252.101.65 (ae58-0.nilyo101.rbci.orange.net) - TCP: 127.85ms
Hop 11: 193.251.255.186 (amazon-34.gw.opentransit.net) - UDP: 169.31ms
        81.253.184.86 - TCP: 137.89ms
Hop 12: 81.253.184.86 - ICMP: 119.5ms
Hop 13: * * * * * * * * - ICMP, UDP and TCP
Hop 14: * * * * * * * * - ICMP, UDP and TCP
Hop 15: * * * * * * * * - ICMP, UDP and TCP
Hop 16: * * * * * * * * - ICMP, UDP and TCP
Hop 17: * * * * * * * * - ICMP, UDP and TCP
Hop 18: * * * * * * * * - ICMP, UDP and TCP
Hop 19: * * * * * * * * - ICMP, UDP and TCP
Hop 20: * * * * * * * * - ICMP, UDP and TCP
Hop 21: 54.230.112.104 (server-54-230-112-104.mrs52.r.cloudfront.net) - ICMP: 138.65ms
```
```
$ python3 flyingroutes.py example.com -n 20 -p udp -r 2 -t 1
flyingroutes to example.com (93.184.216.34) with 20 hops max (2 packets per hop) on UDP port 33434 with a timeout of 1.0s
example.com (93.184.216.34) reached in 13 hops
Hop 1:  192.168.1.254 (lan.home) - 4.15ms
Hop 2:  80.10.237.205 - 6.24ms
Hop 3:  193.253.84.82 (lag-10.neblc00z.rbci.orange.net) - 7.94ms
Hop 4:  193.253.83.242 (ae87-0.nctou201.rbci.orange.net) - 8.1ms
Hop 5:  193.252.160.49 (ae43-0.nipoi201.rbci.orange.net) - 14.43ms
Hop 6:  193.252.137.18 - 17.13ms
Hop 7:  129.250.66.144 (ae-26.a01.parsfr05.fr.bb.gin.ntt.net) - 17.19ms
Hop 8:  129.250.2.178 (ae-15.r20.parsfr04.fr.bb.gin.ntt.net) - 16.59ms
Hop 9:  129.250.6.6 (ae-13.r24.asbnva02.us.bb.gin.ntt.net) - 98.23ms
        129.250.4.194 (ae-14.r21.nwrknj03.us.bb.gin.ntt.net) - 95.81ms
Hop 10: 129.250.3.17 (ae-1.a02.nycmny17.us.bb.gin.ntt.net) - 98.46ms
        129.250.3.128 (ae-1.a03.nycmny17.us.bb.gin.ntt.net) - 95.41ms
Hop 11: 129.250.192.86 (ce-1-4-0.a04.asbnva02.us.ce.gin.ntt.net) - 97.49ms
        128.241.1.90 (ce-3-3-0.a03.nycmny17.us.ce.gin.ntt.net) - 95.73ms
Hop 12: 152.195.65.129 (ae-66.core1.dcb.edgecastcdn.net) - 110.58ms
        152.195.68.131 (ae-65.core1.nyb.edgecastcdn.net) - 95.46ms
Hop 13: 93.184.216.34 - 91.47ms
```
```
$ python3 flyingroutes.py example.com -n 18 -p all -r 2 -t 1
flyingroutes to example.com (93.184.216.34) with 18 hops max (2 packets per hop) on ICMP, UDP port 33434 and TCP port 33434 with a timeout of 1.0s
example.com (93.184.216.34) reached in 13 hops
Hop 1:  192.168.1.254 (lan.home) - ICMP: 8.11ms, UDP: 8.02ms, TCP: 7.93ms
Hop 2:  80.10.237.205 - ICMP: 10.5ms, UDP: 10.52ms
Hop 3:  193.253.84.82 (lag-10.neblc00z.rbci.orange.net) - ICMP: 10.15ms, UDP: 10.15ms
Hop 4:  193.253.83.242 (ae87-0.nctou201.rbci.orange.net) - ICMP: 10.39ms, UDP: 10.33ms, TCP: 10.21ms
Hop 5:  193.252.160.49 (ae43-0.nipoi201.rbci.orange.net) - ICMP: 13.84ms, UDP: 15.99ms, TCP: 15.42ms
Hop 6:  193.252.137.18 - ICMP: 23.77ms, UDP: 23.75ms, TCP: 23.61ms
Hop 7:  129.250.66.144 (ae-26.a01.parsfr05.fr.bb.gin.ntt.net) - ICMP: 22.55ms, UDP: 22.55ms, TCP: 22.43ms
Hop 8:  129.250.2.106 (ae-15.r21.parsfr04.fr.bb.gin.ntt.net) - TCP: 1027.31ms
Hop 9:  129.250.4.194 (ae-14.r21.nwrknj03.us.bb.gin.ntt.net) - ICMP: 93.82ms, UDP: 93.83ms, TCP: 94.07ms
        129.250.6.6 (ae-13.r24.asbnva02.us.bb.gin.ntt.net) - UDP: 99.99ms, TCP: 99.91ms
Hop 10: 129.250.3.17 (ae-1.a02.nycmny17.us.bb.gin.ntt.net) - ICMP: 94.51ms, UDP: 94.52ms
        129.250.2.145 (ae-0.a04.asbnva02.us.bb.gin.ntt.net) - TCP: 104.16ms
Hop 11: 128.241.1.14 (ce-0-3-0.a02.nycmny17.us.ce.gin.ntt.net) - ICMP: 95.95ms, UDP: 95.87ms
        129.250.192.86 (ce-1-4-0.a04.asbnva02.us.ce.gin.ntt.net) - UDP: 108.33ms
        129.250.192.98 (ce-1-1-3.a05.asbnva02.us.ce.gin.ntt.net) - TCP: 1099.17ms
        128.241.1.90 (ce-3-3-0.a03.nycmny17.us.ce.gin.ntt.net) - TCP: 99.81ms
Hop 12: 152.195.68.131 (ae-65.core1.nyb.edgecastcdn.net) - ICMP: 102.28ms
        152.195.64.129 (ae-65.core1.dcb.edgecastcdn.net) - UDP: 104.41ms, TCP: 104.34ms
        152.195.68.141 (ae-70.core1.nyb.edgecastcdn.net) - TCP: 99.88ms
Hop 13: 93.184.216.34 - ICMP: 100.32ms, UDP: 90.33ms
```
```
$ python3 flyingroutes.py thibautprobst.fr -p tcp -d 443 -n 20 -r 8 -t 4
flyingroutes to thibautprobst.fr (99.86.91.127) with 20 hops max (8 packets per hop) on TCP port 443 with a timeout of 4.0s
thibautprobst.fr (99.86.91.127) reached in 19 hops
Hop 1:  10.189.80.1 - 22.42ms
Hop 2:  77.199.118.249 (249.118.199.77.rev.sfr.net) - 45.89ms
Hop 3:  212.30.97.108 (108.97.30.212.rev.sfr.net) - 120.99ms
Hop 4:  77.136.172.218 (218.172.136.77.rev.sfr.net) - 149.59ms
Hop 5:  77.136.172.217 (217.172.136.77.rev.sfr.net) - 137.57ms
Hop 6:  194.6.146.57 (57.146.6.194.rev.sfr.net) - 186.33ms
Hop 7:  194.6.146.57 (57.146.6.194.rev.sfr.net) - 186.33ms
Hop 8:  99.83.65.104 - 166.5ms
Hop 9:  52.46.95.84 - 217.2ms
Hop 10: 15.230.82.226 - 235.63ms
Hop 11: 52.46.93.243 - 175.2ms
Hop 12: 52.95.60.62 - 221.77ms
Hop 13: 52.95.60.211 - 191.51ms
Hop 14: * * * * * * * *
Hop 15: * * * * * * * *
Hop 16: * * * * * * * *
Hop 17: * * * * * * * *
Hop 18: * * * * * * * *
Hop 19: 99.86.91.127 (server-99-86-91-127.cdg50.r.cloudfront.net) - 140.88ms
```
```
$ python3 flyingroutes.py thibautprobst.fr -p all -d 443 -n 20 -r 8 -t 3
flyingroutes to thibautprobst.fr (99.86.91.127) with 20 hops max (8 packets per hop) on ICMP, UDP port 443 and TCP port 443 with a timeout of 3.0s
thibautprobst.fr (99.86.91.127) reached in 19 hops
Hop 1:  10.189.80.1 - ICMP: 84.65ms, TCP: 84.38ms
Hop 2:  77.199.118.249 (249.118.199.77.rev.sfr.net) - ICMP: 88.91ms, TCP: 88.77ms
Hop 3:  212.30.97.108 (108.97.30.212.rev.sfr.net) - ICMP: 93.9ms, TCP: 93.71ms
Hop 4:  77.136.172.218 (218.172.136.77.rev.sfr.net) - ICMP: 77.38ms, TCP: 77.21ms
Hop 5:  77.136.172.217 (217.172.136.77.rev.sfr.net) - ICMP: 80.97ms, TCP: 80.68ms
Hop 6:  194.6.146.57 (57.146.6.194.rev.sfr.net) - ICMP: 98.65ms, TCP: 73.76ms
Hop 7:  194.6.146.57 (57.146.6.194.rev.sfr.net) - TCP: 73.76ms
Hop 8:  99.83.65.106 - ICMP: 77.08ms
        99.83.65.104 - TCP: 90.72ms
Hop 9:  52.46.95.134 - ICMP: 88.93ms
        52.46.95.76 - TCP: 132.11ms
Hop 10: 15.230.82.222 - ICMP: 114.41ms
        15.230.82.238 - TCP: 125.66ms
Hop 11: 52.46.93.243 - ICMP: 112.55ms
        52.46.93.241 - TCP: 105.2ms
Hop 12: 15.230.82.147 - ICMP: 85.7ms
        15.230.82.179 - TCP: 96.2ms
Hop 13: 52.95.60.205 - ICMP: 96.41ms
        52.95.60.207 - TCP: 89.14ms
Hop 14: * * * * * * * * - ICMP, UDP and TCP
Hop 15: * * * * * * * * - ICMP, UDP and TCP
Hop 16: * * * * * * * * - ICMP, UDP and TCP
Hop 17: * * * * * * * * - ICMP, UDP and TCP
Hop 18: * * * * * * * * - ICMP, UDP and TCP
Hop 19: 99.86.91.127 (server-99-86-91-127.cdg50.r.cloudfront.net) - ICMP: 54.14ms, TCP: 28.07ms
```
