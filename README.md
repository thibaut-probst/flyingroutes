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
                        Timeout for responses (default: 2s)
  --repeat REPEAT, -r REPEAT
                        Number of packets to repeat per TTL value increase using different destination ports (default: 3, max: 16)
```

You might need to run ***flyingroutes*** with high privileges depending on the platform and protocol.  

## Examples
```
$ python3 flyingroutes.py thibautprobst.fr 
flyingroutes to thibautprobst.fr (99.86.91.127) with 30 hops max (3 packets per hop) on ICMP with a timeout of 2.0s
thibautprobst.fr (99.86.91.127) reached in 19 hops
Hop 1:  10.189.80.1 - 22.41ms
Hop 2:  77.199.118.249 (249.118.199.77.rev.sfr.net) - 24.36ms
Hop 3:  212.30.97.108 (108.97.30.212.rev.sfr.net) - 45.61ms
Hop 4:  77.136.172.218 (218.172.136.77.rev.sfr.net) - 45.58ms
Hop 5:  77.136.172.217 (217.172.136.77.rev.sfr.net) - 42.31ms
Hop 6:  194.6.146.57 (57.146.6.194.rev.sfr.net) - 45.32ms
Hop 7:  * * * * * * * *
Hop 8:  99.83.65.106 - 43.77ms
Hop 9:  52.46.95.134 - 52.54ms
Hop 10: 15.230.82.222 - 35.32ms
Hop 11: 52.46.93.243 - 45.53ms
Hop 12: 15.230.82.147 - 42.17ms
Hop 13: 52.95.60.205 - 50.82ms
Hop 14: * * * * * * * *
Hop 15: * * * * * * * *
Hop 16: * * * * * * * *
Hop 17: * * * * * * * *
Hop 18: * * * * * * * *
Hop 19: 99.86.91.127 (server-99-86-91-127.cdg50.r.cloudfront.net) - 38.54ms
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
example.com (93.184.216.34) reached in 18 hops
Hop 1:  192.168.47.230 - 18.74ms
Hop 2:  255.0.0.0 - 61.69ms
Hop 3:  * * * * * * * *
Hop 4:  255.0.0.1 - 68.8ms
Hop 5:  255.0.0.4 - 63.61ms
Hop 6:  10.216.34.65 - 73.44ms
Hop 7:  81.253.184.38 (ae31-760.ngebagnr01.rbci.orange.net) - 61.68ms
Hop 8:  193.251.110.137 (ae31-0.ncidf103.rbci.orange.net) - 73.15ms
Hop 9:  193.252.159.41 (ae41-0.niidf101.rbci.orange.net) - 78.83ms
Hop 10: 193.252.137.10 - 81.63ms
Hop 11: 193.251.131.8 - 81.18ms
Hop 12: 129.250.66.144 (ae-26.a01.parsfr05.fr.bb.gin.ntt.net) - 84.48ms
Hop 13: 129.250.2.178 (ae-15.r20.parsfr04.fr.bb.gin.ntt.net) - 100.91ms
        129.250.2.106 (ae-15.r21.parsfr04.fr.bb.gin.ntt.net) - 94.19ms
Hop 14: 129.250.6.6 (ae-13.r24.asbnva02.us.bb.gin.ntt.net) - 162.17ms
        129.250.4.194 (ae-14.r21.nwrknj03.us.bb.gin.ntt.net) - 131.71ms
Hop 15: 129.250.2.145 (ae-0.a04.asbnva02.us.bb.gin.ntt.net) - 168.82ms
        129.250.6.97 (ae-11.r01.nycmny17.us.bb.gin.ntt.net) - 162.48ms
Hop 16: 128.241.1.90 (ce-0-13-0-3.r01.nycmny17.us.ce.gin.ntt.net) - 147.83ms
        129.250.192.98 (ce-1-1-3.a05.asbnva02.us.ce.gin.ntt.net) - 141.29ms
Hop 17: 152.195.64.129 (ae-65.core1.dcb.edgecastcdn.net) - 143.87ms
        152.195.65.129 (ae-66.core1.dcb.edgecastcdn.net) - 137.19ms
Hop 18: 93.184.216.34 - 119.56ms
```
```
$ python3 flyingroutes.py example.com -n 18 -p all -r 2 -t 1
flyingroutes to example.com (93.184.216.34) with 18 hops max (2 packets per hop) on ICMP, UDP port 33434 and TCP port 33434 with a timeout of 1.0s
example.com (93.184.216.34) reached in 18 hops
Hop 1:  192.168.47.230 - ICMP: 24.23ms, UDP: 24.22ms, TCP: 24.01ms
Hop 2:  255.0.0.0 - ICMP: 73.04ms, UDP: 73.0ms, TCP: 72.82ms
Hop 3:  * * * * * * * * - ICMP, UDP and TCP
Hop 4:  255.0.0.1 - ICMP: 67.05ms, UDP: 66.95ms, TCP: 66.73ms
Hop 5:  255.0.0.4 - ICMP: 157.02ms, UDP: 156.96ms, TCP: 156.79ms
Hop 6:  10.216.34.65 - UDP: 176.71ms
Hop 7:  81.253.184.38 (ae31-760.ngebagnr01.rbci.orange.net) - UDP: 176.36ms
Hop 8:  193.251.110.137 (ae31-0.ncidf103.rbci.orange.net) - UDP: 156.84ms
Hop 9:  193.252.159.41 (ae41-0.niidf101.rbci.orange.net) - UDP: 146.76ms
Hop 10: 193.252.137.10 - ICMP: 161.95ms, UDP: 161.92ms
        81.253.129.137 (ae40-0.niidf101.rbci.orange.net) - TCP: 148.02ms
Hop 11: 193.251.131.8 - ICMP: 127.12ms, UDP: 127.09ms
        193.252.137.10 - TCP: 154.6ms
Hop 12: 129.250.66.144 (ae-26.a01.parsfr05.fr.bb.gin.ntt.net) - UDP: 192.11ms
        193.251.131.8 - TCP: 123.17ms
Hop 13: 129.250.2.178 (ae-15.r20.parsfr04.fr.bb.gin.ntt.net) - UDP: 174.54ms
Hop 14: 129.250.4.194 (ae-14.r21.nwrknj03.us.bb.gin.ntt.net) - UDP: 208.44ms
Hop 15: 129.250.3.242 (ae-0.a05.asbnva02.us.bb.gin.ntt.net) - UDP: 214.56ms
Hop 16: 129.250.192.98 (ce-1-1-3.a05.asbnva02.us.ce.gin.ntt.net) - UDP: 241.59ms
        129.250.192.86 (ce-1-4-0.a04.asbnva02.us.ce.gin.ntt.net) - UDP: 231.3ms
Hop 17: 152.195.69.131 (ae-66.core1.nyb.edgecastcdn.net) - UDP: 236.26ms
        152.195.65.129 (ae-66.core1.dcb.edgecastcdn.net) - UDP: 224.48ms
Hop 18: 93.184.216.34 - ICMP: 208.55ms, UDP: 208.53ms
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
