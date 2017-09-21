# Suricata SecurityResource

Suricata is a free and open source network threat detection engine.

The Suricata engine is capable of real time intrusion detection (IDS), inline intrusion prevention (IPS), network security monitoring (NSM) and offline pcap processing.

Suricata inspects the network traffic using a powerful and extensive rules and signature language, and has powerful Lua scripting support for detection of complex threats.

The Suricata project and code is owned and supported by the Open Information Security Foundation (OISF), a non-profit foundation committed to ensuring Suricata’s development and sustained success as an open source project.

Suricata is provided in SoftFIRE on top of an Ubuntu VM, and the Suricata Resource offers following Services:

1. The Experimenters can statically define a list of rules that will be inspected by Suricata 
2. The Experimenters can view Suricata log messages on a dedicated dashboard
3. The Experimenters can exploits all Suricata features. 

The official documentation about Suricata can be found at <http://suricata.readthedocs.io/en/latest/>.

List of features: 

## TCP/IP engines

* Scalable flow engine
  * Full IPv6 support
  * Tunnel decoding
  * TCP stream engine
  * IP Defrag engine

## Protocol parsers
* Support for packet decoding of
  * IPv4, IPv6, TCP, UDP, SCTP, ICMPv4, ICMPv6, GRE, Ethernet, PPP, PPPoE, Raw, SLL, VLAN, QINQ, MPLS, ERSPAN
* App layer decoding of:
  * HTTP, SSL, TLS, SMB, SMB2, DCERPC, SMTP, FTP, SSH, DNS, Modbus, ENIP/CIP, DNP3, NFS, NTP

## HTTP engine
* Stateful HTTP parser built on libhtp
* HTTP request logger
* File identification, extraction and logging
* Per server settings — limits, personality, etc
* Keywords to match on (normalized) buffers:
  * uri and raw uri
  * headers and raw headers
  * cookie
  * user-agent
  * request body and response body
  * method, status and status code
  * host
  * request and response lines
  * and many more

## Detection engine
* Protocol keywords
* Multi-tenancy
* xbits – flowbits extension
* fast_pattern
* Rule profiling
* File matching
* multiple pattern matcher algorithms that can be selected
* extensive tuning options
* live rule reloads — use new rules w/o restarting Suricata
* delayed rules initialization
* Lua scripting
* Hyperscan integration

## Outputs

* Eve log, all JSON alert and event output
* Lua output scripts
* Redis support
* HTTP request logging
* TLS handshake logging
* Unified2 output — compatible with Barnyard2
* Alert fast log
* Alert debug log — for rule writers
* Traffic recording using pcap logger
* Prelude support
* drop log — netfilter style log of dropped packets in IPS mode
* syslog — alert to syslog
* stats — engine stats at fixed intervals
* File logging including MD5 checksum in JSON format
* Extracted file storing to disk
* DNS request/reply logger, including TXT data
* Signal based Log rotation
* Flow logging

## Alert/Event filtering

* per rule alert filtering and thresholding
* global alert filtering and thresholding
* per host/subnet thresholding and rate limiting settings

## Packet acquisition

* High performance capture
* Standard capture
* IPS mode
* Capture cards and specialized devices

## Multi Threading

* fully configurable threading — from single thread to dozens of threads
* precooked “runmodes”
* optional CPU affinity settings
* Use of fine grained locking and atomic operations for optimal performance
* Optional lock profiling

## IP Reputation

* loading of large amounts host based reputation data
* matching on reputation data in the rule language using the “iprep” keyword
* live reload support
* supports CIDR ranges

