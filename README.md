# Zeek-Script
Each script scans the _pcap file_ looking for one of the main symptoms on the network that there is a command and control server. Therefore each script produces a _log file_ to show the results of its analysis.

## Goals
These scripts parse _pcap files_ and produce _log files_ (typical of Zeek). As objectives they have:
- looking for long connections, based on duration
- seeking persistent connections
- count of equal-sized packets per connection
- geolocation of the IPs , with  *libmaxminddb* software and *GeoLite2 city* database
- count how many fully qualified domain names are associated with each domain
- check if there are any problems with SSL certificates, such as expired or self-signed
- check if there are any unexpected usage or unexpected application running across a well-known ports

## Documentation
At the following [link](https://github.com/Davide-Lotito/Zeek-Script/wiki) you can find complete documentation for Zeek installation and use of scripts.



