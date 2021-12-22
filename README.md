# Zeek-Script
Each script scans the _pcap file_ looking for one of the main symptoms on the network that there is a command and control server. Therefore each script produces a _log file_ to show the results of its analysis. Note that disrupting C2 can prevent a malware infection from turning into a more serious incident such as a data breach. In fact, many large-scale cyberattacks were initially discovered when researchers noticed C2 activity.

## Goals
These scripts parse _pcap files_ and produce _log files_ (typical of Zeek). As objectives they have:
- looking for long connections, based on duration
- seeking persistent connections, base on times "talked" to each other
- count of equal-sized packets per connection
- geolocation of the IPs , with  *libmaxminddb* software and *GeoLite2 city* database
- count how many fully qualified domain names are associated with each domain
- check if there are any problems with SSL certificates, such as expired or self-signed
- check if there are any unexpected usage or unexpected application running across a well-known ports

## Documentation
At the following [link](https://github.com/Davide-Lotito/Zeek-Script/wiki) you can find complete documentation for Zeek installation and use of scripts.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/Davide-Lotito/Zeek-Script/blob/master/LICENSE)


