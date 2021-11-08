# Zeek-Script

## Introduction
These scripts parse pcap files and produce log files (typical of Zeek). As objectives they have:
- looking for long connections, based on duration
- seeking persistent connections
- count of equal-sized packets per connection
- geolocation of the IPs , with  *libmaxminddb* software and *GeoLite2 city* database
- count how many fully qualified domain names are associated with each domain
- check if there are any problems with SSL certificates, such as expired or self-signed
- check if there are any unexpected usage or unexpected application running across a well-known ports





