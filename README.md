# Zeek-Script
These scripts parse pcap files and produce log files (typical of Zeek). As objectives they have:
- looking for long connections, based on duration
- seeking persistent connections
- count of equal-sized packets per connection
- geolocation of the IPs , with  *libmaxminddb* software and *GeoLite2 city* database
