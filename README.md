# Zeek-Script

## Introduction
These scripts parse pcap files and produce log files (typical of Zeek). As objectives they have:
- looking for long connections, based on duration
- seeking persistent connections
- count of equal-sized packets per connection
- geolocation of the IPs , with  *libmaxminddb* software and *GeoLite2 city* database

## Getting Started
### Dependencies

` ZEEK 4.0 or greater`

### Install Zeek Dependencies

`sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev`

### Install libmaxminddb

`sudo apt-get install libmaxminddb-dev`

### GeoLite2-City Database Installation
Zeek can use the city or country database. The city database includes cities and regions in addition to countries. First, [signup](https://www.maxmind.com/en/geolite2/signup) for a MaxMind account, which is now required to [download](https://www.maxmind.com/en/accounts/current/geoip/downloads) even free/public GeoIP databases. Then, you can download databases. For example, download the GeoLite2-City database and decompress it. 

Next, the file GeoLite2-City_YYYYMMDD/GeoLite2-City.mmdb needs to be moved to the GeoIP database directory. This directory might already exist and will vary depending on which platform and package you are using. Use `/usr/share/GeoIP` or `/var/lib/GeoIP` (choose whichever one already exists).

`mv <extracted subdir>/GeoLite2-City.mmdb <path_to_database_dir>/GeoLite2-City.mmdb`

### Installing Zeek
For xUbuntu 20.04 do the following:
`echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list`
`curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
``sudo apt update`
`sudo apt install zeek-lts`
Furthermore, you can download the packages for the latest LTS release build [here](https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek-lts).


