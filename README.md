# Zeek-Script

## Introduction
These scripts parse pcap files and produce log files (typical of Zeek). As objectives they have:
- looking for long connections, based on duration
- seeking persistent connections
- count of equal-sized packets per connection
- geolocation of the IPs , with  *libmaxminddb* software and *GeoLite2 city* database

## Getting Started
Complete documentation at the following [link](https://docs.zeek.org/en/lts/). Below is a quick installation and launch guide for Ubuntu.

### Dependencies

  *ZEEK 4.0 or greater*


### Install Zeek Dependencies

`$sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev`

### Install libmaxminddb

`$sudo apt-get install libmaxminddb-dev`

### GeoLite2-City Database Installation
Zeek can use the city or country database. The city database includes cities and regions in addition to countries. First, [signup](https://www.maxmind.com/en/geolite2/signup) for a MaxMind account, which is now required to [download](https://www.maxmind.com/en/accounts/current/geoip/downloads) even free/public GeoIP databases. Then, you can download databases. For example, download the GeoLite2-City database and decompress it. 

Next, the file GeoLite2-City_YYYYMMDD/GeoLite2-City.mmdb needs to be moved to the GeoIP database directory. This directory might already exist and will vary depending on which platform and package you are using. Use `/usr/share/GeoIP` or `/var/lib/GeoIP` (choose whichever one already exists).

`$mv <extracted subdir>/GeoLite2-City.mmdb <path_to_database_dir>/GeoLite2-City.mmdb`

### Installing Zeek
For xUbuntu 20.04 do the following:

`$echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list`

`$curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null`

`$sudo apt update`

`$sudo apt install zeek-lts`

Furthermore, you can download the packages for the latest LTS release build [here](https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek-lts).

By default the binary package install location is `/opt/zeek`. Under `/opt/zeek/bin` there is the executable of the tool, we can launch it from here. Then you can add the Zeek binary path to PATH, so we can launch it without going into its folder. To do it:

`$export PATH="/opt/zeek/bin:$PATH"`

Now you can check that everything went well:

`$zeek --version`

### Download Scripts
You can download these scripts to the folder you want, and then use them to parse a pcap file. To download them:

`$git clone https://github.com/Davide-Lotito/Zeek-Script.git`

### How to use
Finally an example on how to use a script against a pcap file. Note that Zeek will produce log files in the current directory, that is the one from which the command is launched.

`$zeek -r ./exampleDir/filePcap.pcap ./exampleDir2/scriptExample.zeek`




