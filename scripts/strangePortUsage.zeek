@load base/protocols/conn

module Beacons;
##Purpose:
#Unexpected usage or unexpected application running across a well-known ports.
#The control takes place on the ports of the source IP

#It seems to be working

#Record useful for printing on the log file, strangePorts.log
type LineLog: record {
  timeStamp: time &log;
  connection: conn_id &log;
  transportP: transport_proto &log;
  protocol: string &log;
};

#Record useful like identifier
type PortProt: record {
  portN: port;
  protocol: string;
};

export{
  redef enum Log::ID += { strangePorts::LOG };
  #It contains all the domainName and their counter
  global stamp: vector of Conn::Info;
	global counter = 0;
  #Set of well-known port
  global knownPorts = set(PortProt($portN=20/tcp, $protocol="ftp"), PortProt($portN=21/tcp, $protocol="ftp"), PortProt($portN=22/tcp, $protocol="ssh"),
                    PortProt($portN=23/tcp, $protocol="telnet"), PortProt($portN=25/tcp, $protocol="SMTP"), PortProt($portN=80/tcp, $protocol="HTTP"),
                    PortProt($portN=110/tcp, $protocol="POP"), PortProt($portN=143/tcp, $protocol="IMAP4"), PortProt($portN=443/tcp, $protocol="HTTPS"),
                    PortProt($portN=465/tcp, $protocol="SMTP"), PortProt($portN=53/udp, $protocol="DNS"), PortProt($portN=67/udp, $protocol="DHCP"),
                    PortProt($portN=68/udp , $protocol="DHCP"));

  }

  #Generated at Zeek initialization time.
  event zeek_init(){
    Log::create_stream(strangePorts::LOG, [$columns=LineLog, $path="strangePorts"]);
  }

  #Function useful to correct those lines in which there is not protocol field
  function handleProtocolError(rec: Conn::Info): string {
    if (!(rec?$service)){
      return "unknown";
    }
    return to_upper(rec$service);
  }

  #Function useful to check if a port i
  function checkPort(p: PortProt): bool {
    if (p in knownPorts){
      return T;
    } else {
      return F;
    }
  }

  #Event that can be handled to access the Conn::Info record as it is sent
  #on to the logging framework.
  event Conn::log_conn (rec: Conn::Info){
    local actual = PortProt($portN=rec$id$orig_p, $protocol=handleProtocolError(rec));

    if (!checkPort(actual)) {
      stamp += rec;
    }
  }

  #Function useful to write on the longConn.log file, at the end of the counts
  function writeLog() {
  local i: int = 0;
  local l: int = |stamp|;
  while (i < l) {
  		++counter;
      Log::write(strangePorts::LOG, LineLog($timeStamp=stamp[i]$ts, $connection=stamp[i]$id, $transportP=stamp[i]$proto, $protocol=handleProtocolError(stamp[i])));
  		++i;
  	}
  }

  #Generated at Zeek termination time.
  event zeek_done(){
  	writeLog();
  	print fmt("Number of hits:%d", counter);
  }
