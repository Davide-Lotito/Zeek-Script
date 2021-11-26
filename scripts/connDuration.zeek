@load base/protocols/conn

module Beacons;
##Purpose:
#to create a log file that which lists for each pair of IPs the amount of time
#in which they "talked" to each other. It uses the GeoLocation framework too.

#Record useful for printing on the log file, longConn.log
type LineLog: record {
  line: int &log;
  sourceAddr: addr &log;
  destAddr: addr &log;
  duration: interval &log &optional;
  sourceL: string &log &optional;
  destL: string &log &optional;
};

#Record useful as a "connection" identifier
type Info: record {
  addr1: addr ;
  addr2: addr ;
};

export{
  redef enum Log::ID += { longConn::LOG };
  #Counter of the lines
  global counter = 0;
  #It contains all the "connections" and their duration
  global scanned: table[Info] of interval &default=0usec;
}

#Generated at Zeek initialization time.
event zeek_init(){
	Log::create_stream(longConn::LOG, [$columns=LineLog, $path="longConn"]);
}

#Function useful to correct those lines in which the duration does not exist
function handleDurationError(rec: Conn::Info): interval {
  if (!(rec?$duration)){
    return 0usec;
  }
  return rec$duration;
}

#Function useful to handle situations without location info
function handleLocationError(geo: geo_location): string {
  if (!(geo?$country_code)){
    return "unknown";
  }
  return geo$country_code;
}

#Function that correct the "bad" situations of private IPs and them location
function handleLocationPrivate(address: addr): bool {
  local private1: subnet = 192.168.0.0/16;
  local private2: subnet = 172.16.0.0/12;
  local private3: subnet = 10.0.0.0/8;
  if (address in private1 || address in private2 || address in private3){
    return T;
  }
  return F;
}

#Event that can be handled to access the Conn::Info record as it is sent
#on to the logging framework.
event Conn::log_conn (rec: Conn::Info){
  local actualTalk: Info = record($addr1=rec$id$orig_h, $addr2=rec$id$resp_h);
	local adder: interval = handleDurationError(rec);

    scanned[actualTalk]+=adder;
}

#Function useful to write on the longConn.log file, at the end of the counts
function writeLog() {
	for (t in scanned){
		++counter;

    if(handleLocationPrivate(t$addr2)){
      local sourceL: string = "privateAddress";
    } else {
      sourceL = handleLocationError(lookup_location(t$addr2));
    }

    if(handleLocationPrivate(t$addr1)){
      local destL: string = "privateAddress";
    } else {
        destL = handleLocationError(lookup_location(t$addr1));
    }

		Log::write(longConn::LOG, LineLog($sourceAddr=t$addr2, $destAddr=t$addr1, $duration=scanned[t], $line=counter, $sourceL=sourceL, $destL=destL));
	}
}

#Generated at Zeek termination time.
event zeek_done(){
	writeLog();
  print "***";
	print fmt("Number of Connections:%d",counter);
	print "***";
}
