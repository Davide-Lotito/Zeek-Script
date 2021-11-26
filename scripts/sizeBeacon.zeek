@load base/protocols/conn

module Beacons;
##Purpose:
##to create a log file that which lists for each pair of IPs how many times
#they "talked" to each other.

#Record useful for printing on the log file, longConn.log
type LineLog: record {
  sourceAddr: addr &log;
  destAddr: addr &log;
  numberOfConnections: int &log &optional;
};

#Record useful as a "connection" identifier
type Info: record {
  addr1: addr ;
  addr2: addr ;
};

export{
  redef enum Log::ID += { longConn::LOG };

  #It contains all the "connections" and their counter
  global scanned: table[Info] of int &default=0;
}

#Generated at Zeek initialization time.
event zeek_init(){
	Log::create_stream(longConn::LOG, [$columns=LineLog, $path="sizeBeacon"]);
}

#Event that can be handled to access the Conn::Info record as it is sent
#on to the logging framework.
event Conn::log_conn (rec: Conn::Info){
  local actualTalk: Info = record($addr1=rec$id$orig_h, $addr2=rec$id$resp_h);

  scanned[actualTalk]+=1;
}

#Function useful to write on the longConn.log file, at the end of the counts
function writeLog() {
	for (t in scanned){
  		Log::write(longConn::LOG, LineLog($sourceAddr=t$addr2, $destAddr=t$addr1, $numberOfConnections=scanned[t]));
	}
}

#Generated at Zeek termination time.
event zeek_done(){
  writeLog();
}
