@load base/protocols/conn

module Beacons;
##Purpose:
#to create a sorted log file that which lists for each pair of IPs how many times
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
  #It contains all the "connections" and their duration
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

#Function useful to write on the longConn.log file sorted, at the end of the counts
function writeLogS() {
	local vectStamp: vector of LineLog;

	for (t in scanned){
		vectStamp += LineLog($sourceAddr=t$addr1, $destAddr=t$addr2, $numberOfConnections=scanned[t]);
    sort(vectStamp, function (a: LineLog, b: LineLog): int {return a$numberOfConnections < b$numberOfConnections ? 1 : -1;});
	}

  local i: int = 0;
  local j: int = 0;
  #I hoped this was less heavy, but it's not so..
  while (i < |vectStamp| && j<5 ){
    local a: LineLog = vectStamp[i];
    Log::write(longConn::LOG, a);
    i+=1;
    j+=1;
  }
}

#Generated at Zeek termination time.
event zeek_done(){
  writeLogS();
}
