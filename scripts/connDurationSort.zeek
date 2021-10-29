@load base/protocols/conn
@load base/bif

module Beacons;
##Purpose:
#to create a log sorted file that which lists for each pair of IPs the amount
#of time in which they "talked" to each other.

##It works, but only with small pcap files...

#Record useful for printing on the log file, longConn.log
type LineLog: record {
  sourceAddr: addr &log;
  destAddr: addr &log;
  duration: interval &log &optional;
};

#Record useful as a "connection" identifier
type Info: record {
  addr1: addr;
  addr2: addr;
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

#Event that can be handled to access the Conn::Info record as it is sent
#on to the logging framework.
event Conn::log_conn (rec: Conn::Info){
	local actualTalk: Info = record($addr1=rec$id$orig_h, $addr2=rec$id$resp_h);
	local adder: interval = handleDurationError(rec);

  scanned[actualTalk]+=adder;
}

#Function useful to write on the longConn.log file, at the end of the counts
function writeLog() {
	local vectStamp: vector of LineLog;

	for (t in scanned){
		counter+=1;
		vectStamp += LineLog($sourceAddr=t$addr1, $destAddr=t$addr2, $duration=scanned[t]);
	}
sort(vectStamp, function (a: LineLog, b: LineLog): int {return a$duration < b$duration ? 1 : -1;} );

  for (i in vectStamp){
		local a: LineLog = vectStamp[i];
		Log::write(longConn::LOG, a);
}
}


#Generated at Zeek termination time.
event zeek_done(){
	writeLog();
	print "***";
	print fmt("Number of Connections:%d",counter);
	print "***";
}
