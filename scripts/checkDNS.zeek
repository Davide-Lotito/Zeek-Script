@load base/protocols/conn

module Beacons;
##Purpose: how many fully qualified domain names are associated with each domain,
##which means that we need to count up the number of times something was queried
##within a specific domain.


#Record useful for printing on the log file, checkDNS.log
type LineLog: record {
  domainName: string &log &optional;
  counter: count &log;
};

export{
  redef enum Log::ID += { checkDNS::LOG };
  #It contains all the domainName and their counter
  global scanned: table[string] of count &default=0;
}

#Generated at Zeek initialization time.
event zeek_init(){
	Log::create_stream(checkDNS::LOG, [$columns=LineLog, $path="checkDNS"]);
}

function handleMissingValue(rec: DNS::Info): string {
  if (!(rec?$query)){
    return "unknown";
  }
  return rec$query;
}

#An event that can be handled to access the DNS::Info record
#as it is sent to the logging framework.
event DNS::log_dns(rec: DNS::Info){
  local s = handleMissingValue(rec);
  local c = split_string(s, /\./);
  local actualDomain: string;

  #In order the get the unique host name
  if (|c| >= 2){
    actualDomain = c[|c|-2] + "." + c[|c|-1];
  } else {
    actualDomain = s;
  }

  scanned[actualDomain] += 1;
}

#Function useful to write on the checkDNS.log file, at the end of the counts
function writeLog() {
	for (l in scanned) {
    if (l == "unknown"){next;}
	  Log::write(checkDNS::LOG, LineLog($domainName=l, $counter=scanned[l]));
	}
}

#Generated at Zeek termination time.
event zeek_done(){
  writeLog();
}
