@load policy/protocols/ssl/validate-certs.zeek

module Beacons;
##Purpose:
#check if there are any problems with SSL certificates,
#such as expired or self-signed

#It seems to be working

#Reminder:
#"unable to get local issuer certificate" --> a self-signed certificate cannot be verified.

type LineLog: record {
  timeStamp: time &log;
  connection: conn_id &log;
  validation: string &log;
};

export{
  redef enum Log::ID += { problemSSL::LOG };
  #It contains all the domainName and their counter
  global stamp: vector of SSL::Info;
	global counter = 0;
}

#Generated at Zeek initialization time.
event zeek_init(){
  Log::create_stream(problemSSL::LOG, [$columns=LineLog, $path="problemSSL"]);
}

#Function useful to correct those lines in which there is not protocol field
function handleProtocolError(rec: SSL::Info): string {
  if (!(rec?$validation_status)){
    return "unknown";
  }
  return (rec$validation_status);
}

#Function useful to check if a port
function checkSSL(s: string): bool {
	local found = find_all(s,/expired|ok/i);
  if (|found| >= 1){
    return T;
  } else {
    return F;
  }
}

#Event that can be handled to access the SSL record as it is sent on to the
#logging framework
event SSL::log_ssl(rec: SSL::Info){
  if (!checkSSL(handleProtocolError(rec))){
    stamp += rec;
  }
}

#Function useful to write on the problemSSL.log file, at the end of the counts
function writeLog() {
local i: int = 0;
local l: int = |stamp|;
while (i < l) {
    ++counter;
    Log::write(problemSSL::LOG, LineLog($timeStamp=stamp[i]$ts, $connection=stamp[i]$id, $validation=handleProtocolError(stamp[i])));
    ++i;
  }
}

#Generated at Zeek termination time.
event zeek_done(){
  writeLog();
  print fmt("Number of hits:%d", counter);
}
