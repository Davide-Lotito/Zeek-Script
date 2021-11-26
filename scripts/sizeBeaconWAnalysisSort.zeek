@load base/protocols/conn

module Beacons;
##Purpose:
#to create two log files. One that lists for each pair of IPs how many times
#they "talked" to each other. The other one says the amount of bytes exchanged
#between them and the occurrence of this amount (only for top-5).

#Record useful for printing on the log file, sizeBeacon.log
type sizeBeaconLine: record {
  sourceAddr: addr &log;
  destAddr: addr &log;
  numberOfConnections: int &log &optional;
  quanTable: table[count] of int &optional;
};

#Record useful for printing on the log file, sizeConn.log
type sizeConnLine: record {
  sourceAddr: addr &log;
  destAddr: addr &log;
  numberOfConnections: int &log &optional;
  quantity: count &log;
};

type Value: record {
	numberConnections: int &default=0;
	quantityTable: table[count] of int &optional;
};

#Record useful as a "connection" identifier
type Info: record {
  addr1: addr ;
  addr2: addr ;
};

export{
	redef enum Log::ID += { sizeBeacon::LOG };
	redef enum Log::ID += { sizeConn::LOG };
	#It contains all the "connections" and their duration
	global scanned: table[Info] of Value;

}

#Generated at Zeek initialization time.
event zeek_init(){
	Log::create_stream(sizeBeacon::LOG, [$columns=sizeBeaconLine, $path="sizeBeacon"]);
	Log::create_stream(sizeConn::LOG, [$columns=sizeConnLine, $path="sizeConn"]);
}

#function useful to increment a log's field
function incrementR(v: Value, q: table[count] of int): Value {
	local a = v$numberConnections + 1;
	local b: Value = record($numberConnections=a, $quantityTable=q);
	return b;
}

function addNewQuantity(quant: count): table[count] of int{
	local q: table[count] of int;
	q[quant] = 1;
	return q;
}

function addQuantity(quant: count, q:table[count] of int): table[count] of int{
		if ( quant in q){
			q[quant] += 1;
		} else {
			q[quant] = 1;
		}
		return q;
}

function handleQuantError(rec: Conn::Info): count {
  if (!(rec?$orig_bytes)){
    return 0;
  }
  return rec$orig_bytes;
}

#Event that can be handled to access the Conn::Info record as it is sent
#on to the logging framework.
event Conn::log_conn (rec: Conn::Info){
	local actualTalk: Info = record($addr1=rec$id$orig_h, $addr2=rec$id$resp_h);
	local bytes: count = handleQuantError(rec);

  if(actualTalk in scanned){
		local q2: table[count] of int = scanned[actualTalk]$quantityTable;
		q2 = addQuantity(bytes,q2);
		scanned[actualTalk] = incrementR(scanned[actualTalk],q2);
	} else {
		local q1: table[count] of int = addNewQuantity(bytes);
		local c: Value; #= record($numberConnections=0);
		scanned[actualTalk] = incrementR(c,q1);
	}
}

#Function useful to write on the sizeConn.log file sorted, at the end of the counts
function writeLogSize(actual: sizeBeaconLine) {
	local quantTable: table[count] of int = actual$quanTable;

  for ( k in quantTable ){
    local a: sizeConnLine = record($sourceAddr=actual$sourceAddr, $destAddr=actual$destAddr, $numberOfConnections=actual$quanTable[k], $quantity=k);
    Log::write(sizeConn::LOG, a);
  }
}

#Function useful to write on the sizeBeacon.log file sorted, at the end of the counts
function writeLogS() {
  local vectStamp: vector of sizeBeaconLine;
	for (t in scanned){
		vectStamp += sizeBeaconLine($sourceAddr=t$addr1, $destAddr=t$addr2, $numberOfConnections=scanned[t]$numberConnections, $quanTable=scanned[t]$quantityTable);
	}

  sort(vectStamp, function (a: sizeBeaconLine, b: sizeBeaconLine): int {return a$numberOfConnections < b$numberOfConnections ? 1 : -1;});

  local i: int = 0;
  local j: int = 0;

  while (i < |vectStamp| && j<5 ){
    local a: sizeBeaconLine = vectStamp[i];
    writeLogSize(a);
    Log::write(sizeBeacon::LOG, a);
    i+=1;
    j+=1;
  }
}

event zeek_done(){
  writeLogS();
}
