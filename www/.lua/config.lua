local util=app.util
local source=require"loadconf"
local supplied=source.certmgr or {}

local function integer(name, default, min, max)
   local value=supplied[name]
   if value == nil then return default end
   if type(value) ~= "number" or value ~= math.floor(value) or value < min or value > max then
      error(string.format("mako.conf certmgr.%s must be an integer from %d through %d",name,min,max))
   end
   return value
end

local keyMode=supplied.keyMode or "unique"
if keyMode ~= "unique" and keyMode ~= "global" then
   error("mako.conf certmgr.keyMode must be 'unique' or 'global'")
end

local testAddress=supplied.testAddress or "127.0.0.1"
if not util.isLoopback(testAddress) then
   error("mako.conf certmgr.testAddress must be a loopback address")
end

local testPort=integer("testPort",9000,1024,65535)
local testPortCount=integer("testPortCount",20,1,100)
if testPort+testPortCount-1 > 65535 then
   error("mako.conf certmgr.testPort plus testPortCount exceeds port 65535")
end

return {
   keyMode=keyMode,
   keyName="realtimelogic.certmgr.private-keys.v1",
   testAddress=testAddress,
   testPort=testPort,
   testPortCount=testPortCount,
   busyTimeout=integer("busyTimeout",3000,100,30000),
   maxAuthorities=integer("maxAuthorities",100,1,10000),
   maxCertificatesPerAuthority=integer("maxCertificatesPerAuthority",10000,1,1000000)
}
