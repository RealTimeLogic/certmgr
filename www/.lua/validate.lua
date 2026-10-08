local util,pki=app.util,app.pki
local M={}

local function text(data,name,label,max,required)
   local value=util.trim(data[name])
   if value == "" then
      if required then return nil,label.." is required" end
      return nil
   end
   if #value > max then return nil,label.." is too long" end
   if util.containsControl(value) then return nil,label.." contains a control character" end
   if not value:match("^[A-Za-z0-9 %.,'()+@_/%-]+$") then
      return nil,label.." contains an unsupported character"
   end
   return value
end

local function country(data)
   local value=util.trim(data.country):upper()
   if value == "" then return nil end
   if not value:match("^[A-Z][A-Z]$") then return nil,"Country must be a two-letter code" end
   return value
end

local function integer(data,name,label,default,min,max)
   local raw=util.trim(data[name])
   local value=raw == "" and default or tonumber(raw)
   if not value or value ~= math.floor(value) or value < min or value > max then
      return nil,string.format("%s must be an integer from %d through %d",label,min,max)
   end
   return value
end

local function dn(data,commonName)
   local result={commonname=commonName}
   local value,err=text(data,"organization","Organization",128,false)
   if err then return nil,err end
   result.organization=value
   value,err=text(data,"unit","Organizational unit",128,false)
   if err then return nil,err end
   result.unit=value
   value,err=text(data,"locality","Locality",128,false)
   if err then return nil,err end
   result.locality=value
   value,err=text(data,"province","State or province",128,false)
   if err then return nil,err end
   result.province=value
   value,err=country(data)
   if err then return nil,err end
   result.countryname=value
   value,err=text(data,"email","Email address",128,false)
   if err then return nil,err end
   if value and not value:match("^[^@%s]+@[^@%s]+$") then return nil,"Email address is invalid" end
   result.email=value
   for key,item in pairs(result) do if item == nil then result[key]=nil end end
   return result
end

function M.authority(data)
   local name,err=text(data,"name","Authority name",64,true)
   if not name then return nil,err end
   local commonName
   commonName,err=text(data,"commonName","Common name",128,true)
   if not commonName then return nil,err end
   local algorithm=util.trim(data.algorithm)
   if not pki.algorithms[algorithm] then return nil,"Select a supported authority algorithm" end
   local days
   days,err=integer(data,"days","Validity",3650,365,7300)
   if not days then return nil,err end
   local subject
   subject,err=dn(data,commonName)
   if not subject then return nil,err end
   local now=os.time()
   return {
      id=util.newId(),
      name=name,
      algorithm=algorithm,
      dn=subject,
      days=days,
      created_at=now,
      not_before=now-300,
      not_after=now+(days*86400)
   }
end

local function normalizeSan(commonName,raw)
   if #raw > 2048 then return nil,"Additional server identities are too long" end
   local result,seen={},{}
   local function add(value)
      if value:sub(1,3):upper() == "IP:" then
         value="IP:"..value:sub(4)
      else
         value=value:lower()
      end
      if not seen[value] then
         seen[value]=true
         result[#result+1]=value
      end
   end
   local function parse(value)
      value=util.trim(value)
      if value == "" then return true end
      local prefix,name=value:match("^([A-Za-z]+):(.*)$")
      if prefix then
         prefix=prefix:upper()
         name=util.trim(name)
         if prefix == "IP" then
            if not util.hostIsIPv4(name) then return nil,"Only version 4 IP addresses, such as 127.0.0.1, are supported" end
            add("IP:"..name)
            return true
         end
         if prefix ~= "DNS" then return nil,"Use a host name or a version 4 IP address" end
         value=name
      end
      if util.hostIsIPv4(value) then add("IP:"..value) return true end
      if value:find(":",1,true) then return nil,"Version 6 IP addresses are not currently supported by Mako Server" end
      if value:sub(-1) == "." then return nil,"Server host names must not end with a dot" end
      if not util.hostIsDns(value) then return nil,"Invalid server host name: "..value end
      add(value)
      return true
   end
   for value in (raw..";"):gmatch("%s*([^,;\r\n]+)%s*[,;\r\n]") do
      local ok,err=parse(value)
      if not ok then return nil,err end
   end
   local ok,err=parse(commonName)
   if not ok then return nil,err end
   if #result > 16 then return nil,"No more than 16 server identities are supported" end
   table.sort(result)
   local sanText=table.concat(result,";")
   if #sanText > 255 then return nil,"Combined server identities must not exceed 255 bytes" end
   return result,sanText
end

function M.certificate(data,authority)
   local authorityId=util.trim(data.authority)
   if not authorityId:match("^[0-9a-f][0-9a-f]+$") or #authorityId ~= 32 then
      return nil,"Select a valid authority"
   end
   if authorityId ~= authority.id then return nil,"Selected authority does not match the request" end
   local commonName=util.trim(data.commonName)
   if commonName == "" or #commonName > 253 or util.containsControl(commonName) then
      return nil,"Primary server name or network address is required and must be at most 253 characters"
   end
   if commonName:find(":",1,true) then return nil,"Version 6 IP addresses are not currently supported by Mako Server" end
   if not util.hostIsIPv4(commonName) and not util.hostIsDns(commonName) then
      return nil,"Primary server identity must be a host name or version 4 Internet Protocol address"
   end
   commonName=commonName:lower()
   local label,err=text(data,"label","Certificate label",64,false)
   if err then return nil,err end
   label=label or commonName
   local days
   days,err=integer(data,"days","Validity",397,1,825)
   if not days then return nil,err end
   local subject
   subject,err=dn(data,commonName)
   if not subject then return nil,err end
   local sans,sanText=normalizeSan(commonName,data.san or "")
   if not sans then return nil,sanText end
   local now=os.time()
   local notAfter=now+(days*86400)
   if notAfter >= tonumber(authority.not_after) then
      return nil,"Certificate validity must end before the authority expires"
   end
   return {
      id=util.newId(),
      authority_id=authorityId,
      label=label,
      common_name=commonName,
      dn=subject,
      san_list=sans,
      san=sanText,
      days=days,
      created_at=now,
      not_before=now-300,
      not_after=notAfter
   }
end

return M
