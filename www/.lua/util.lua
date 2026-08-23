local M={}

function M.trim(value)
   if type(value) ~= "string" then return "" end
   return value:match("^%s*(.-)%s*$")
end

function M.html(value)
   value=tostring(value or "")
   return (value:gsub("[&<>\"']", {
      ["&"]="&amp;",
      ["<"]="&lt;",
      [">"]="&gt;",
      ["\""]="&quot;",
      ["'"]="&#39;"
   }))
end

function M.hex(data)
   return (data:gsub(".", function(c)
      return string.format("%02x", string.byte(c))
   end))
end

function M.newId()
   return M.hex(ba.rndbs(16))
end

function M.isLoopback(address)
   if type(address) ~= "string" then return false end
   address=address:lower()
   if address == "::1" or address == "0:0:0:0:0:0:0:1" then return true end
   if address:match("^127%.") then return true end
   local mapped=address:match("^::ffff:(127%..+)$")
   return mapped and true or false
end

function M.baseUri(appDir)
   local base=appDir:baseuri() or ""
   if base == "/" or base == "" then return "/" end
   return base:gsub("/+$", "").."/"
end

function M.utcDate(epoch)
   return os.date("!*t", epoch)
end

function M.utcText(epoch)
   return os.date("!%Y-%m-%d %H:%M:%S UTC", tonumber(epoch))
end

function M.pemToDer(pem)
   if type(pem) ~= "string" then return nil,"certificate is not a string" end
   local body=pem:match(
      "%-%-%-%-%-BEGIN CERTIFICATE%-%-%-%-%-%s*(.-)%s*%-%-%-%-%-END CERTIFICATE%-%-%-%-%-")
   if not body then return nil,"certificate PEM body not found" end
   local ok,der=pcall(ba.b64decode,(body:gsub("%s", "")))
   if not ok or not der then return nil,tostring(der or "invalid certificate base64") end
   return der
end

function M.derToPem(der)
   local body=ba.b64encode(der)
   local lines={"-----BEGIN CERTIFICATE-----"}
   for pos=1,#body,64 do lines[#lines+1]=body:sub(pos,pos+63) end
   lines[#lines+1]="-----END CERTIFICATE-----"
   return table.concat(lines,"\n").."\n"
end

function M.safeJsonDecode(value, fallback)
   if type(value) ~= "string" then return fallback end
   local ok,result=pcall(ba.json.decode,value)
   return ok and result or fallback
end

function M.containsControl(value)
   return type(value) ~= "string" or value:find("[%z\1-\31\127]") ~= nil
end

function M.hostIsIPv4(value)
   local a,b,c,d=value:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
   if not a then return false end
   for _,part in ipairs{a,b,c,d} do
      if #part > 1 and part:sub(1,1) == "0" then return false end
      local n=tonumber(part)
      if not n or n > 255 then return false end
   end
   return true
end

function M.hostIsDns(value)
   if type(value) ~= "string" or #value < 1 or #value > 253 then return false end
   if value:sub(-1) == "." then value=value:sub(1,-2) end
   if #value < 1 then return false end
   for label in value:gmatch("[^.]+") do
      if #label > 63 or not label:match("^[A-Za-z0-9%-]+$") or
         label:sub(1,1) == "-" or label:sub(-1) == "-" then
         return false
      end
   end
   return not value:find("%.%.",1,true)
end

return M
