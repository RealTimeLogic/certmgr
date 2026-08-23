local app=app
local M={}

function M.algorithm(value)
   local item=app.pki.algorithms[value]
   return item and item.label or tostring(value or "Unknown")
end

function M.date(value)
   if not value or not tonumber(value) then return "—" end
   return app.util.utcText(value)
end

function M.shortFingerprint(value)
   if not value or value == "" then return "—" end
   local groups={}
   for pos=1,#value,4 do groups[#groups+1]=value:sub(pos,pos+3) end
   return table.concat(groups," ")
end

function M.authorityFromRequest(request)
   local id=app.util.trim(request:data"ca")
   local authorities,err=app.store.listAuthorities()
   if not authorities then return nil,nil,err end
   if id ~= "" then
      for _,authority in ipairs(authorities) do
         if authority.id == id then return authority,authorities end
      end
   end
   return authorities[1],authorities
end

function M.status(value)
   local class=value == "active" and "status-good" or
      (value == "pending" and "status-warn" or "status-bad")
   local labels={active="Active",pending="In progress",failed="Failed"}
   return '<span class="status '..class..'">'..app.util.html(labels[value] or value or "Unknown")..'</span>'
end

function M.nativeFields(json)
   local parsed=app.util.safeJsonDecode(json,{})
   local keys={}
   for key in pairs(parsed) do keys[#keys+1]=key end
   table.sort(keys)
   if #keys == 0 then return '<p class="muted">Mako Server did not return any additional certificate fields.</p>' end
   local out={'<dl class="detail-grid">'}
   for _,key in ipairs(keys) do
      local value=parsed[key]
      if type(value) == "table" then value=ba.json.encode(value) end
      out[#out+1]='<dt>'..app.util.html(key)..'</dt><dd>'..app.util.html(value)..'</dd>'
   end
   out[#out+1]='</dl>'
   return table.concat(out)
end

function M.dnFields(json)
   local dn=app.util.safeJsonDecode(json,{})
   local labels={
      commonname="Common name",organization="Organization",unit="Organizational unit",
      locality="Locality",province="State or province",countryname="Country",email="Email"
   }
   local order={"commonname","organization","unit","locality","province","countryname","email"}
   local out={'<dl class="detail-grid">'}
   for _,key in ipairs(order) do
      if dn[key] and dn[key] ~= "" then
         out[#out+1]='<dt>'..labels[key]..'</dt><dd>'..app.util.html(dn[key])..'</dd>'
      end
   end
   out[#out+1]='</dl>'
   return table.concat(out)
end

return M
