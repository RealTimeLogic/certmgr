local util=app.util
local M={}

local headers={
   ["Content-Security-Policy"]="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
   ["X-Content-Type-Options"]="nosniff",
   ["Referrer-Policy"]="no-referrer",
   ["Permissions-Policy"]="camera=(), microphone=(), geolocation=(), payment=(), usb=()",
   ["X-Frame-Options"]="DENY"
}

function M.dynamicHeaders(response)
   for name,value in pairs(headers) do response:setheader(name,value) end
   response:setheader("Cache-Control","no-store")
   response:setheader("Pragma","no-cache")
end

function M.install(appDir)
   appDir:header(headers)
   local gate=ba.create.dir(100)
   gate:setfunc(function(_ENV)
      local address=request:peername()
      if util.isLoopback(address) then return false end
      response:setstatus(403)
      response:setcontenttype"text/plain; charset=utf-8"
      response:setheader("Cache-Control","no-store")
      response:write"Certificate Manager is available only from the local computer."
      return true
   end)
   appDir:insertprolog(gate,true)
   return gate
end

function M.csrfToken(request)
   local session=request:session(true)
   if not session.certmgrCsrf then session.certmgrCsrf=util.hex(ba.rndbs(32)) end
   return session.certmgrCsrf
end

function M.checkPost(request)
   if request:method() ~= "POST" then return nil,"POST is required",405 end
   local session=request:session(false)
   local supplied=request:data"csrf"
   if not session or type(supplied) ~= "string" or
      type(session.certmgrCsrf) ~= "string" or supplied ~= session.certmgrCsrf then
      return nil,"The form security token is missing or expired. Reload the page and try again.",403
   end
   return true
end

return M
