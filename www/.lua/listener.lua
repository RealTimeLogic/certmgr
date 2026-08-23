local config,keyvault=app.config,app.keyvault
local M={}
local active

local function closeActive()
   if not active then return end
   local connection=active.connection
   active=nil
   if connection then
      local ok,err=pcall(connection.close,connection)
      if not ok then trace("certmgr TLS test listener close failed",err) end
   end
   collectgarbage()
end

function M.start(certificate)
   closeActive()
   if certificate.status ~= "active" then return nil,"certificate is not active" end
   local key,err=keyvault.decrypt(certificate,"certificate",certificate.id,certificate.algorithm)
   if not key then return nil,err end
   local ok,sharkCert=pcall(ba.create.sharkcert,certificate.cert_pem,key)
   key=nil
   if not ok or not sharkCert then return nil,"Server certificate loading failed: "..tostring(sharkCert) end
   local shark=ba.create.sharkssl(nil,{server=true})
   local added,addErr=shark:addcert(sharkCert)
   if not added then return nil,"Server certificate installation failed: "..tostring(addErr) end
   for port=config.testPort,config.testPort+config.testPortCount-1 do
      local connection,bindErr=ba.create.servcon(port,{shark=shark,intf=config.testAddress})
      if connection then
         active={
            connection=connection,
            shark=shark,
            sharkCert=sharkCert,
            port=port,
            address=config.testAddress,
            certificate_id=certificate.id,
            common_name=certificate.common_name,
            started_at=os.time()
         }
         return M.status()
      end
      err=bindErr
   end
   return nil,"No secure test port is available: "..tostring(err)
end

function M.stop()
   closeActive()
   return true
end

function M.status()
   if not active then return {running=false} end
   return {
      running=true,
      port=active.port,
      address=active.address,
      certificate_id=active.certificate_id,
      common_name=active.common_name,
      started_at=active.started_at
   }
end

function M.close()
   closeActive()
end

return M
