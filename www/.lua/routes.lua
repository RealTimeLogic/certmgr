local app=app
local M={}

local function errorBody(message,back)
   return table.concat{
      '<section class="page"><div class="page-header"><p class="eyebrow">Request failed</p>',
      '<h1>The operation was not completed</h1></div><div class="alert alert-error" role="alert">',
      app.util.html(message),'</div><p><a class="button button-secondary" href="',
      app.util.html(back),'">Return</a></p></section>'}
end

local function errorDocument(message,back)
   return table.concat{
      '<!doctype html><html lang="en"><head><meta charset="utf-8">',
      '<meta name="viewport" content="width=device-width,initial-scale=1">',
      '<title>Request failed · Certificate Manager</title><link rel="stylesheet" href="',
      app.util.html(app.base),'static/styles.css?v=3"></head><body><div class="standalone-error">',
      errorBody(message,back),'</div></body></html>'}
end

local function syncError(_ENV,status,message,back)
   app.security.dynamicHeaders(response)
   response:setstatus(status)
   response:setcontenttype"text/html; charset=utf-8"
   response:write(errorDocument(message,back))
   return true
end

local function deferredSend(defresp,status,body,headers)
   if not defresp:valid() then return end
   defresp:setstatus(status)
   defresp:setheader("Content-Type","text/html; charset=utf-8")
   defresp:setheader("Cache-Control","no-store")
   if headers then for name,value in pairs(headers) do defresp:setheader(name,value) end end
   defresp:setcontentlength(#body)
   defresp:send(body)
   defresp:close()
end

local function deferredError(defresp,message,back,status)
   deferredSend(defresp,status or 422,errorDocument(message,back))
end

local function deferredRedirect(defresp,url,htmx)
   if htmx then
      deferredSend(defresp,200,"",{["HX-Redirect"]=url})
   else
      deferredSend(defresp,303,"",{Location=url})
   end
end

local function deferredDownload(defresp,data,contentType,filename)
   if not defresp:valid() then return end
   defresp:setstatus(200)
   defresp:setheader("Content-Type",contentType)
   defresp:setheader("Content-Disposition",'attachment; filename="'..filename..'"')
   defresp:setheader("Cache-Control","no-store, private")
   defresp:setheader("Pragma","no-cache")
   defresp:setheader("X-Content-Type-Options","nosniff")
   defresp:setheader("Referrer-Policy","no-referrer")
   defresp:setheader("Cross-Origin-Resource-Policy","same-origin")
   defresp:setcontentlength(#data)
   defresp:send(data)
   defresp:close()
end

local function worker(defresp,back,operation)
   app.pkiWorker:run(function()
      local ok,err=xpcall(operation,debug.traceback)
      if not ok and defresp:valid() then
         trace("certmgr PKI worker failure",err)
         deferredError(defresp,"Internal certificate operation failed.",back)
      end
   end)
end

local function friendlyDatabaseError(err)
   err=tostring(err or "database operation failed")
   if err == "authority name already exists" or
      err:find("UNIQUE constraint failed: authorities.name",1,true) then
      return "An authority with that name already exists."
   end
   return "The certificate database could not complete the operation."
end

local function createAuthority(_ENV)
   local back=app.base.."authorities.html"
   local valid,err,status=app.security.checkPost(request)
   if not valid then return syncError(_ENV,status,err,back) end
   local input
   input,err=app.validate.authority(request:data())
   if not input then return syncError(_ENV,422,err,back) end
   local existing
   existing,err=app.store.getAuthorityByName(input.name)
   if err then return syncError(_ENV,500,"The certificate database could not be read.",back) end
   if existing then return syncError(_ENV,409,"An authority with that name already exists.",back) end
   local htmx=request:header"HX-Request" and true or false
   local defresp=response:deferred()
   worker(defresp,back,function()
      local generated
      generated,err=app.pki.createAuthority(input)
      if not generated then deferredError(defresp,err,back) return end
      local encrypted
      encrypted,err=app.keyvault.encrypt(generated.key,"authority",input.id,input.algorithm)
      generated.key=nil
      if not encrypted then deferredError(defresp,err,back) return end
      local record={
         id=input.id,name=input.name,algorithm=input.algorithm,hash_algorithm=generated.hash,
         dn_json=ba.json.encode(input.dn),csr_pem=generated.csr,cert_pem=generated.certificate,
         cert_der=generated.der,parsed_json=ba.json.encode(generated.parsed),
         fingerprint_sha256=generated.fingerprint,shark_ca_list=generated.shark_ca_list,
         key_ciphertext=encrypted.ciphertext,key_iv=encrypted.iv,key_tag=encrypted.tag,
         key_mode=encrypted.mode,key_version=encrypted.version,created_at=input.created_at,
         not_before=input.not_before,not_after=input.not_after
      }
      app.store.insertAuthority(record,function(id,storeErr)
         if not id then
            local conflict=storeErr == "authority name already exists" or
               tostring(storeErr):find("UNIQUE constraint failed: authorities.name",1,true)
            deferredError(defresp,friendlyDatabaseError(storeErr),back,conflict and 409 or 500)
            return
         end
         deferredRedirect(defresp,app.base.."authority.html?id="..ba.urlencode(id),htmx)
      end)
   end)
   return true
end

local function failIssuance(defresp,record,message,back)
   app.store.failCertificate(record.id,record.authority_id,message,function(_,storeErr)
      if storeErr then message=tostring(message).." (failure record error: "..tostring(storeErr)..")" end
      deferredError(defresp,message,back)
   end)
end

local function createCertificate(_ENV)
   local authorityId=app.util.trim(request:data"authority")
   local back=app.base.."issue.html"..(authorityId ~= "" and "?ca="..ba.urlencode(authorityId) or "")
   local valid,err,status=app.security.checkPost(request)
   if not valid then return syncError(_ENV,status,err,back) end
   local authority
   authority,err=app.store.getAuthority(authorityId,true)
   if not authority then return syncError(_ENV,404,err or "Authority not found.",back) end
   local input
   input,err=app.validate.certificate(request:data(),authority)
   if not input then return syncError(_ENV,422,err,back) end
   local htmx=request:header"HX-Request" and true or false
   local defresp=response:deferred()
   app.store.reserveCertificate({
      id=input.id,authority_id=input.authority_id,label=input.label,common_name=input.common_name,
      dn_json=ba.json.encode(input.dn),san_json=ba.json.encode(input.san_list),
      created_at=input.created_at,not_before=input.not_before,not_after=input.not_after
   },function(reservation,reserveErr)
      if not reservation then deferredError(defresp,friendlyDatabaseError(reserveErr),back) return end
      input.serial=reservation.serial
      worker(defresp,back,function()
         local generated
         generated,err=app.pki.createTlsServer(input,reservation.authority,app.keyvault)
         if not generated then failIssuance(defresp,input,err,back) return end
         local encrypted
         encrypted,err=app.keyvault.encrypt(generated.key,"certificate",input.id,reservation.authority.algorithm)
         generated.key=nil
         if not encrypted then failIssuance(defresp,input,err,back) return end
         app.store.completeCertificate({
            id=input.id,authority_id=input.authority_id,serial=input.serial,label=input.label,
            csr_pem=generated.csr,cert_pem=generated.certificate,cert_der=generated.der,
            parsed_json=ba.json.encode(generated.parsed),fingerprint_sha256=generated.fingerprint,
            key_ciphertext=encrypted.ciphertext,key_iv=encrypted.iv,key_tag=encrypted.tag,
            key_mode=encrypted.mode,key_version=encrypted.version,completed_at=os.time()
         },function(id,completeErr)
            if not id then
               failIssuance(defresp,input,"Certificate was signed but could not be committed: "..
                  tostring(completeErr),back)
               return
            end
            deferredRedirect(defresp,app.base.."certificate.html?id="..ba.urlencode(id),htmx)
         end)
      end)
   end)
   return true
end

local function startTest(_ENV)
   local back=app.base.."test.html"
   local valid,err,status=app.security.checkPost(request)
   if not valid then return syncError(_ENV,status,err,back) end
   local id=app.util.trim(request:data"certificate")
   if not id:match("^[0-9a-f]+$") or #id ~= 32 then
      return syncError(_ENV,422,"Select a valid certificate.",back)
   end
   local certificate
   certificate,err=app.store.getCertificate(id,true)
   if not certificate then return syncError(_ENV,404,err or "Certificate not found.",back) end
   local htmx=request:header"HX-Request" and true or false
   local defresp=response:deferred()
   worker(defresp,back,function()
      local status
      status,err=app.listener.start(certificate)
      if not status then deferredError(defresp,err,back) return end
      deferredRedirect(defresp,back.."?certificate="..ba.urlencode(id),htmx)
   end)
   return true
end

local function stopTest(_ENV)
   local back=app.base.."test.html"
   local valid,err,status=app.security.checkPost(request)
   if not valid then return syncError(_ENV,status,err,back) end
   app.listener.stop()
   if request:header"HX-Request" then
      response:setstatus(200)
      response:setheader("HX-Redirect",back)
   else
      response:setstatus(303)
      response:setheader("Location",back)
   end
   response:setcontentlength(0)
   return true
end

local function downloadPrivateKey(_ENV)
   local id=app.util.trim(request:data"certificate")
   local back=app.base.."certificates.html"
   if id:match("^[0-9a-f]+$") and #id == 32 then
      back=app.base.."certificate.html?id="..ba.urlencode(id)
   end
   local valid,err,status=app.security.checkPost(request)
   if not valid then return syncError(_ENV,status,err,back) end
   if not id:match("^[0-9a-f]+$") or #id ~= 32 then
      return syncError(_ENV,422,"Select a valid certificate.",back)
   end
   local certificate
   certificate,err=app.store.getCertificate(id,true)
   if not certificate or certificate.status ~= "active" or not certificate.key_ciphertext then
      return syncError(_ENV,404,err or "Certificate key not found.",back)
   end
   local defresp=response:deferred()
   worker(defresp,back,function()
      local privateKey
      privateKey,err=app.keyvault.decrypt(certificate,"certificate",id,certificate.algorithm)
      certificate=nil
      if not privateKey then deferredError(defresp,err,back) return end
      app.store.recordCertificateKeyExport(id,function(exportId,auditErr)
         if not exportId then
            privateKey=nil
            deferredError(defresp,"The private-key export could not be audited.",back,500)
            if auditErr then trace("certmgr private-key export audit failed",auditErr) end
            return
         end
         deferredDownload(defresp,privateKey,"application/octet-stream",
            "certificate-"..id.."-private-key.pem")
         privateKey=nil
      end)
   end)
   return true
end

local actions={
   ["create-authority"]=createAuthority,
   ["create-certificate"]=createCertificate,
   ["start-test"]=startTest,
   ["stop-test"]=stopTest,
   ["download-private-key"]=downloadPrivateKey
}

local function actionHandler(_ENV,relpath)
   local handler=actions[relpath]
   if not handler then return syncError(_ENV,404,"Action not found.",app.base) end
   return handler(_ENV)
end

local function downloadHandler(_ENV,relpath)
   if request:method() ~= "GET" and request:method() ~= "HEAD" then
      return syncError(_ENV,405,"Downloads require GET.",app.base)
   end
   local kind,id,extension=relpath:match("^(authority)/([0-9a-f]+)%.(.+)$")
   if not kind then kind,id,extension=relpath:match("^(certificate)/([0-9a-f]+)%.(.+)$") end
   if not kind or #id ~= 32 then return syncError(_ENV,404,"Download not found.",app.base) end
   local data,contentType,filename,err
   if kind == "authority" then
      local authority
      authority,err=app.store.getAuthority(id,false)
      if not authority then return syncError(_ENV,404,err or "Authority not found.",app.base) end
      if extension == "pem" then
         data=authority.cert_pem contentType="application/x-pem-file" filename="authority-"..id..".pem"
      elseif extension == "cer" then
         data=authority.cert_der contentType="application/pkix-cert" filename="authority-"..id..".cer"
      elseif extension == "shark-ca.bin" then
         data=authority.shark_ca_list contentType="application/octet-stream" filename="authority-"..id.."-shark-ca.bin"
      end
   else
      local certificate
      certificate,err=app.store.getCertificate(id,false)
      if not certificate or certificate.status ~= "active" then
         return syncError(_ENV,404,err or "Certificate not found.",app.base)
      end
      if extension == "pem" then
         data=certificate.cert_pem contentType="application/x-pem-file" filename="certificate-"..id..".pem"
      elseif extension == "cer" then
         data=certificate.cert_der contentType="application/pkix-cert" filename="certificate-"..id..".cer"
      elseif extension == "chain.pem" then
         data=certificate.cert_pem..certificate.authority_cert_pem
         contentType="application/x-pem-file" filename="certificate-"..id.."-chain.pem"
      end
   end
   if not data then return syncError(_ENV,404,"Download format not found.",app.base) end
   app.security.dynamicHeaders(response)
   response:setcontenttype(contentType)
   response:setheader("Content-Disposition",'attachment; filename="'..filename..'"')
   response:setcontentlength(#data)
   if request:method() == "GET" then response:write(data) end
   return true
end

function M.install()
   local actionDir=ba.create.dir"actions"
   actionDir:setfunc(actionHandler)
   app.dir:insert(actionDir,true)
   local downloadDir=ba.create.dir"downloads"
   downloadDir:setfunc(downloadHandler)
   app.dir:insert(downloadDir,true)
   return actionDir,downloadDir
end

return M
