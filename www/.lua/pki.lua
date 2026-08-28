local config,util=app.config,app.util
local M={}

local algorithms={
   ["ecc-p256"]={family="ecc",key={key="ecc",curve="SECP256R1"},hash="sha256",label="Elliptic curve P-256"},
   ["ecc-p384"]={family="ecc",key={key="ecc",curve="SECP384R1"},hash="sha384",label="Elliptic curve P-384"},
   ["rsa-2048"]={family="rsa",key={key="rsa",bits=2048},hash="sha256",label="RSA, 2048-bit"},
   ["rsa-3072"]={family="rsa",key={key="rsa",bits=3072},hash="sha384",label="RSA, 3072-bit"}
}

M.algorithms=algorithms

local function call(label,func,...)
   local ok,a,b=pcall(func,...)
   if not ok then return nil,label.." failed: "..tostring(a) end
   if not a then return nil,label.." failed: "..tostring(b) end
   return a
end

local function fingerprint(der)
   return util.hex(ba.crypto.hash("sha256")(der)(true)):upper()
end

local function inspect(certPem)
   local der,err=util.pemToDer(certPem)
   if not der then return nil,err end
   local parsed,parseErr=call("certificate inspection",ba.parsecert,der)
   if not parsed then return nil,parseErr end
   return der,parsed,fingerprint(der)
end

function M.tpmAuthoritySupported()
   return type(ba.tpm) == "table" and type(ba.tpm.createcertificate) == "function"
end

function M.tpmAuthorityEnabled()
   return config.keyMode == "unique" and M.tpmAuthoritySupported()
end

local function tpmKeyName(id)
   return "certmgr.authority."..id..".v1"
end

local function ensureTpmKey(authority,algorithm)
   local expected=tpmKeyName(authority.id)
   if authority.tpm_key_name ~= expected then
      return nil,"invalid TPM authority-key reference"
   end
   if not ba.tpm.haskey(expected) then
      local ok,err=call("TPM authority-key recreation",ba.tpm.createkey,expected,algorithm.key)
      if not ok then return nil,err end
   end
   return expected
end

function M.createAuthority(input)
   local algorithm=algorithms[input.algorithm]
   if not algorithm then return nil,"unsupported authority algorithm" end
   if algorithm.family == "ecc" and M.tpmAuthorityEnabled() then
      local keyName=tpmKeyName(input.id)
      local ok,err=call("TPM authority-key generation",ba.tpm.createkey,keyName,algorithm.key)
      if not ok then return nil,err end
      local csr
      csr,err=call("authority certificate-request generation",ba.tpm.createcsr,keyName,input.dn,
         {"SSL_CA"},{"KEY_CERT_SIGN","CRL_SIGN"},algorithm.hash)
      if not csr then return nil,err end
      local certificate
      certificate,err=call("authority certificate generation",ba.tpm.createcertificate,keyName,
         csr,util.utcDate(input.not_before),util.utcDate(input.not_after),1,algorithm.hash)
      if not certificate then return nil,err end
      local der,parsed,fp=inspect(certificate)
      if not der then return nil,parsed end
      local combined
      combined,err=call("TPM authority certificate validation",ba.tpm.sharkcert,keyName,certificate)
      if not combined then return nil,err end
      local combinedData
      combinedData,err=call("TPM authority certificate validation",combined.data,combined)
      combined=nil
      if not combinedData then return nil,err end
      combinedData=nil -- Contains the private key; validate in memory but never persist it.
      local certstore,storeErr=call("SharkSSL trust-list creation",ba.create.certstore)
      if not certstore then return nil,storeErr end
      local added,addErr=certstore:addcert(certificate)
      if not added then return nil,"SharkSSL trust-list creation failed: "..tostring(addErr) end
      local caList,caListErr=certstore:data()
      if not caList then return nil,"SharkSSL trust-list serialization failed: "..tostring(caListErr) end
      return {
         key_provider="tpm",tpm_key_name=keyName,csr=csr,certificate=certificate,der=der,
         parsed=parsed,fingerprint=fp,shark_ca_list=caList,hash=algorithm.hash
      }
   end
   local key,err=call("authority key generation",ba.create.key,algorithm.key)
   if not key then return nil,err end
   local csr
   csr,err=call("authority certificate-request generation",ba.create.csr,key,input.dn,
      {"SSL_CA"},{"KEY_CERT_SIGN","CRL_SIGN"},algorithm.hash)
   if not csr then return nil,err end
   local certificate
   certificate,err=call("authority certificate generation",ba.create.certificate,
      csr,key,util.utcDate(input.not_before),util.utcDate(input.not_after),1,algorithm.hash)
   if not certificate then return nil,err end
   local der,parsed,fp=inspect(certificate)
   if not der then return nil,parsed end
   local certstore,storeErr=call("SharkSSL trust-list creation",ba.create.certstore)
   if not certstore then return nil,storeErr end
   local ok,addErr=certstore:addcert(certificate)
   if not ok then return nil,"SharkSSL trust-list creation failed: "..tostring(addErr) end
   local caList,caListErr=certstore:data()
   if not caList then return nil,"SharkSSL trust-list serialization failed: "..tostring(caListErr) end
   return {
      key=key,key_provider="encrypted",
      csr=csr,
      certificate=certificate,
      der=der,
      parsed=parsed,
      fingerprint=fp,
      shark_ca_list=caList,
      hash=algorithm.hash
   }
end

function M.createTlsServer(input,authority,keyvault)
   local algorithm=algorithms[authority.algorithm]
   if not algorithm then return nil,"authority uses an unsupported algorithm" end
   local caKey,caKeyName,err
   if authority.key_provider == "tpm" then
      if algorithm.family ~= "ecc" then
         return nil,"TPM authority uses an unsupported key algorithm"
      end
      if not M.tpmAuthoritySupported() then
         return nil,"TPM authority signing is unavailable in this Mako Server build"
      end
      caKeyName,err=ensureTpmKey(authority,algorithm)
      if not caKeyName then return nil,err end
   elseif authority.key_provider == "encrypted" then
      caKey,err=keyvault.decrypt(authority,"authority",authority.id,authority.algorithm)
      if not caKey then return nil,err end
   else
      return nil,"authority uses an unsupported private-key provider"
   end
   local leafKey
   leafKey,err=call("server-key generation",ba.create.key,algorithm.key)
   if not leafKey then caKey=nil return nil,err end
   local keyUsage=algorithm.family == "rsa" and
      {"DIGITAL_SIGNATURE","KEY_ENCIPHERMENT"} or {"DIGITAL_SIGNATURE","KEY_AGREEMENT"}
   local csr
   csr,err=call("server certificate-request generation",ba.create.csr,leafKey,input.dn,input.san,
      {"SSL_SERVER"},keyUsage,algorithm.hash)
   if not csr then caKey=nil leafKey=nil return nil,err end
   local certificate
   if caKeyName then
      certificate,err=call("server-certificate signing",ba.tpm.createcertificate,caKeyName,csr,
         authority.cert_pem,util.utcDate(input.not_before),util.utcDate(input.not_after),
         input.serial,algorithm.hash)
   else
      certificate,err=call("server-certificate signing",ba.create.certificate,csr,
         authority.cert_pem,caKey,util.utcDate(input.not_before),util.utcDate(input.not_after),
         input.serial,algorithm.hash)
   end
   caKey=nil
   if not certificate then leafKey=nil return nil,err end
   local der,parsed,fp=inspect(certificate)
   if not der then leafKey=nil return nil,parsed end
   local shark,sharkErr=call("SharkSSL certificate validation",ba.create.sharkcert,certificate,leafKey)
   if not shark then leafKey=nil return nil,sharkErr end
   local sharkData,dataErr=shark:data()
   if not sharkData then leafKey=nil return nil,"SharkSSL certificate serialization failed: "..tostring(dataErr) end
   sharkData=nil -- Contains the private key; validate in memory but never persist it.
   return {
      key=leafKey,
      csr=csr,
      certificate=certificate,
      der=der,
      parsed=parsed,
      fingerprint=fp,
      hash=algorithm.hash
   }
end

return M
