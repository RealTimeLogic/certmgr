local config,util=app.config,app.util
local M={}

local function masterKey(mode)
   if not ba.tpm then return nil,"Mako Server's private-key protection service is unavailable" end
   local derive=mode == "global" and ba.tpm.globalkey or ba.tpm.uniquekey
   if type(derive) ~= "function" then return nil,"The configured private-key protection mode is unavailable" end
   local ok,raw=pcall(derive,config.keyName,32)
   if not ok or not raw then return nil,"Private-key protection failed: "..tostring(raw) end
   local hash=ba.crypto.hash"sha256"
   return hash(raw)(true)
end

local function aad(kind,id,algorithm)
   return table.concat{"certmgr-key-v1",kind,id,algorithm},"\0"
end

function M.encrypt(plaintext,kind,id,algorithm,mode)
   mode=mode or config.keyMode
   if type(plaintext) ~= "string" or #plaintext == 0 then return nil,"private key is empty" end
   if #plaintext > 0xFFF0 then return nil,"The private key is too large to encrypt" end
   local key,err=masterKey(mode)
   if not key then return nil,err end
   local iv=ba.rndbs(12)
   local cipher=ba.crypto.symmetric("GCM",key,iv)
   cipher:setauth(aad(kind,id,algorithm))
   local ciphertext,tag=cipher:encrypt(plaintext)
   key=nil
   if not ciphertext or not tag then return nil,"private key encryption failed" end
   return {
      ciphertext=ciphertext,
      iv=iv,
      tag=tag,
      mode=mode,
      version=1
   }
end

function M.decrypt(record,kind,id,algorithm)
   if tonumber(record.key_version) ~= 1 then return nil,"unsupported private-key record version" end
   local mode=record.key_mode
   if mode ~= "unique" and mode ~= "global" then return nil,"invalid private-key protection mode" end
   local key,err=masterKey(mode)
   if not key then return nil,err end
   local cipher=ba.crypto.symmetric("GCM",key,record.key_iv)
   cipher:setauth(aad(kind,id,algorithm))
   local ok,plaintext=pcall(cipher.decrypt,cipher,record.key_ciphertext,record.key_tag)
   key=nil
   if not ok or not plaintext then
      return nil,"private key authentication/decryption failed"
   end
   return plaintext
end

return M
