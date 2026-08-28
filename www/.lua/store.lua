local config,util=app.config,app.util
local sqlutil=require"sqlutil"
local M={}

local env,conn=sqlutil.open("certmgr")
conn:setbusytimeout(config.busyTimeout)

local function closeCursor(value)
   if type(value) == "userdata" then pcall(value.close,value) end
end

local function execute(sql)
   local result,err=conn:execute(sql)
   if not result then error(err) end
   closeCursor(result)
end

execute("PRAGMA foreign_keys=ON")
execute("PRAGMA journal_mode=DELETE")
execute([[
CREATE TABLE IF NOT EXISTS schema_meta (
   singleton INTEGER PRIMARY KEY CHECK(singleton=1),
   version INTEGER NOT NULL,
   created_at INTEGER NOT NULL
) ]])
execute([[
CREATE TABLE IF NOT EXISTS authorities (
   id TEXT PRIMARY KEY,
   name TEXT NOT NULL UNIQUE,
   algorithm TEXT NOT NULL,
   hash_algorithm TEXT NOT NULL,
   dn_json TEXT NOT NULL,
   csr_pem TEXT NOT NULL,
   cert_pem TEXT NOT NULL,
   cert_der BLOB NOT NULL,
   parsed_json TEXT NOT NULL,
   fingerprint_sha256 TEXT NOT NULL,
   shark_ca_list BLOB NOT NULL,
   key_ciphertext BLOB NOT NULL,
   key_iv BLOB NOT NULL,
   key_tag BLOB NOT NULL,
   key_mode TEXT NOT NULL CHECK(key_mode IN ('unique','global')),
   key_version INTEGER NOT NULL,
   key_provider TEXT NOT NULL DEFAULT 'encrypted' CHECK(key_provider IN ('encrypted','tpm')),
   tpm_key_name TEXT,
   created_at INTEGER NOT NULL,
   not_before INTEGER NOT NULL,
   not_after INTEGER NOT NULL,
   next_serial INTEGER NOT NULL CHECK(next_serial >= 2),
   status TEXT NOT NULL CHECK(status IN ('active','disabled'))
) ]])
execute([[
CREATE TABLE IF NOT EXISTS certificates (
   id TEXT PRIMARY KEY,
   authority_id TEXT NOT NULL REFERENCES authorities(id),
   serial INTEGER NOT NULL,
   label TEXT NOT NULL,
   common_name TEXT NOT NULL,
   algorithm TEXT NOT NULL,
   profile TEXT NOT NULL CHECK(profile='tls-server'),
   hash_algorithm TEXT NOT NULL,
   dn_json TEXT NOT NULL,
   san_json TEXT NOT NULL,
   csr_pem TEXT,
   cert_pem TEXT,
   cert_der BLOB,
   parsed_json TEXT,
   fingerprint_sha256 TEXT,
   key_ciphertext BLOB,
   key_iv BLOB,
   key_tag BLOB,
   key_mode TEXT CHECK(key_mode IN ('unique','global')),
   key_version INTEGER,
   created_at INTEGER NOT NULL,
   not_before INTEGER NOT NULL,
   not_after INTEGER NOT NULL,
   completed_at INTEGER,
   status TEXT NOT NULL CHECK(status IN ('pending','active','failed')),
   error TEXT,
   UNIQUE(authority_id,serial)
) ]])
execute("CREATE INDEX IF NOT EXISTS certificates_authority_status ON certificates(authority_id,status,serial)")
execute([[
CREATE TABLE IF NOT EXISTS audit_events (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   occurred_at INTEGER NOT NULL,
   event_type TEXT NOT NULL,
   authority_id TEXT,
   certificate_id TEXT,
   details_json TEXT NOT NULL
) ]])
execute("INSERT OR IGNORE INTO schema_meta(singleton,version,created_at) VALUES(1,2,strftime('%s','now'))")

local transactionStarted=false
do
   local cur=assert(conn:execute("SELECT version FROM schema_meta WHERE singleton=1"))
   local row=cur:fetch({},"a")
   cur:close()
   local version=row and tonumber(row.version)
   if version == 1 then
      assert(conn:setautocommit("IMMEDIATE"))
      transactionStarted=true
      execute("ALTER TABLE authorities ADD COLUMN key_provider TEXT NOT NULL DEFAULT 'encrypted' CHECK(key_provider IN ('encrypted','tpm'))")
      execute("ALTER TABLE authorities ADD COLUMN tpm_key_name TEXT")
      execute("UPDATE schema_meta SET version=2 WHERE singleton=1")
      assert(conn:commit("IMMEDIATE"))
   elseif version ~= 2 then
      error("unsupported certmgr SQLite schema version: "..tostring(version))
   end
end

if not transactionStarted then assert(conn:setautocommit("IMMEDIATE")) end
local writer=ba.thread.create()
local closing=false

local function bindValue(value,kind)
   if value == nil then return {"NULL",0} end
   return {kind or "TEXT",value}
end

local function statement(db,sql,values)
   local stmt,err=db:prepare(sql)
   if not stmt then return nil,err end
   if values then
      local ok
      ok,err=stmt:bind(values)
      if not ok then stmt:close() return nil,err end
   end
   local result
   result,err=stmt:execute()
   if not result then stmt:close() return nil,err end
   return result,stmt
end

local function update(db,sql,values)
   local result,stmt=statement(db,sql,values)
   if not result then return nil,stmt end
   stmt:close()
   return result
end

local function one(db,sql,values)
   local result,stmt=statement(db,sql,values)
   if not result then return nil,stmt end
   local row=result:fetch({},"a")
   result:close()
   return row
end

local function audit(db,eventType,authorityId,certificateId,details)
   return update(db,[[
      INSERT INTO audit_events(occurred_at,event_type,authority_id,certificate_id,details_json)
      VALUES(?,?,?,?,?)]],{
      {"INTEGER",os.time()},{"TEXT",eventType},bindValue(authorityId),bindValue(certificateId),
      {"TEXT",ba.json.encode(details or {})}
   })
end

local function finishCallback(callback,...)
   if not callback then return end
   local ok,err=pcall(callback,...)
   if not ok then trace("certmgr completion callback failed",err) end
end

local function write(operation,callback)
   if closing then finishCallback(callback,nil,"certificate database is closing") return end
   writer:run(function()
      local called,result,opErr=pcall(operation,conn)
      local ok=called and result ~= nil
      if not called then opErr=result result=nil end
      if ok then
         local committed,commitErr=conn:commit("IMMEDIATE")
         if not committed then ok=false opErr=commitErr result=nil end
      end
      if not ok then
         local rolledBack,rollbackErr=conn:rollback("IMMEDIATE")
         if not rolledBack then
            opErr=tostring(opErr).."; rollback failed: "..tostring(rollbackErr)
         end
      end
      finishCallback(callback,result,opErr)
   end)
end

function M.insertAuthority(record,callback)
   record.key_provider=record.key_provider or "encrypted"
   if record.key_provider == "tpm" then
      if record.key_mode ~= "unique" or type(record.algorithm) ~= "string" or
         not record.algorithm:match("^ecc%-") or
         record.tpm_key_name ~= "certmgr.authority."..record.id..".v1" or
         record.key_ciphertext ~= "" or record.key_iv ~= "" or record.key_tag ~= "" then
         finishCallback(callback,nil,"invalid TPM authority-key record")
         return
      end
   elseif record.key_provider ~= "encrypted" or record.tpm_key_name ~= nil then
      finishCallback(callback,nil,"invalid encrypted authority-key record")
      return
   end
   write(function(db)
      local existing,err=one(db,"SELECT id FROM authorities WHERE name=?",{{"TEXT",record.name}})
      if existing then return nil,"authority name already exists" end
      if err then return nil,err end
      local count,err=one(db,"SELECT count(*) AS n FROM authorities")
      if not count then return nil,err end
      if tonumber(count.n) >= config.maxAuthorities then return nil,"authority limit reached" end
      local result
      result,err=update(db,[[
         INSERT INTO authorities(
            id,name,algorithm,hash_algorithm,dn_json,csr_pem,cert_pem,cert_der,
            parsed_json,fingerprint_sha256,shark_ca_list,key_ciphertext,key_iv,key_tag,
            key_mode,key_version,key_provider,tpm_key_name,created_at,not_before,not_after,
            next_serial,status)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)]],{
         {"TEXT",record.id},{"TEXT",record.name},{"TEXT",record.algorithm},{"TEXT",record.hash_algorithm},
         {"TEXT",record.dn_json},{"TEXT",record.csr_pem},{"TEXT",record.cert_pem},{"BLOB",record.cert_der},
         {"TEXT",record.parsed_json},{"TEXT",record.fingerprint_sha256},{"BLOB",record.shark_ca_list},
         {"BLOB",record.key_ciphertext},{"BLOB",record.key_iv},{"BLOB",record.key_tag},
         {"TEXT",record.key_mode},{"INTEGER",record.key_version},{"TEXT",record.key_provider},
         bindValue(record.tpm_key_name),{"INTEGER",record.created_at},
         {"INTEGER",record.not_before},{"INTEGER",record.not_after},{"INTEGER",2},{"TEXT","active"}
      })
      if not result then return nil,err end
      result,err=audit(db,"authority-created",record.id,nil,
         {name=record.name,algorithm=record.algorithm,key_provider=record.key_provider})
      if not result then return nil,err end
      return record.id
   end,callback)
end

function M.getAuthorityByName(name)
   return M.withReader(function(db)
      return one(db,"SELECT id FROM authorities WHERE name=?",{{"TEXT",name}})
   end)
end

function M.validateKeyConfiguration(hasTpmCertificateApi)
   local row,err=M.withReader(function(db)
      return one(db,"SELECT count(*) AS n FROM authorities WHERE key_provider='tpm'")
   end)
   if not row then return nil,err end
   if tonumber(row.n) == 0 then return true end
   if config.keyMode ~= "unique" then
      return nil,"mako.conf certmgr.keyMode cannot be changed to 'global' because this database "..
         "contains device-bound elliptic-curve authority keys. The Certificate Manager database must be rebuilt."
   end
   if not hasTpmCertificateApi then
      return nil,"This database contains device-bound elliptic-curve authority keys, but this Mako Server "..
         "build cannot use them. Rebuild Mako Server with ba.tpm.createcertificate support."
   end
   return true
end

function M.reserveCertificate(record,callback)
   write(function(db)
      local authority,err=one(db,"SELECT * FROM authorities WHERE id=? AND status='active'",{{"TEXT",record.authority_id}})
      if not authority then return nil,err or "authority not found" end
      local count
      count,err=one(db,"SELECT count(*) AS n FROM certificates WHERE authority_id=?",{{"TEXT",record.authority_id}})
      if not count then return nil,err end
      if tonumber(count.n) >= config.maxCertificatesPerAuthority then
         return nil,"certificate limit reached for this authority"
      end
      local serial=tonumber(authority.next_serial)
      local result
      result,err=update(db,[[
         INSERT INTO certificates(
            id,authority_id,serial,label,common_name,algorithm,profile,hash_algorithm,
            dn_json,san_json,created_at,not_before,not_after,status)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'pending')]],{
         {"TEXT",record.id},{"TEXT",record.authority_id},{"INTEGER",serial},{"TEXT",record.label},
         {"TEXT",record.common_name},{"TEXT",authority.algorithm},{"TEXT","tls-server"},
         {"TEXT",authority.hash_algorithm},{"TEXT",record.dn_json},{"TEXT",record.san_json},
         {"INTEGER",record.created_at},{"INTEGER",record.not_before},{"INTEGER",record.not_after}
      })
      if not result then return nil,err end
      result,err=update(db,"UPDATE authorities SET next_serial=? WHERE id=?",{
         {"INTEGER",serial+1},{"TEXT",record.authority_id}})
      if not result then return nil,err end
      result,err=audit(db,"certificate-serial-reserved",record.authority_id,record.id,
         {serial=serial,label=record.label,profile="tls-server"})
      if not result then return nil,err end
      authority.next_serial=tostring(serial+1)
      return {id=record.id,serial=serial,authority=authority}
   end,callback)
end

function M.completeCertificate(record,callback)
   write(function(db)
      local result,err=update(db,[[
         UPDATE certificates SET
            csr_pem=?,cert_pem=?,cert_der=?,parsed_json=?,fingerprint_sha256=?,
            key_ciphertext=?,key_iv=?,key_tag=?,key_mode=?,key_version=?,completed_at=?,status='active',error=NULL
         WHERE id=? AND status='pending']],{
         {"TEXT",record.csr_pem},{"TEXT",record.cert_pem},{"BLOB",record.cert_der},
         {"TEXT",record.parsed_json},{"TEXT",record.fingerprint_sha256},
         {"BLOB",record.key_ciphertext},{"BLOB",record.key_iv},{"BLOB",record.key_tag},
         {"TEXT",record.key_mode},{"INTEGER",record.key_version},{"INTEGER",record.completed_at},
         {"TEXT",record.id}
      })
      if not result then return nil,err end
      result,err=audit(db,"certificate-issued",record.authority_id,record.id,
         {serial=record.serial,label=record.label,profile="tls-server"})
      if not result then return nil,err end
      return record.id
   end,callback)
end

function M.failCertificate(id,authorityId,message,callback)
   message=tostring(message or "certificate issuance failed"):sub(1,1000)
   write(function(db)
      local result,err=update(db,[[
         UPDATE certificates SET status='failed',error=?,completed_at=?
         WHERE id=? AND status='pending']],{
         {"TEXT",message},{"INTEGER",os.time()},{"TEXT",id}
      })
      if not result then return nil,err end
      result,err=audit(db,"certificate-failed",authorityId,id,{message=message})
      if not result then return nil,err end
      return id
   end,callback)
end

function M.recoverPending(callback)
   write(function(db)
      local rows,err=M.queryAll(db,"SELECT id,authority_id,serial FROM certificates WHERE status='pending'")
      if not rows then return nil,err end
      for _,row in ipairs(rows) do
         local result
         result,err=update(db,[[
            UPDATE certificates SET status='failed',error=?,completed_at=?
            WHERE id=? AND status='pending']],{
            {"TEXT","Issuance was interrupted before completion."},{"INTEGER",os.time()},{"TEXT",row.id}
         })
         if not result then return nil,err end
         result,err=audit(db,"certificate-recovered-as-failed",row.authority_id,row.id,
            {serial=tonumber(row.serial)})
         if not result then return nil,err end
      end
      return #rows
   end,callback)
end

function M.withReader(operation)
   local readEnv,readConn
   local ok,result,err=pcall(function()
      readEnv,readConn=sqlutil.open("certmgr","READONLY")
      readConn:setbusytimeout(config.busyTimeout)
      return operation(readConn)
   end)
   if readConn then pcall(readConn.close,readConn) end
   if readEnv then pcall(readEnv.close,readEnv) end
   if not ok then return nil,result end
   return result,err
end

function M.queryAll(db,sql,values)
   local result,stmt=statement(db,sql,values)
   if not result then return nil,stmt end
   local rows={}
   local row=result:fetch({},"a")
   while row do
      rows[#rows+1]=row
      row=result:fetch({},"a")
   end
   result:close()
   return rows
end

function M.listAuthorities()
   return M.withReader(function(db)
      return M.queryAll(db,[[
         SELECT a.id,a.name,a.algorithm,a.hash_algorithm,a.fingerprint_sha256,a.created_at,
                a.not_before,a.not_after,a.next_serial,a.key_mode,a.key_provider,a.status,
                sum(CASE WHEN c.status='active' THEN 1 ELSE 0 END) AS issued_count,
                sum(CASE WHEN c.status='failed' THEN 1 ELSE 0 END) AS failed_count
         FROM authorities a LEFT JOIN certificates c ON c.authority_id=a.id
         GROUP BY a.id ORDER BY lower(a.name),a.id]])
   end)
end

function M.getAuthority(id,includeSecrets)
   return M.withReader(function(db)
      local columns=includeSecrets and "*" or [[
         id,name,algorithm,hash_algorithm,dn_json,csr_pem,cert_pem,cert_der,parsed_json,
         fingerprint_sha256,shark_ca_list,key_mode,key_version,key_provider,
         created_at,not_before,not_after,next_serial,status]]
      return one(db,"SELECT "..columns.." FROM authorities WHERE id=?",{{"TEXT",id}})
   end)
end

function M.listCertificates(authorityId)
   return M.withReader(function(db)
      local sql=[[
         SELECT c.id,c.authority_id,c.serial,c.label,c.common_name,c.algorithm,c.profile,
                c.hash_algorithm,c.san_json,c.fingerprint_sha256,c.created_at,c.not_before,
                c.not_after,c.completed_at,c.status,c.error,a.name AS authority_name
         FROM certificates c JOIN authorities a ON a.id=c.authority_id]]
      if authorityId and authorityId ~= "" then
         return M.queryAll(db,sql.." WHERE c.authority_id=? ORDER BY c.serial DESC",{{"TEXT",authorityId}})
      end
      return M.queryAll(db,sql.." ORDER BY c.created_at DESC,c.id DESC")
   end)
end

function M.getCertificate(id,includeSecrets)
   return M.withReader(function(db)
      local secret=includeSecrets and
         ",c.key_ciphertext,c.key_iv,c.key_tag,c.key_mode,c.key_version" or ""
      return one(db,[[
         SELECT c.id,c.authority_id,c.serial,c.label,c.common_name,c.algorithm,c.profile,
                c.hash_algorithm,c.dn_json,c.san_json,c.csr_pem,c.cert_pem,c.cert_der,
                c.parsed_json,c.fingerprint_sha256,c.created_at,c.not_before,c.not_after,
                c.completed_at,c.status,c.error,a.name AS authority_name,a.cert_pem AS authority_cert_pem
      ]]..secret..[[ FROM certificates c JOIN authorities a ON a.id=c.authority_id WHERE c.id=?]],
         {{"TEXT",id}})
   end)
end

function M.recordCertificateKeyExport(id,callback)
   write(function(db)
      local certificate,err=one(db,[[
         SELECT authority_id,status,key_ciphertext IS NOT NULL AS has_key
         FROM certificates WHERE id=?]],{{"TEXT",id}})
      if not certificate or certificate.status ~= "active" or tonumber(certificate.has_key) ~= 1 then
         return nil,err or "active certificate key not found"
      end
      local result
      result,err=audit(db,"certificate-private-key-export-requested",
         certificate.authority_id,id,{format="pem"})
      if not result then return nil,err end
      return id
   end,callback)
end

function M.stats()
   return M.withReader(function(db)
      local row,err=one(db,[[
         SELECT
            (SELECT count(*) FROM authorities WHERE status='active') AS authorities,
            (SELECT count(*) FROM certificates WHERE status='active') AS certificates,
            (SELECT count(*) FROM certificates WHERE status='failed') AS failed,
            (SELECT min(not_after) FROM certificates WHERE status='active') AS next_expiry]])
      return row,err
   end)
end

function M.recentAudit(limit)
   limit=math.max(1,math.min(100,tonumber(limit) or 20))
   return M.withReader(function(db)
      return M.queryAll(db,"SELECT * FROM audit_events ORDER BY id DESC LIMIT "..limit)
   end)
end

function M.databasePath()
   return sqlutil.dir().."certmgr.sqlite.db"
end

function M.close()
   if closing then return end
   closing=true
   writer:run(function()
      pcall(conn.rollback,conn)
      pcall(conn.close,conn)
      pcall(env.close,env)
   end)
end

return M
