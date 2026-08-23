local app=app
if not dir then error"Certificate Manager must run as an LSP application" end

local rw=require"rwfile"
local io,appDir=app.io,app.dir

local function parsePage(name)
   local data,err=rw.file(io,name)
   if data then data,err=ba.parselsp(data) end
   if data then
      local func
      func,err=load(data,name,"t")
      if func then return func end
   end
   error(string.format("Cannot load %s: %s",name,tostring(err)))
end

local template=parsePage".lua/www/template.lsp"
local menu=assert(rw.json(io,".lua/menu.json"),"menu.json parse error")
local byPath={}
for _,item in ipairs(menu) do byPath[item.href]=item end
local pageState={}

local function cms(_ENV,relpath)
   local hx=request:header"HX-Request"
   local restore=request:header"HX-History-Restore-Request"
   if relpath == "" or relpath:sub(-1) == "/" then relpath=relpath.."index.html" end
   if not byPath[relpath] then
      if relpath:sub(-5) ~= ".html" then return false end
      response:setstatus(404)
      relpath="404.html"
   end
   local page=pageState[relpath]
   if not page then page={} pageState[relpath]=page end
   local compressed <close> = response:setresponse()
   response:setdefaultheaders()
   app.security.dynamicHeaders(response)
   response:setcontenttype"text/html; charset=utf-8"
   local content=parsePage(".lua/www/"..relpath)
   if hx and not restore then
      content(_ENV,relpath,io,page,app)
   else
      _ENV.certmgrMenu=menu
      _ENV.certmgrMenuByPath=byPath
      _ENV.certmgrRelpath=relpath
      _ENV.certmgrContent=content
      template(_ENV,relpath,io,page,app)
   end
   compressed:finalize(true)
   return true
end

local cmsDir=ba.create.dir()
cmsDir:setfunc(cms)
appDir:insert(cmsDir,true)
return cmsDir
