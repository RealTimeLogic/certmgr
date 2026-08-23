<?lsp
local item=certmgrMenuByPath[certmgrRelpath] or {name="Certificate Manager",href=""}
local active=item.active or item.href
local function navUrl(href)
   local ca=app.util.trim(request:data"ca")
   if ca ~= "" and (href == "index.html" or href == "issue.html" or href == "certificates.html") then
      return app.base..href.."?ca="..ba.urlencode(ca)
   end
   return app.base..href
end
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="htmx-config" content='{"timeout":10000,"includeIndicatorStyles":false,"allowEval":false,"allowScriptTags":false,"responseHandling":[{"code":"204","swap":false},{"code":"[23]..","swap":true},{"code":"[45]..","swap":true,"error":true}]}'>
  <title><?lsp=app.util.html(item.name)?> · Certificate Manager</title>
  <link rel="stylesheet" href="<?lsp=app.base?>static/styles.css?v=5">
  <script src="<?lsp=app.base?>static/htmx.min.js" defer></script>
  <script src="<?lsp=app.base?>static/ui.js?v=4" defer></script>
</head>
<body>
<div class="app-shell" id="layout">
  <aside class="sidebar" id="sidebar">
    <div class="brand-block">
      <a class="brand" href="<?lsp=app.base?>" aria-label="Certificate Manager home">
        <span class="brand-mark" aria-hidden="true">RTL</span>
        <span><strong>Certificate</strong><small>Manager</small></span>
      </a>
    </div>
    <nav aria-label="Main navigation">
      <ul class="nav-list">
      <?lsp for _,nav in ipairs(certmgrMenu) do if not nav.hidden then local href=navUrl(nav.href) ?>
        <li><a class="nav-link<?lsp=active == nav.href and ' is-active' or ''?>" href="<?lsp=href?>"
          hx-get="<?lsp=href?>" hx-target="#main" hx-push-url="true">
          <span class="nav-mark" aria-hidden="true"><?lsp=app.util.html(nav.mark)?></span>
          <span><?lsp=app.util.html(nav.name)?></span></a></li>
      <?lsp end end ?>
      </ul>
    </nav>
    <div class="sidebar-foot"><span class="local-dot"></span>Local access only</div>
  </aside>
  <button class="menu-button" type="button" data-menu-toggle aria-controls="sidebar" aria-expanded="false">
    <span></span><span></span><span></span><span class="sr-only">Toggle navigation</span>
  </button>
  <main class="main" id="main" hx-history-elt>
    <?lsp certmgrContent(_ENV,certmgrRelpath,io,page,app) ?>
  </main>
</div>
</body>
</html>
