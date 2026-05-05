/* DDNS page templates
 *
 * SPDX-License-Identifier: MIT
 */
#define DDNS_CHUNK_HEAD "<html>\
<head>\
<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0'>\
<meta charset='UTF-8'>\
<title>Dynamic DNS</title>\
<link rel='icon' href='favicon.png'>\
</head>\
<style>\
* { box-sizing: border-box; margin: 0; padding: 0; }\
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: linear-gradient(135deg, #1a1d21 0%, #22262b 100%); color: #e0e0e0; padding: 1rem; min-height: 100vh; line-height: 1.6; }\
h1 { font-size: 1.5rem; font-weight: 600; color: #7eb8d4; margin-bottom: 1rem; text-shadow: 0 0 20px rgba(126, 184, 212, 0.3); }\
h2 { font-size: 1.15rem; font-weight: 500; color: #7eb8d4; margin: 1.5rem 0 0.75rem 0; padding-bottom: 0.5rem; border-bottom: 1px solid rgba(126, 184, 212, 0.2); }\
#container { max-width: 500px; margin: 0 auto; padding: 1.5rem; background: rgba(26, 29, 33, 0.9); border-radius: 16px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); backdrop-filter: blur(10px); }\
table { width: 100%; border-collapse: collapse; }\
td { padding: 0.5rem 0; vertical-align: top; }\
td:first-child { color: #888; font-size: 0.9rem; padding-right: 0.75rem; width: 35%; text-align: right; }\
input[type='text'], input[type='number'], input[type='password'] { width: 100%; background: rgba(22, 27, 34, 0.6); border: 1px solid rgba(126, 184, 212, 0.2); border-radius: 8px; color: #e0e0e0; padding: 0.75rem; font-size: 0.95rem; }\
input[type='text']:focus, input[type='number']:focus, input[type='password']:focus, select:focus { outline: none; border-color: #7eb8d4; box-shadow: 0 0 0 3px rgba(126, 184, 212, 0.1); background: rgba(22, 27, 34, 0.8); }\
input::placeholder { color: #666; }\
select { width: 100%; background: rgba(22, 27, 34, 0.6); border: 1px solid rgba(126, 184, 212, 0.2); border-radius: 8px; color: #e0e0e0; padding: 0.75rem; font-size: 0.95rem; cursor: pointer; -webkit-appearance: none; -moz-appearance: none; appearance: none; background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%237eb8d4' stroke-width='1.5' fill='none'/%3E%3C/svg%3E\"); background-repeat: no-repeat; background-position: right 0.75rem center; padding-right: 2rem; }\
select option { background: #22262b; color: #e0e0e0; }\
.ok-button { border: none; border-radius: 8px; padding: 0.75rem 1.5rem; font-size: 0.95rem; font-weight: 600; cursor: pointer; width: 100%; margin-top: 0.5rem; background: linear-gradient(135deg, #2d6a8f 0%, #1e4d6b 100%); color: #fff; box-shadow: 0 4px 15px rgba(45, 106, 143, 0.4); }\
.status-table { background: rgba(22, 27, 34, 0.6); border-radius: 12px; padding: 1rem; margin: 1rem 0; border: 1px solid rgba(126, 184, 212, 0.1); }\
.status-table table { width: 100%; }\
.status-table td { padding: 0.75rem 0.5rem; font-size: 0.95rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05); }\
.status-table tr:last-child td { border-bottom: none; }\
.status-table td:first-child { color: #888; text-align: right; padding-right: 1rem; width: 45%; font-size: 0.9rem; }\
.status-table td:last-child { color: #e0e0e0; font-weight: 500; }\
small { display: block; color: #888; font-size: 0.85rem; margin-top: 0.5rem; line-height: 1.4; }\
.flash { padding: 0.5rem 0.85rem; border-radius: 8px; margin-bottom: 1rem; font-size: 0.875rem; font-weight: 500; }\
.flash-ok   { background: rgba(76, 175, 80, 0.14); border: 1px solid rgba(76, 175, 80, 0.32); color: #81c784; }\
.flash-info { background: rgba(126, 184, 212, 0.12); border: 1px solid rgba(126, 184, 212, 0.28); color: #7eb8d4; }\
@media (max-width: 600px) { body { padding: 0.5rem; } #container { padding: 1rem; } h1 { font-size: 1.25rem; } h2 { font-size: 1rem; } td:first-child { font-size: 0.8rem; width: 40%; } input[type='text'], input[type='number'], input[type='password'], select { font-size: 0.9rem; padding: 0.65rem; } .ok-button { font-size: 0.9rem; padding: 0.65rem 1.25rem; } }\
</style>\
<body>\
<div id='container'>\
<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;'>\
<div style='display: flex; align-items: center;'>\
<a href='/' style='display: inline-block; margin-right: 1rem;'><img src='/favicon.png' alt='Home' style='width: 64px; height: 64px; border: none;'></a>\
<h1 style='margin: 0;'>Dynamic DNS</h1>\
</div>"

/* Closes the header flex row; script handles flash messages and provider toggle */
#define DDNS_CHUNK_MID "\
</div>\
<script>\
(function(){\
var p = new URLSearchParams(window.location.search);\
function flash(cls, msg) {\
var d = document.createElement('div');\
d.className = 'flash ' + cls;\
d.textContent = msg;\
var c = document.getElementById('container');\
c.insertBefore(d, c.children[1]);\
}\
if (p.get('saved') === '1')     { flash('flash-ok',   'Settings saved.');   history.replaceState(null, '', '/ddns'); }\
if (p.get('triggered') === '1') { flash('flash-info', 'Update triggered.'); history.replaceState(null, '', '/ddns'); }\
function toggleFields() {\
var v = document.getElementById('ddns_prov').value;\
var noip = (v === '0'), duck = (v === '1');\
document.getElementById('row_user').style.display = noip ? '' : 'none';\
document.getElementById('row_pass').style.display = noip ? '' : 'none';\
document.getElementById('row_tok').style.display  = noip ? 'none' : '';\
document.getElementById('lbl_host').textContent   = duck ? 'Subdomain' : 'Hostname';\
document.getElementById('hint_host').textContent  =\
duck ? 'Your DuckDNS subdomain \x2014 without .duckdns.org' :\
noip ? 'Your full NoIP hostname, e.g. myhost.ddns.net' :\
'Your full Selfhost.de hostname';\
}\
document.getElementById('ddns_prov').addEventListener('change', toggleFields);\
toggleFields();\
})();\
</script>"

#define DDNS_CHUNK_FORM_OPEN "\
<h2>Configuration</h2>\
<form action='/ddns' method='GET'>\
<table>"

/* Closes the config form at the Save button; handler appends status + trigger + tail */
#define DDNS_CHUNK_FORM_CLOSE "\
<tr><td></td><td><input type='submit' value='Save' class='ok-button'/></td></tr>\
</table>\
</form>"

/* Closes #container, body, html — sent after the trigger form and home link */
#define DDNS_CHUNK_TAIL "\
</div>\
</body>\
</html>"
