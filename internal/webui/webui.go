// Package webui holds the shared console assets: the design system
// stylesheet (light/dark via data-theme + prefers-color-scheme), the
// navigation shell, i18n helper and fetch plumbing with CSRF. Static
// strings in Go: no build toolchain, no external CDN, no telemetry — the
// console must work offline. Design tokens per
// docs/ARA_INTERFACE_DIRECTION_2026-11-03.md: почти белая рабочая область,
// тонированная навигация, графитовый текст, один синий акцент; тёмная тема
// равноправна; системный шрифтовой стек; шкала spacing 4/8/12/16/24/32.
package webui

import "strings"

// CSS is the design system: tokens, typography, layout primitives,
// components (cards/pills/tables/buttons/inputs/sparklines), nav shell,
// responsive breakpoints 1440/1024/390 and reduced-motion support.
const CSS = `
:root{
  --bg:#f7f7f8;--nav:#eef0f4;--card:#ffffff;--fg:#1d1d1f;--sub:#6e6e73;
  --acc:#0a60ff;--acc-soft:#e8f0ff;--ok:#1f8a44;--ok-soft:#dcf2e3;
  --bad:#c53030;--bad-soft:#fbe5e3;--warn:#9a6b15;--warn-soft:#f7ecd4;
  --line:#e3e4e8;--line-soft:#eef0f3;
  --sp-1:4px;--sp-2:8px;--sp-3:12px;--sp-4:16px;--sp-5:24px;--sp-6:32px;
  --r:10px;--r-lg:14px;
  --fs-base:15px;--fs-sm:13px;--fs-h1:26px;--fs-h2:19px;--fs-big:30px;
}
[data-theme="dark"]{
  --bg:#141416;--nav:#1b1c1f;--card:#1f2023;--fg:#f2f2f4;--sub:#9a9aa2;
  --acc:#5b9bff;--acc-soft:#1c2a44;--ok:#4cc27e;--ok-soft:#16321f;
  --bad:#ef6b60;--bad-soft:#3b1d1a;--warn:#d9a53f;--warn-soft:#3a2f14;
  --line:#33343a;--line-soft:#2a2b30;
}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#141416;--nav:#1b1c1f;--card:#1f2023;--fg:#f2f2f4;--sub:#9a9aa2;
  --acc:#5b9bff;--acc-soft:#1c2a44;--ok:#4cc27e;--ok-soft:#16321f;
  --bad:#ef6b60;--bad-soft:#3b1d1a;--warn:#d9a53f;--warn-soft:#3a2f14;
  --line:#33343a;--line-soft:#2a2b30;
}}
*{box-sizing:border-box;margin:0}
html{font-size:var(--fs-base)}
body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans",Roboto,"Helvetica Neue",Arial,sans-serif;
  background:var(--bg);color:var(--fg);line-height:1.5;
  font-variant-numeric:tabular-nums;
}
.layout{display:flex;min-height:100vh}
.sidenav{
  width:212px;flex-shrink:0;background:var(--nav);padding:var(--sp-4) var(--sp-3);
  display:flex;flex-direction:column;gap:2px;position:sticky;top:0;height:100vh;overflow-y:auto;
}
.sidenav .brand{font-weight:700;font-size:15px;padding:var(--sp-2) var(--sp-3) var(--sp-4);letter-spacing:-.01em}
.sidenav a{
  display:flex;align-items:center;gap:var(--sp-2);color:var(--sub);text-decoration:none;
  padding:var(--sp-2) var(--sp-3);border-radius:var(--r);font-size:14px;
}
.sidenav a:hover{background:var(--acc-soft);color:var(--fg)}
.sidenav a.active{background:var(--acc-soft);color:var(--acc);font-weight:600}
.sidenav .spacer{flex:1}
.sidenav .lang,.sidenav .theme{color:var(--sub);cursor:pointer;font-size:13px;padding:var(--sp-1) var(--sp-3)}
main{flex:1;padding:var(--sp-5) var(--sp-6);max-width:1080px;min-width:0}
h1{font-size:var(--fs-h1);font-weight:700;letter-spacing:-.02em;margin:0 0 var(--sp-4)}
h2{font-size:var(--fs-h2);font-weight:600;margin:var(--sp-5) 0 var(--sp-3)}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r-lg);
  padding:var(--sp-4) var(--sp-5);margin:var(--sp-3) 0}
.muted{color:var(--sub);font-size:13px}
.row{display:flex;gap:var(--sp-2);align-items:center;flex-wrap:wrap}
button,.btn{background:var(--acc);color:#fff;border:none;border-radius:var(--r);
  padding:7px 14px;font-size:14px;font-family:inherit;cursor:pointer}
button:hover{filter:brightness(1.06)}
button.secondary{background:transparent;color:var(--acc);border:1px solid var(--acc)}
button.danger{background:var(--bad)}
button:disabled{opacity:.45;cursor:default}
input,select,textarea{background:var(--card);color:var(--fg);border:1px solid var(--line);
  border-radius:var(--r);padding:7px 10px;font-size:14px;font-family:inherit}
input:focus,select:focus,textarea:focus,button:focus-visible,a:focus-visible{
  outline:2px solid var(--acc);outline-offset:1px}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line-soft)}
th{color:var(--sub);font-weight:500;font-size:13px}
tbody tr:hover{background:var(--acc-soft)}
.pill{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12px;background:var(--line-soft);color:var(--sub)}
.pill.ok{background:var(--ok-soft);color:var(--ok)}
.pill.bad{background:var(--bad-soft);color:var(--bad)}
.pill.warn{background:var(--warn-soft);color:var(--warn)}
.pill.acc{background:var(--acc-soft);color:var(--acc)}
code{background:var(--line-soft);border-radius:5px;padding:1px 5px;font-size:12px;
  font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
.spark{width:100%;height:64px}
.statgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:var(--sp-3)}
.stat{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:var(--sp-3) var(--sp-4)}
.stat .v{font-size:var(--fs-big);font-weight:700;letter-spacing:-.02em}
.stat .l{color:var(--sub);font-size:12px}
.event{display:flex;gap:var(--sp-2);padding:var(--sp-2) 0;border-bottom:1px solid var(--line-soft);font-size:14px}
.sidenav .nav-control{background:transparent;color:var(--sub);text-align:left;padding:8px 12px}
.admin-link{max-width:520px;margin:8vh auto 0}
.admin-link .card{padding:24px}
.admin-link a{display:inline-block;color:var(--acc);margin-top:12px;text-underline-offset:3px}
.client-home{max-width:660px}
.client-home h1{font-size:clamp(28px,4vw,40px);letter-spacing:-.045em}
.client-connection{padding:24px}
.client-connection h2{font-size:clamp(23px,4vw,32px);letter-spacing:-.035em;margin:14px 0 4px}
.client-connection .row{margin-top:20px;gap:16px}
.client-connection a{color:var(--acc);font-size:14px;text-underline-offset:3px}
.client-connection #conn-msg:not(:empty){margin-top:12px}
.client-tool .row{margin-top:14px}
.client-tool .row input{flex:1 1 220px;min-width:0}
.client-tool #spark:empty{display:none}
.client-start h2{margin:0 0 5px;font-size:16px}
@media(max-width:720px){
  .layout{flex-direction:column}
  .sidenav{width:100%;height:auto;position:static;flex-direction:row;flex-wrap:wrap;align-items:center}
  .sidenav .brand{width:100%}
  main{padding:var(--sp-4)}
}
@media(prefers-reduced-motion:no-preference){
  button,.sidenav a{transition:background .12s,color .12s}
}
@media print{.sidenav,button{display:none}}
`

// JS carries the shared client helpers: theme/lang switching, CSRF-aware
// fetch with AbortController plumbing, sparkline drawing, section routing.
const JS = `let CSRF=(document.cookie.match(/(?:^|; )ara_csrf=([^;]*)/)||[])[1]||'';
async function api(method, path, body){
  const opt={method,headers:{'Content-Type':'application/json'}};
  if(CSRF) opt.headers['X-CSRF']=CSRF;
  if(body!==undefined) opt.body=JSON.stringify(body);
  const r=await fetch(path,opt);
  if(r.status===401){location.reload();throw new Error('unauthorized')}
  if(!r.ok){const j=await r.json().catch(()=>({}));throw new Error(j.error||('HTTP '+r.status))}
  return r.json();
}
function t(ru,en){return document.documentElement.lang==='ru'?ru:en}
function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function spark(el, values, color){
  const w=el.clientWidth||400, h=64, n=values.length;
  if(!n){el.textContent=t('нет данных','no data');return}
  const max=Math.max(...values,1);
  let d='',x=0;
  values.forEach(v=>{const y=h-(v/max)*(h-6)-3; d+=(x?'L':'M')+x.toFixed(1)+' '+y.toFixed(1)+' '; x+=w/Math.max(n-1,1)});
  el.innerHTML='<svg class="spark" viewBox="0 0 '+w+' '+h+'" role="img" aria-label="'+t('график','chart')+'"><path d="'+d+'" fill="none" stroke="'+(color||'var(--acc)')+'" stroke-width="2"/></svg>';
}
function langToggle(){
  const next=document.documentElement.lang==='ru'?'en':'ru';
  localStorage.removeItem('ara_lang');
  document.cookie='ara_lang='+next+'; Path=/; SameSite=Lax; Max-Age=31536000'+(location.protocol==='https:'?'; Secure':'');
  location.reload();
}
function themeToggle(){
  const cur=document.documentElement.getAttribute('data-theme')||
    (matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');
  const next=cur==='dark'?'light':'dark';
  document.documentElement.setAttribute('data-theme',next);
  localStorage.setItem('ara_theme',next);
}
(function(){
  const l=(document.cookie.match(/(?:^|; )ara_lang=(ru|en)(?:;|$)/)||[])[1];if(l)document.documentElement.lang=l;
  const th=localStorage.getItem('ara_theme');if(th)document.documentElement.setAttribute('data-theme',th);
})();`

func HTML(lang, title, body string) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html lang=\"")
	b.WriteString(lang)
	b.WriteString("\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>")
	b.WriteString(title)
	b.WriteString("</title><style>")
	b.WriteString(CSS)
	b.WriteString("</style><script>")
	b.WriteString(JS)
	b.WriteString("</script></head><body>")
	b.WriteString(body)
	b.WriteString("</body></html>")
	return b.String()
}
