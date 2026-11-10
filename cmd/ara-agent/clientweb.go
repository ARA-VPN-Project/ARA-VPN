package main

// Local client UI served by the agent on loopback only: status,
// connect/disconnect (through the same IPC handlers as the CLI), usage,
// ping and a bounded speedtest. The page runs on 127.0.0.1 with no admin
// surface: it controls THIS machine's tunnel, not the network.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"aravpn/core/speedtest"
	"aravpn/internal/clientengine"
	"aravpn/internal/service"
	"aravpn/internal/webui"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// localGuard (B29): the loopback UI is NOT a public control surface.
// Every mutation (POST) requires: loopback Host, an EXACT same-origin
// Origin (scheme+host+port of THIS listener), Sec-Fetch-Site not
// cross-site, and the session CSRF token (HttpOnly cookie echoed in the
// X-ARA-CSRF header — a foreign page can read neither). Everything else is
// read-only GET. The CLI/IPC path stays separate and unauthenticated by
// cookies; loopback alone never grants mutation rights.
func (a *agentWeb) localGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.LastIndex(host, ":"); i > 0 {
			host = host[:i]
		}
		if host != "127.0.0.1" && host != "localhost" && host != "[::1]" {
			http.Error(w, `{"error":"AUTH_FAILED: foreign host"}`, http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			// exact origin: full scheme://host:port comparison
			if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+r.Host {
				http.Error(w, `{"error":"AUTH_FAILED: cross-site origin refused"}`, http.StatusForbidden)
				return
			}
			if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" {
				http.Error(w, `{"error":"AUTH_FAILED: cross-site mutation refused"}`, http.StatusForbidden)
				return
			}
			// CSRF: HttpOnly cookie value echoed in a custom header
			ck, err := r.Cookie("ara_csrf")
			tok := a.csrfToken()
			if err != nil || tok == "" || ck.Value == "" ||
				subtle.ConstantTimeCompare([]byte(ck.Value), []byte(tok)) != 1 {
				http.Error(w, `{"error":"AUTH_FAILED: csrf token required"}`, http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

// csrfToken is the per-process UI session token; a failed CSPRNG read
// yields "" and every mutation is refused (fail-closed).
func (a *agentWeb) csrfToken() string {
	a.csrfOnce.Do(func() {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err == nil {
			a.csrfTokenValue = hex.EncodeToString(b)
		}
	})
	return a.csrfTokenValue
}

func (a *agentWeb) routes(mux *http.ServeMux) {
	mux.HandleFunc("/client", a.page)
	mux.HandleFunc("/client/api/status", a.apiStatus)
	// every mutation is POST-only behind the same guard (B29)
	mux.HandleFunc("/client/api/connect", a.localGuard(postOnly(a.apiConnect)))
	mux.HandleFunc("/client/api/disconnect", a.localGuard(postOnly(a.apiDisconnect)))
	mux.HandleFunc("/client/api/ping", a.localGuard(postOnly(a.apiPing)))
	mux.HandleFunc("/client/api/speedtest", a.localGuard(postOnly(a.apiSpeedtest)))
	mux.HandleFunc("/client/api/subscription", a.apiSubscription)
	mux.HandleFunc("/client/api/subscription/refresh", a.localGuard(postOnly(a.apiSubscriptionRefresh)))
	// B43: client import + profile choice through the SAME service layer
	// as the CLI (follow chain with LKG semantics) — no hand-edited JSON.
	mux.HandleFunc("/client/api/profiles", a.localGuard(a.apiProfiles))
	mux.HandleFunc("/client/api/subscription/import", a.localGuard(postOnly(a.apiSubscriptionImport)))
	mux.HandleFunc("/client/api/profile/connect", a.localGuard(postOnly(a.apiProfileConnect)))
}

type agentWeb struct {
	eng *clientengine.Engine
	// profile targets for ping/speedtest (from the active profile)
	targets        func() []string
	svc            *service.Service
	csrfOnce       sync.Once
	csrfTokenValue string
}

// postOnly wraps a mutation: GET links must never trigger it (B29).
func postOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"VALIDATION_FAILED: POST required"}`, http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

func pageLangOf(r *http.Request) string {
	if c, err := r.Cookie("ara_lang"); err == nil && c.Value == "en" {
		return "en"
	}
	return "ru"
}

func pi(lang, ru, en string) string {
	if lang == "en" {
		return en
	}
	return ru
}

func (a *agentWeb) page(w http.ResponseWriter, r *http.Request) {
	lang := pageLangOf(r)
	// B29: session CSRF token — HttpOnly SameSite=Strict cookie; the page
	// echoes it in the X-ARA-CSRF header of every mutation
	tok := a.csrfToken()
	if tok != "" {
		http.SetCookie(w, &http.Cookie{Name: "ara_csrf", Value: tok, Path: "/client",
			HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	body := `<meta name="ara-csrf" content="` + tok + `">
<style>
.client-settings{--row-radius:15px}.client-settings main{max-width:920px;margin-inline:auto}
.client-settings .sidenav{padding:24px 14px}.client-settings .sidenav a{min-height:42px;color:var(--fg)}
.client-settings .sidenav a.active{color:var(--acc);background:var(--acc-soft)}
.client-settings h1{font-size:clamp(31px,5vw,44px);letter-spacing:-.045em}
.client-settings .card{border-color:var(--line-soft);border-radius:var(--row-radius)}
.client-capture{display:grid;grid-template-columns:minmax(0,1fr) minmax(130px,auto);align-items:center;gap:9px 14px}
.client-capture small{color:var(--sub);grid-column:1/-1;line-height:1.55}
.client-profile-row{display:flex;justify-content:space-between;align-items:center;gap:12px;border-bottom:1px solid var(--line-soft);padding:9px 0}
.client-profile-row strong{overflow-wrap:anywhere}
@media(max-width:900px){.client-settings .sidenav{padding:10px}.client-settings main{padding:20px 16px}}
</style>
<div class="layout client-settings"><nav class="sidenav" aria-label="` + pi(lang, "Разделы клиента", "Client sections") + `">
<a class="brand" href="#main" aria-label="` + pi(lang, "ARA VPN · на главную", "ARA VPN · Home") + `">ARA VPN</a>
<a href="#main" class="active" data-sec="main">` + pi(lang, "Подключение", "Connection") + `</a>
<a href="#profiles" data-sec="profiles">` + pi(lang, "Профили", "Profiles") + `</a>
<a href="#diagsec" data-sec="diagsec">` + pi(lang, "Диагностика", "Diagnostics") + `</a>
<a href="#subsec" data-sec="subsec">` + pi(lang, "Подписка", "Subscription") + `</a>
<div class="spacer"></div>
<button class="nav-control" onclick="themeToggle()">` + pi(lang, "Тема", "Theme") + `</button>
<button class="nav-control" onclick="langToggle()">` + pi(lang, "English", "Русский") + `</button>
</nav><main>
<section id="sec-main" class="client-home"><h1>` + pi(lang, "Подключение", "Connection") + `</h1>
<div class="card client-connection">
  <div id="state" role="status">` + pi(lang, "Проверяем состояние…", "Checking connection…") + `</div>
  <h2 id="connection-title">` + pi(lang, "Ваш VPN", "Your VPN") + `</h2>
  <p id="detail" class="muted"></p>
  <div class="row"><button id="btnConn" disabled onclick="toggle()">` + pi(lang, "Подключить", "Connect") + `</button>
  <a href="#profiles">` + pi(lang, "Профили", "Profiles") + `</a></div>
  <p class="muted" id="conn-msg" role="status"></p>
</div>
<div class="card client-capture"><label for="capture-mode"><strong>` + pi(lang, "Захват трафика", "Traffic capture") + `</strong></label>
<select id="capture-mode"><option value="">` + pi(lang, "Как в профиле", "Use profile setting") + `</option>
<option value="tun">` + pi(lang, "Устройство · TUN", "Device · TUN") + `</option>
<option value="proxy">` + pi(lang, "Приложения · прокси", "Applications · proxy") + `</option></select>
<small>` + pi(lang, "TUN перехватывает системный трафик. Прокси используют только приложения, настроенные на его адрес. DIRECT — исключение по правилу клиента.", "TUN captures device traffic. Only applications configured for the proxy use it. DIRECT is a client routing exception.") + `</small></div>
<div class="card client-start"><h2>` + pi(lang, "Первое подключение", "First connection") + `</h2>
<p class="muted">` + pi(lang, "Получите ссылку у администратора и импортируйте её в разделе «Профили».", "Get a subscription link from your administrator and import it in Profiles.") + `</p></div>
	</section>
	<section id="sec-profiles" class="client-home" hidden><h1>` + pi(lang, "Профили", "Profiles") + `</h1>
	<div class="card client-tool"><div id="profiles" class="muted">…</div>
	<form class="row" onsubmit="event.preventDefault(); importSub(this)">
	<label for="imp-url">` + pi(lang, "Ссылка подписки", "Subscription link") + `</label>
	<input id="imp-url" type="password" inputmode="url" autocomplete="off" required placeholder="https://vpn.example/connect/…">
	<button type="submit" class="secondary">` + pi(lang, "Импортировать", "Import") + `</button></form>
	<p class="muted" id="imp-msg" role="status"></p></div></section>
	<section id="sec-diagsec" class="client-home" hidden><h1>` + pi(lang, "Диагностика", "Diagnostics") + `</h1>
	<div class="card client-tool"><p class="muted">` + pi(lang, "Для замера сначала подключите VPN.", "Connect to the VPN before running a measurement.") + `</p><div class="row"><button class="secondary" onclick="ping()">` + pi(lang, "Проверить задержку", "Check latency") + `</button>
	<button class="secondary" onclick="speedtest()">` + pi(lang, "Замерить скорость · до 8 МиБ", "Test speed · up to 8 MiB") + `</button></div>
	<div id="diag" class="muted" role="status"></div><div id="spark" class="spark"></div></div></section>
	<section id="sec-subsec" class="client-home" hidden><h1>` + pi(lang, "Подписка", "Subscription") + `</h1>
	<div class="card client-tool"><div id="sub" class="muted" role="status">…</div>
	<div class="row"><button id="sub-refresh" class="secondary" disabled onclick="refreshSub()">` + pi(lang, "Обновить сейчас", "Refresh now") + `</button></div></div></section>
	</main></div>
	<script>
let LANG=document.documentElement.lang, st=null;
function pi(ru,en){return LANG==='ru'?ru:en}
// section routing: show one section at a time
function showSection(){
  const hash=location.hash.slice(1);
  const section=['main','profiles','diagsec','subsec'].includes(hash)?hash:'main';
  document.querySelectorAll('main > section').forEach(el=>{el.hidden=el.id!=='sec-'+section});
  document.querySelectorAll('.sidenav a[data-sec]').forEach(a=>{
    const active=a.dataset.sec===section;
    a.classList.toggle('active',active);
    if(active)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');
  });
}
window.addEventListener('hashchange',showSection);
showSection();
// every mutation carries the session CSRF token (B29)
async function api(method,url,body){
  const meta=document.querySelector('meta[name=ara-csrf]');
  const opt={method,headers:{'X-ARA-CSRF':meta?meta.content:''}};
  if(body!==undefined){opt.headers['Content-Type']='application/json';opt.body=JSON.stringify(body)}
  const r=await fetch(url,opt);
  return r.json();
}
let changingConnection=false;
async function refresh(){
  const button=document.getElementById('btnConn');
  const status=document.getElementById('state');
  const detail=document.getElementById('detail');
  try{
    const response=await fetch('/client/api/status');
    if(!response.ok)throw new Error();
    st=await response.json();
    button.textContent=st.running?pi('Отключить','Disconnect'):pi('Подключить','Connect');
    status.innerHTML='<span class="pill '+(st.running?'ok':'')+'">'+(st.running?(st.mode==='proxy'?pi('Прокси запущен','Proxy running'):pi('Туннель запущен','Tunnel running')):pi('Отключено','Disconnected'))+'</span>';
    document.getElementById('capture-mode').disabled=st.running;
    detail.textContent=st.running ? pi('Профиль · ','Profile · ')+(st.profile_name||'—')+(st.proxy_listen?' · '+st.proxy_listen:'') :
      pi('Выберите профиль или подключитесь с текущими настройками.','Choose a profile or connect with your current settings.');
  }catch{
    st=null;
    status.textContent=pi('Не удалось получить состояние','Connection status unavailable');
    detail.textContent='';
  }
  button.disabled=changingConnection||!st;
}
async function toggle(){
  if(!st||changingConnection)return;
  changingConnection=true;
  document.getElementById('btnConn').disabled=true;
  const message=document.getElementById('conn-msg');
  message.textContent=pi('Выполняем…','Working…');
  try{
    const result=st.running?await api('POST','/client/api/disconnect'):
      await api('POST','/client/api/profile/connect',{name:'default',mode:document.getElementById('capture-mode').value});
    message.textContent=result.error ? connectionError(result.error) : '';
  }catch{
    message.textContent=pi('Не удалось связаться с агентом.','Could not reach the agent.');
  }finally{
    changingConnection=false;
    await refresh();
  }
}
function connectionError(message){
  if(String(message).includes('PROFILE_MISSING'))
    return pi('Сначала импортируйте подписку или выберите профиль.','Import a subscription or choose a profile first.');
  return pi('Не удалось изменить подключение: ','Connection action failed: ')+message;
}
async function subStatus(){
  const r=await (await fetch('/client/api/subscription')).json();
  const el=document.getElementById('sub');
  document.getElementById('sub-refresh').disabled=!r.enabled;
  if(!r.enabled){el.textContent=pi('Автообновление подписки не настроено.','Subscription auto-refresh is not configured.');return}
  const parts=[pi('обновлено','updated')+': '+(r.last_success?new Date(r.last_success).toLocaleTimeString():pi('никогда','never'))];
  if(r.followed_count)parts.push(pi('переносов','transfers')+': '+r.followed_count);
  if(r.fail_streak)parts.push('<span class="pill bad">'+pi('ошибок подряд','failures in a row')+': '+r.fail_streak+'</span>');
  if(r.lkg_available)parts.push('LKG ✓');
  el.innerHTML=parts.join(' · ');
}
async function refreshSub(){
  const r=await api('POST','/client/api/subscription/refresh');
  if(r&&r.error){document.getElementById('sub').textContent=pi('Ошибка: ','Error: ')+r.error;return}
  subStatus();
}
// B43: profile choice and subscription import through the same service
// layer as the CLI (follow chain, LKG preserved).
async function loadProfiles(){
  const r=await (await fetch('/client/api/profiles')).json();
  const el=document.getElementById('profiles');
  if(!r.profiles||!r.profiles.length){el.textContent=pi('Профилей нет — импортируйте подписку.','No profiles yet — import a subscription.');return}
  el.replaceChildren();
  for(const p of r.profiles){
    const row=document.createElement('div'), name=document.createElement('strong'), button=document.createElement('button');
    row.className='client-profile-row';name.textContent=p;button.className='secondary';
    button.textContent=r.running&&r.profile===p?pi('Активен','Active'):pi('Подключить','Connect');
    button.disabled=r.running;
    button.addEventListener('click',()=>connectProfile(p,button));
    row.append(name,button);el.append(row);
  }
  if(r.running){
    const message=document.createElement('p');message.textContent=pi('Чтобы сменить профиль, сначала отключите текущее подключение.','Disconnect the current session before changing profiles.');el.append(message);
  }
}
async function connectProfile(name,button){
  button.disabled=true;
  try{
    const r=await api('POST','/client/api/profile/connect',{name,mode:document.getElementById('capture-mode').value});
    if(r&&r.error)throw new Error(r.error);
    await refresh();await loadProfiles();
  }catch(err){
    const message=document.createElement('p');message.setAttribute('role','status');message.textContent=connectionError(err.message);
    button.parentElement.after(message);button.disabled=false;
  }
}
async function importSub(form){
  const msg=document.getElementById('imp-msg');
  const input=document.getElementById('imp-url');
  const submit=form.querySelector('button');
  if(submit.disabled)return;
  submit.disabled=true;
  msg.textContent=pi('Импорт…','Importing…');
  try{
    const r=await api('POST','/client/api/subscription/import',{url:input.value.trim()});
    if(!r.ok)throw new Error(r.error||pi('Импорт не выполнен.','Import did not complete.'));
    input.value='';
    msg.textContent=pi('Подписка импортирована.','Subscription imported.');
    await loadProfiles();
  }catch(err){msg.textContent=pi('Ошибка: ','Error: ')+err.message}
  finally{submit.disabled=false}
}
subStatus(); setInterval(subStatus, 15000); loadProfiles(); setInterval(loadProfiles, 30000);
async function ping(){
  if(!st||!st.running){document.getElementById('diag').textContent=pi('Подключитесь сначала','Connect first');return}
  const r=await api('POST','/client/api/ping');
  document.getElementById('diag').textContent=r.results.map(x=>x.target+' '+x.rtt_ms.toFixed(1)+' ms'+(x.ok?'':' ('+pi('недоступен','unreachable')+')')).join(' · ');
}
async function speedtest(){
  const r=await api('POST','/client/api/speedtest');
  if(!r.ok){document.getElementById('diag').textContent=pi('Ошибка: ','Error: ')+(r.error||'');return}
  spark(document.getElementById('spark'), r.samples_mbit_s);
  document.getElementById('diag').textContent=pi('Итог','Total')+': '+r.mbit_s.toFixed(1)+' Mbit/s, '+r.bytes+' B / '+r.seconds.toFixed(2)+' s';
}
refresh(); setInterval(refresh, 5000);
</script>`
	w.Write([]byte(webui.HTML(lang, "ARA Client", body)))
}

func (a *agentWeb) apiSubscription(w http.ResponseWriter, r *http.Request) {
	st, err := a.svc.SubscriptionRefreshStatus()
	if err != nil {
		writeErrJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (a *agentWeb) apiSubscriptionRefresh(w http.ResponseWriter, r *http.Request) {
	res, err := a.svc.SubscriptionRefreshOnce()
	if err != nil {
		writeErrJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// apiProfiles lists the stored client profiles and the live session.
func (a *agentWeb) apiProfiles(w http.ResponseWriter, r *http.Request) {
	names, err := a.eng.ListProfiles()
	if err != nil {
		writeErrJSON(w, err)
		return
	}
	if names == nil {
		names = []string{}
	}
	st, _ := a.eng.Status()
	writeJSON(w, http.StatusOK, map[string]any{"profiles": names, "running": st.Running, "profile": st.ProfileName})
}

// apiSubscriptionImport applies a subscription URL through the shared
// follow chain (redirect/refusal policy, LKG preserved, own-device scope
// check). The token is accepted in the request body only (never a query
// string) and never echoed back.
func (a *agentWeb) apiSubscriptionImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeErrJSON(w, fmtError("valid subscription link required"))
		return
	}
	base, token, err := service.ParseSubscriptionLink(req.URL, req.Token)
	if err != nil {
		writeErrJSON(w, err)
		return
	}
	// the follow chain enforces HTTPS; loopback http stays an explicit lab
	// allowlist entry — never a blanket downgrade
	opts := service.FollowOptions{
		MaxHops: 4, Deadline: 20 * time.Second, ApplyProfile: true,
		ProfileDir: a.svc.State.Root + string(os.PathSeparator) + "profiles",
	}
	if u, perr := url.Parse(base); perr == nil && u.Scheme == "http" {
		if h := u.Hostname(); h == "127.0.0.1" || h == "localhost" || h == "::1" {
			opts.AllowedBases = []string{base}
		}
	}
	res, err := service.SubscriptionFollowChain(a.svc.State, service.FollowHTTPClient(20*time.Second), token, base, opts)
	if err != nil {
		writeErrJSON(w, err)
		return
	}
	if res.Error != "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": res.Error})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "profiles": res.Profiles, "followed": res.Followed, "applied": res.ProfileApplied})
}

// apiProfileConnect starts the requested profile and capture mode.
func (a *agentWeb) apiProfileConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil || req.Name == "" {
		writeErrJSON(w, fmtError("profile name required"))
		return
	}
	v, err := a.eng.StartMode(req.Name, req.Mode)
	if err != nil {
		writeErrJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *agentWeb) apiStatus(w http.ResponseWriter, r *http.Request) {
	v, err := a.eng.Status()
	if err != nil {
		writeErrJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *agentWeb) apiConnect(w http.ResponseWriter, r *http.Request) {
	v, err := a.eng.Start("default")
	if err != nil {
		writeErrJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *agentWeb) apiDisconnect(w http.ResponseWriter, r *http.Request) {
	v, err := a.eng.Stop()
	if err != nil && err != clientengine.ErrNotConnected {
		writeErrJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// apiPing measures real TCP RTT to the profile targets through the tunnel.
func (a *agentWeb) apiPing(w http.ResponseWriter, r *http.Request) {
	targets := a.targets()
	type res struct {
		Target string  `json:"target"`
		OK     bool    `json:"ok"`
		RTTMs  float64 `json:"rtt_ms"`
	}
	out := []res{}
	d := &net.Dialer{Timeout: 2 * time.Second}
	for _, t := range targets {
		start := time.Now()
		conn, err := d.Dial("tcp", t)
		rtt := float64(time.Since(start).Microseconds()) / 1000.0
		if err == nil {
			conn.Close()
		}
		out = append(out, res{Target: t, OK: err == nil, RTTMs: rtt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}

// apiSpeedtest downloads from the first reachable target with hard bounds
// (default 8 MiB / 10 s), sampling throughput every 250 ms. Bounded by
// construction: context deadline and a LimitReader.
func (a *agentWeb) apiSpeedtest(w http.ResponseWriter, r *http.Request) {
	// B30: the SHARED diagnostic service (core/speedtest + SpeedtestRunJob)
	// — request-scoped cancellation, bounded budget, integrity checks,
	// honest failed/no-data states. The JSON contract carries
	// samples_mbit_s: real per-direction goodput samples only — a failed
	// or canceled run is reported as an error/empty state, never zeros.
	targets := a.targets()
	if len(targets) == 0 {
		writeErrJSON(w, errNoTargets)
		return
	}
	if a.svc == nil {
		writeErrJSON(w, fmtError("diagnostics service unavailable"))
		return
	}
	host, port, err := net.SplitHostPort(targets[0])
	if err != nil {
		host = targets[0]
		port = "443"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	var samples []float64
	jobs := []map[string]any{}
	ok := true
	for _, dir := range []speedtest.Direction{speedtest.DirDown, speedtest.DirUp} {
		spec := speedtest.Spec{
			Segment: speedtest.SegClientEdge, Source: "client-ui", Dest: host,
			Endpoint: net.JoinHostPort(host, port), Direction: dir,
			Budget: speedtest.Budget{BytesPerDirection: 8 << 20, Duration: 10 * time.Second},
		}
		job, jerr := a.svc.SpeedtestRunJob(ctx, spec, "ui", map[string]string{"target": host}, time.Now().UTC())
		if jerr != nil {
			writeErrJSON(w, jerr)
			return
		}
		jm := map[string]any{"id": job.ID, "segment": job.Segment, "direction": job.Direction,
			"status": job.Status, "dest": job.Dest, "endpoint": job.Endpoint}
		if job.Error != "" {
			jm["error"] = job.Error
			ok = false
		}
		if len(job.Results) > 0 {
			m := job.Results[0].Metrics
			jm["goodput_mbps"] = m.GoodputMbps
			jm["bytes"] = m.Bytes
			jm["rtt_p50_idle_ms"] = m.RTTP50IdleMs
			jm["rtt_p95_idle_ms"] = m.RTTP95IdleMs
			jm["failed_probe_ratio"] = m.FailedProbeRatio
			jm["integrity_ok"] = m.IntegrityOK
			if m.OK && !job.Results[0].Canceled {
				samples = append(samples, m.GoodputMbps)
			}
		}
		jobs = append(jobs, jm)
	}
	if samples == nil {
		samples = []float64{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "samples_mbit_s": samples, "jobs": jobs})
}

var errNoTargets = fmtError("no ping/speedtest targets configured")

type fmtErr string

func (e fmtErr) Error() string { return string(e) }

func fmtError(s string) error { return fmtErr(s) }

func writeErrJSON(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
}
