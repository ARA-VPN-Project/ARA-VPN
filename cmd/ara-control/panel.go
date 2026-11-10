package main

// Control Center (docs/WEB_CONSOLE_REQUIREMENTS.md): one origin serves the
// guest site, the enrollment landing and the admin panel. Admin actions
// require the operator key exchanged for an HttpOnly session cookie plus a
// CSRF token; every JSON API keeps its bearer path for automation. Ping
// measures real TCP-connect RTT to nodes (no ICMP, no synthetic data).

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"aravpn/internal/controlstore"
	"aravpn/internal/webui"
)

//go:embed signin.css
var signinCSS string

//go:embed dashboard.css
var dashboardCSS string

//go:embed dashboard.js
var dashboardJS string

//go:embed route_presets.js
var routePresetsJS string

//go:embed sub_activity.js
var subActivityJS string

type session struct {
	expires time.Time
	csrf    string
}

var (
	sessMu     sync.Mutex
	sessions   = map[string]session{}
	pingClient = &net.Dialer{Timeout: 2 * time.Second}
)

func newSession() (token, csrf string, err error) {
	token, err = randomHex(32)
	if err != nil {
		return "", "", err
	}
	csrf, err = randomHex(32)
	if err != nil {
		return "", "", err
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	now := time.Now()
	for id, current := range sessions {
		if !now.Before(current.expires) {
			delete(sessions, id)
		}
	}
	sessions[token] = session{expires: now.Add(12 * time.Hour), csrf: csrf}
	return token, csrf, nil
}

func requestSession(r *http.Request) (session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return session{}, false
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	current, ok := sessions[c.Value]
	if ok && !time.Now().Before(current.expires) {
		delete(sessions, c.Value)
		return session{}, false
	}
	return current, ok
}

func validSessionCSRF(r *http.Request, csrf string) bool {
	current, ok := requestSession(r)
	return ok && subtleCompare(current.csrf, csrf) == 1
}

func dropSession(tok string) {
	sessMu.Lock()
	delete(sessions, tok)
	sessMu.Unlock()
}

const cookieName = "ara_session"

func (s *server) isAdmin(r *http.Request) bool {
	_, ok := requestSession(r)
	return ok
}

func adminPageHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

func (s *server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	adminPageHeaders(w)
	lang := pageLang(r)
	if !s.isAdmin(r) {
		w.Write([]byte(webui.HTML(lang, "Sign in", s.linkPage(lang))))
		return
	}
	w.Write([]byte(webui.HTML(lang, "ARA Control", s.panelPage(lang))))
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	if !s.allowAdminLogin(r, req.Username, req.Password, time.Now()) {
		s.audit.Append(controlstore.AuditEntry{Actor: r.RemoteAddr, Action: "panel.login", Result: "denied"})
		http.Error(w, `{"error":"AUTH_FAILED"}`, http.StatusUnauthorized)
		return
	}
	tok, csrf, err := newSession()
	if err != nil {
		http.Error(w, `{"error":"SESSION_UNAVAILABLE"}`, http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/",
		HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteStrictMode,
		MaxAge: 12 * 3600})
	http.SetCookie(w, &http.Cookie{Name: "ara_csrf", Value: csrf, Path: "/",
		Secure: isHTTPS(r), SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "csrf": csrf})
	s.audit.Append(controlstore.AuditEntry{Actor: r.RemoteAddr, Action: "panel.login", Result: "ok"})
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if c, err := r.Cookie(cookieName); err == nil {
		dropSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "ara_csrf", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func subtleCompare(a, b string) int {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}

// handlePing measures a real TCP-connect RTT to addr (host:port).
func (s *server) handlePing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Targets []string `json:"targets"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil || len(req.Targets) == 0 || len(req.Targets) > 16 {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	type res struct {
		Target string  `json:"target"`
		OK     bool    `json:"ok"`
		RTTMs  float64 `json:"rtt_ms"`
	}
	out := []res{}
	for _, t := range req.Targets {
		start := time.Now()
		conn, err := pingClient.Dial("tcp", t)
		rtt := float64(time.Since(start).Microseconds()) / 1000.0
		if err == nil {
			conn.Close()
		}
		out = append(out, res{Target: t, OK: err == nil, RTTMs: rtt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": out, "measured_at": time.Now().UTC()})
}

// handleEdgeConfig renders the live edge devices[] fragment: the operator
// copies it into the edge config (or the tooling does) and SIGHUPs the
// edge; revoke propagates when the revoked device is removed here.
func (s *server) handleEdgeConfig(w http.ResponseWriter, r *http.Request) {
	devices, err := s.store.ListDevices()
	if err != nil {
		writeErr(w, err)
		return
	}
	type edev struct {
		UUID     string `json:"uuid"`
		DeviceID string `json:"device_id"`
	}
	out := []edev{}
	for _, d := range devices {
		if d.RevokedAt != nil || d.VlessUUID == "" {
			continue
		}
		out = append(out, edev{UUID: d.VlessUUID, DeviceID: d.ID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out, "note": "copy into edge config devices[] and SIGHUP ara-edge; remove revoked devices"})
}

// ---- pages ----

func (s *server) linkPage(lang string) string {
	return `<style>` + signinCSS + `</style><main class="signin-screen"><section class="signin-panel" aria-labelledby="signin-title">
<header class="signin-brand"><div class="signin-wordmark" aria-label="ARA VPN">ARA <span>VPN</span></div><p class="signin-caption">Control Center</p></header>
<h1 id="signin-title">` + pi(lang, "Вход", "Sign in") + `</h1>
<form id="signin" class="signin-form">
<label>` + pi(lang, "Логин", "Username") + `<input name="username" autocapitalize="none" spellcheck="false" autocomplete="username" required></label>
<label>` + pi(lang, "Пароль", "Password") + `<input type="password" name="password" autocomplete="current-password" required></label>
<button>` + pi(lang, "Войти", "Sign in") + `</button><p id="login-status" class="signin-status" role="status" aria-live="polite"></p>
</form></section></main><script>
document.getElementById('signin').onsubmit=async event=>{
  event.preventDefault();
  const form=event.currentTarget;
  const button=form.querySelector('button');if(button.disabled)return;button.disabled=true;
  try{
    const response=await fetch(location.pathname+'/session',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(Object.fromEntries(new FormData(form))),redirect:'error',cache:'no-store',referrerPolicy:'no-referrer'});
    if(response.ok){location.reload();return}
  }catch{}
  button.disabled=false;
  document.getElementById('login-status').textContent=t('Не удалось войти. Проверьте данные для входа.','Sign-in failed. Check your credentials.');
};
</script>`
}

func (s *server) panelPage(lang string) string {
	var b strings.Builder
	sec := func(id, ru, en string) string {
		label := pi(lang, ru, strings.ToUpper(en[:1])+en[1:])
		return `<section id="sec-` + en + `" hidden><h1>` + label + `</h1>`
	}
	b.WriteString(`<style>` + dashboardCSS + `</style><div class="layout console"><nav class="sidenav" aria-label="` + pi(lang, "Разделы панели", "Control Center sections") + `">
<a class="brand" href="#overview" aria-label="` + pi(lang, "ARA VPN · на главную", "ARA VPN · Home") + `"><span class="brand-mark" aria-hidden="true">A</span><span>ARA VPN<small>Control Center</small></span></a>
<div class="nav-sections"><div class="nav-section-label">` + pi(lang, "Рабочая область", "Workspace") + `</div><a href="#overview" class="nav-overview" data-sec="overview">` + pi(lang, "Обзор", "Overview") + `</a>
<a href="#network" class="nav-network" data-sec="network">` + pi(lang, "Сеть", "Network") + `</a>
<a href="#access" class="nav-access" data-sec="access">` + pi(lang, "Доступ", "Access") + `</a>
<a href="#routes" class="nav-routes" data-sec="routes">` + pi(lang, "Маршруты", "Routes") + `</a>
<div class="nav-section-label">` + pi(lang, "Обслуживание", "Maintenance") + `</div><a href="#diagnostics" class="nav-diagnostics" data-sec="diagnostics">` + pi(lang, "Диагностика", "Diagnostics") + `</a>
<a href="#settings" class="nav-settings" data-sec="settings">` + pi(lang, "Настройки", "Settings") + `</a>
</div>
<div class="nav-utilities"><button type="button" class="nav-action" onclick="themeToggle()">` + pi(lang, "Тема", "Theme") + `</button>
<button type="button" class="nav-action" onclick="langToggle()" aria-label="` + pi(lang, "Switch to English", "Переключить на русский") + `">` + pi(lang, "English", "Русский") + `</button>
<a href="` + s.adminPath + `/logout">` + pi(lang, "Выйти", "Sign out") + `</a></div>
</nav><main>`)

	b.WriteString(`<section id="sec-overview" hidden>
<header class="overview-heading">
  <div><div class="eyebrow">` + pi(lang, "МОНИТОРИНГ СЕТИ", "NETWORK MONITORING") + `</div><h1>` + pi(lang, "Обзор", "Overview") + `</h1>
  <p>` + pi(lang, "Трафик, задержка и доступность выходов.", "Traffic, latency, and exit availability.") + `</p></div>
  <button type="button" class="overview-refresh" id="ov-refresh">` + pi(lang, "Обновить", "Refresh") + `</button>
</header>
<div class="overview-summary" id="ov-summary" role="status">` + pi(lang, "Загружаем наблюдения…", "Loading observations…") + `</div>
<div class="overview-period"><label for="ov-period">` + pi(lang, "Период графиков", "Chart period") + `</label>
<select id="ov-period"><option value="1h">` + pi(lang, "Час", "Hour") + `</option><option value="24h">` + pi(lang, "Сутки", "Day") + `</option><option value="7d">` + pi(lang, "Неделя", "Week") + `</option><option value="30d">` + pi(lang, "Месяц", "Month") + `</option><option value="1y">` + pi(lang, "Год", "Year") + `</option></select></div>
<div class="overview-charts">
  <article class="monitor-card">
    <header><div><h2>` + pi(lang, "Трафик", "Traffic") + `</h2><p>` + pi(lang, "Полезные данные через локальный Edge", "Payload through the local Edge") + `</p></div></header>
    <div id="ov-traffic"></div>
  </article>
  <article class="monitor-card">
    <header><div><h2>` + pi(lang, "Задержка", "Latency") + `</h2><p>` + pi(lang, "Проверка выхода или внешней цели", "Exit or external target probe") + `</p></div>
    <select id="ov-target" aria-label="` + pi(lang, "Цель измерения задержки", "Latency probe target") + `" hidden></select></header>
    <div id="ov-latency"></div>
  </article>
</div>
<div class="overview-details">
  <article class="monitor-card">
    <header><div><h2>` + pi(lang, "Выходы Edge", "Edge exits") + `</h2><p>` + pi(lang, "Наблюдения локального Edge", "Observations from the local Edge") + `</p></div>
    <a href="#network">` + pi(lang, "Сеть", "Network") + `</a></header>
    <div id="ov-nodes"></div>
  </article>
  <article class="monitor-card">
    <header><div><h2>` + pi(lang, "Внешняя проверка", "External check") + `</h2><p>` + pi(lang, "Cloudflare, Facebook и Яндекс · TCP 443 от панели", "Cloudflare, Facebook and Yandex · TCP 443 from Control Center") + `</p></div></header>
    <div id="ov-external"></div>
  </article>
</div>
</section>`)
	b.WriteString(`<section id="sec-network" hidden>
<header class="network-header">
  <div><div class="eyebrow">` + pi(lang, "ИНФРАСТРУКТУРА", "INFRASTRUCTURE") + `</div>
  <h1>` + pi(lang, "Сеть", "Network") + `</h1>
  <p>` + pi(lang, "Свяжите вход с выходом, затем примените конфигурацию на Edge.", "Link an ingress to an exit, then deploy the configuration to Edge.") + `</p></div>
  <button type="button" class="secondary" onclick="openNetworkDialog('network-guide')">` + pi(lang, "Настройка сети", "Network setup") + `</button>
</header>
<article class="network-panel">
  <header><div><h2>` + pi(lang, "Связи Edge → Exit", "Edge → Exit links") + `</h2>
  <p>` + pi(lang, "Какие выходы доступны каждой входной ноде.", "Which exits each ingress can use.") + `</p></div>
  <button type="button" id="new-link" disabled onclick="openNetworkDialog('link-editor')">` + pi(lang, "Создать связь", "Create link") + `</button></header>
  <div class="network-panel-body" id="links"></div>
</article>
<div class="network-columns">
  <article class="network-panel">
    <header><div><h2>` + pi(lang, "Ноды", "Nodes") + `</h2><p>` + pi(lang, "Входы и выходы VPN.", "VPN ingress and exit nodes.") + `</p></div>
    <div class="node-actions"><button type="button" class="secondary" onclick="openNodeAccess()">` + pi(lang, "Доступ к ноде", "Node access") + `</button>
    <button type="button" class="secondary" onclick="openNetworkDialog('node-editor')">` + pi(lang, "Добавить", "Add node") + `</button></div></header>
    <div class="network-panel-body" id="nodes"></div>
  </article>
  <article class="network-panel">
    <header><div><h2>` + pi(lang, "Транспорт", "Transport") + `</h2><p>` + pi(lang, "Профили для связей между нодами.", "Profiles for links between nodes.") + `</p></div>
    <button type="button" id="new-profile" class="secondary" disabled onclick="openNetworkDialog('profile-editor')">` + pi(lang, "Добавить", "Add profile") + `</button></header>
    <div class="network-panel-body" id="profiles"></div>
  </article>
</div>
<article class="network-panel"><header><div><h2>` + pi(lang, "Конфигурация входной ноды", "Ingress deployment") + `</h2><p>` + pi(lang, "Подготовьте и проверьте план, затем опубликуйте его для связанной ноды.", "Prepare and review a plan, then publish it to a linked node.") + `</p></div><button type="button" class="secondary" onclick="prepareEdgeDeployment()">` + pi(lang, "Подготовить план", "Prepare plan") + `</button></header><div class="network-panel-body"><p class="muted">` + pi(lang, "Нода получает план через ara edge sync. Публикация не означает, что слушатель уже работает: после доставки проверьте serving receipt и подключение клиента.", "The node pulls the plan with ara edge sync. Publishing does not mean a listener is running: verify the serving receipt and client traffic after delivery.") + `</p></div></article>
<details class="network-advanced"><summary>` + pi(lang, "Устройства в конфигурации Edge", "Devices in the Edge config") + `</summary><div id="edgecfg"></div></details>

<dialog class="network-dialog" id="node-editor" aria-labelledby="node-editor-title">
  <form class="settings-form" onsubmit="addNode(event)">
    <header><h2 id="node-editor-title">` + pi(lang, "Добавить ноду", "Add node") + `</h2></header>
    <label>` + pi(lang, "Имя ноды", "Node ID") + `<input name="id" required placeholder="de-exit"></label>
    <label>` + pi(lang, "Страна ноды", "Node country") + `<select name="country" id="node-country" required aria-describedby="country-hint"></select></label><p class="muted" id="country-hint">` + pi(lang, "Выберите страну по названию. Код подставится автоматически. Это ваша метка, а не проверка геолокации IP.", "Choose a country by name. Its code is filled automatically. This is your label, not an IP geolocation check.") + `</p>
    <label>` + pi(lang, "Роль", "Role") + `<select name="role"><option value="foreign">` + pi(lang, "Зарубежный выход", "Foreign exit") + `</option><option value="ru">` + pi(lang, "Российская нода", "Russian node") + `</option></select></label>
    <label>` + pi(lang, "Приоритет", "Priority") + `<input name="priority" type="number" value="10" required></label>
    ` + networkFormActions(lang, "Добавить ноду", "Add node") + `
  </form>
</dialog>
<dialog class="network-dialog" id="node-access-editor" aria-labelledby="node-access-title">
  <form class="settings-form" onsubmit="previewNodeAccess(event)" oninput="clearNodeAccess(this)">
    <header><h2 id="node-access-title">` + pi(lang, "Доступ к ноде", "Node access") + `</h2>
    <p>` + pi(lang, "Подготовьте правило для входящего порта. Команда выполняется на самой ноде.", "Prepare an inbound port rule. Run the command on the node itself.") + `</p></header>
    <label>` + pi(lang, "Назначение", "Purpose") + `<select name="kind" onchange="updateAccessPurpose(this.form)">
      <option value="ingress">` + pi(lang, "Вход для клиентов", "Client ingress") + `</option>
      <option value="transit">` + pi(lang, "Транзит от ноды через туннель", "Node transit over a tunnel") + `</option></select></label>
    <label>` + pi(lang, "Протокол", "Protocol") + `<select name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
    <label>` + pi(lang, "Порт сервиса", "Service port") + `<input name="port" type="number" min="1" max="65535" required></label>
    <label>` + pi(lang, "Входящий интерфейс", "Receiving interface") + `<input name="interface" required maxlength="15" placeholder="ens3"></label>
    <label>` + pi(lang, "Разрешённый источник", "Allowed source") + `<input name="source" placeholder="` + pi(lang, "Пусто — любой IP", "Blank — any IP") + `"></label>
    <label>` + pi(lang, "Таблица nftables · inet", "nftables table · inet") + `<input name="table" required maxlength="32" value="filter"></label>
    <div class="route-wide" data-access-result hidden><label>` + pi(lang, "Команда для ноды", "Command for the node") + `<textarea readonly rows="3"></textarea></label>
      <div class="node-actions" data-access-live hidden>
        <button type="button" class="secondary" onclick="changeNodeAccess(this,'remove')">` + pi(lang, "Удалить правило", "Remove rule") + `</button>
        <button type="button" onclick="changeNodeAccess(this,'apply')">` + pi(lang, "Открыть порт на этой ноде", "Open port on this node") + `</button>
      </div>
      <p class="muted">` + pi(lang, "На ноде должна быть подключена цепочка ara_node_access. После применения проверьте порт с нужной стороны.", "The node must have the ara_node_access chain connected. After applying, test the port from the intended source.") + `</p>
    </div>
    ` + networkFormActions(lang, "Подготовить правило", "Prepare rule") + `
  </form>
</dialog>
<dialog class="network-dialog" id="link-editor" aria-labelledby="link-editor-title">
  <form class="settings-form" onsubmit="addNetworkLink(event)">
    <header><h2 id="link-editor-title">` + pi(lang, "Создать связь", "Create link") + `</h2>
    <p>` + pi(lang, "Связь появится в топологии. Для запуска нужен план Edge и готовый выход.", "The link will appear in the topology. Deployment requires an Edge plan and a configured exit.") + `</p></header>
    <label>` + pi(lang, "Входная нода", "Ingress node") + `<select name="edge_id" required onchange="updateLinkChoices(this.form)"></select></label>
    <label>` + pi(lang, "Нода выхода", "Exit node") + `<select name="exit_id" required onchange="updateLinkChoices(this.form)"></select></label>
    <label>` + pi(lang, "Транспорт", "Transport") + `<select name="transport" onchange="updateLinkChoices(this.form)"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
    <label>` + pi(lang, "Профиль выхода", "Exit profile") + `<select name="profile_id"></select><span class="link-profile-hint" aria-live="polite"></span></label>
    <label>` + pi(lang, "Приоритет · меньший раньше", "Priority · lower goes first") + `<input name="priority" type="number" value="10" required></label>
    ` + networkFormActions(lang, "Создать связь", "Create link") + `
  </form>
</dialog>
<dialog class="network-dialog" id="profile-editor" aria-labelledby="profile-editor-title"></dialog>
` + networkGuide(lang) + `</section>`)

	// Доступ — subscriptions/devices/invites/federation
	b.WriteString(sec("acc", "Доступ", "access") + `
<article class="card settings-card"><h2>` + pi(lang, "Подписки", "Subscriptions") + `</h2><div id="subs"></div></article>
<article class="card settings-card"><h2>` + pi(lang, "Пользователи", "Users") + `</h2><div id="accounts"></div></article>
<article class="card settings-card"><h2>` + pi(lang, "Устройства", "Devices") + `</h2><div id="devices"></div></article>
<article class="card settings-card"><h2>` + pi(lang, "Приглашения", "Invitations") + `</h2><div id="invites"></div></article>
</section>`)

	// Маршруты — editor + audit trail of applies
	b.WriteString(sec("rt", "Маршруты", "routes") + `
<div class="network-panel route-editor" id="routes"></div>
` + routePresetDialog(lang) + `
</section>`)

	// Диагностика
	b.WriteString(sec("dg", "Диагностика", "diagnostics") + `
<div id="diag"></div>
</section>`)

	// Настройки — federation admin, audit, language/theme
	b.WriteString(sec("st", "Настройки", "settings") + `
<div class="settings-group"><h2>` + pi(lang, "Безопасность", "Security") + `</h2>
<button type="button" class="secondary" onclick="changeAdminPassword()">` + pi(lang, "Изменить пароль панели", "Change panel password") + `</button></div>
<div class="settings-group"><h2>` + pi(lang, "Стартовая страница", "Start page") + `</h2>
<form id="public-page-form" class="settings-form settings-list subscription-endpoint public-page-settings" onsubmit="savePublicPage(event)">
<label>` + pi(lang, "Вид страницы", "Page style") + `<select name="mode"><option value="neutral">` + pi(lang, "Нейтральная", "Neutral") + `</option><option value="custom">` + pi(lang, "Свой текст", "Custom text") + `</option><option value="index">Index</option></select></label>
<label>` + pi(lang, "Заголовок", "Title") + `<input name="title" maxlength="120"></label>
<label>` + pi(lang, "Текст страницы", "Page text") + `<textarea name="text" rows="5" maxlength="6000"></textarea></label>
<p class="muted">` + pi(lang, "Видно всем на главном адресе сайта. Используйте обычный текст. Не размещайте пароли и секретную ссылку панели.", "Visible to everyone at the site root. Use plain text. Keep passwords and the private panel link out of this page.") + `</p>
<footer><p class="form-status" role="status"></p><button type="submit">` + pi(lang, "Сохранить", "Save") + `</button><a class="page-preview-link" href="/" target="_blank" rel="noopener">` + pi(lang, "Открыть страницу", "Open page") + `</a></footer></form></div>
<div class="settings-group"><h2>` + pi(lang, "Сертификаты", "Certificates") + `</h2>
<div class="settings-list" id="cert-settings" aria-live="polite"></div></div>
<div class="settings-group"><h2>` + pi(lang, "Подписочный сервис", "Subscription service") + `</h2>
<div class="settings-list">
<form id="subscription-endpoint-form" class="settings-form subscription-endpoint" onsubmit="saveSubscriptionEndpoint(event)" oninput="previewSubscriptionEndpoint(this)">
  <label>` + pi(lang, "Публичный домен HTTPS", "Public HTTPS domain") + `<input name="origin" type="url" required placeholder="https://vpn.example"></label>
  <label>` + pi(lang, "Имя сервиса в ссылке", "Service name in URL") + `<input name="name" required maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9_\-]*" placeholder="connect"></label>
  <div class="endpoint-preview"><span>` + pi(lang, "Ссылка для клиента", "Client link") + `</span><output aria-live="polite"></output></div>
  <p class="muted endpoint-note">` + pi(lang, "При смене имени сервиса выданные ссылки со старым путём перестанут работать.", "Changing the service name disables links using the previous path.") + `</p>
  <footer><p class="form-status" role="status"></p><button type="submit">` + pi(lang, "Сохранить", "Save") + `</button></footer>
</form>
</div></div>
<div class="settings-group"><h2>` + pi(lang, "Связь панелей", "Panel links") + `</h2>
<div class="settings-list federation-settings" id="fedcfg"></div></div>
<div class="settings-group"><h2>` + pi(lang, "Журнал операций", "Audit log") + `</h2>
<div class="settings-list table-scroll" id="audit"></div></div>
</section>`)

	b.WriteString(`</main></div><dialog id="action-dialog" aria-labelledby="action-title">
<form method="dialog" id="action-form">
<h2 id="action-title"></h2><div id="action-body"></div>
<div class="settings-actions">
<button type="submit" value="cancel" class="secondary" formnovalidate autofocus>` + pi(lang, "Отмена", "Cancel") + `</button>
<button type="submit" value="ok" id="action-submit"></button>
</div></form></dialog><div id="panel-message" class="panel-message" role="status" hidden></div>`)

	b.WriteString(`<script>
let LANG=document.documentElement.lang;
function pi(ru,en){return LANG==='ru'?ru:en}
const regionNames=new Intl.DisplayNames([LANG==='ru'?'ru':'en'],{type:'region'});
function countryLabel(code){try{return regionNames.of(code)||code}catch{return code}}
const countryCodes='AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'.split(' ');
const countrySelect=document.getElementById('node-country');
countrySelect.add(new Option(pi('Выберите страну','Choose a country'),''));
countryCodes.sort((a,b)=>countryLabel(a).localeCompare(countryLabel(b),LANG)).forEach(code=>countrySelect.add(new Option(countryLabel(code)+' · '+code,code)));
const actionDialog=document.getElementById('action-dialog');
function panelMessage(text,failed=false){
  const el=document.getElementById('panel-message');
  el.textContent=text;
  el.classList.toggle('error',failed);
  el.hidden=false;
  clearTimeout(panelMessage.timer);
  panelMessage.timer=setTimeout(()=>{el.hidden=true},7000);
}
function panelError(err){panelMessage(pi('Ошибка: ','Error: ')+err.message,true)}
function openAction(title,content,submit,validate,viewOnly=false){
  if(actionDialog.open)return Promise.resolve(null);
  const form=document.getElementById('action-form');
  document.getElementById('action-title').textContent=title;
  const body=document.getElementById('action-body');
  body.replaceChildren(content);
  const button=document.getElementById('action-submit');
  button.textContent=submit;
  button.disabled=false;
  actionDialog.classList.toggle('view-only-action',viewOnly);
  actionDialog.classList.toggle('configuration-action',content.classList?.contains('subscription-config-picker')||false);
  actionDialog.returnValue='';
  return new Promise(resolve=>{
    const status=document.createElement('p');
    status.className='form-status';
    status.setAttribute('role','status');
    body.append(status);
    const onSubmit=async event=>{
      if(!validate||event.submitter!==button)return;
      event.preventDefault();
      if(button.disabled)return;
      button.disabled=true;
      const cancel=form.querySelector('[value=cancel]');
      cancel.disabled=true;
      const preventCancel=event=>event.preventDefault();
      actionDialog.addEventListener('cancel',preventCancel);
      status.textContent='';
      try{
        await validate(Object.fromEntries(new FormData(form)));
        if(actionDialog.open)actionDialog.close('ok');
      }catch(err){status.textContent=err.message}
      finally{button.disabled=false;cancel.disabled=false;actionDialog.removeEventListener('cancel',preventCancel)}
    };
    form.addEventListener('submit',onSubmit);
    actionDialog.addEventListener('close',()=>{
      form.removeEventListener('submit',onSubmit);
      resolve(actionDialog.returnValue==='ok'?Object.fromEntries(new FormData(form)):null);
    },{once:true});
    actionDialog.showModal();
    const titleNode=document.getElementById('action-title');titleNode.tabIndex=-1;titleNode.focus({preventScroll:true});body.scrollTop=0;
  });
}
function confirmAction(title,text="",submit=pi('Подтвердить','Confirm')){
  const paragraph=document.createElement('p');
  paragraph.textContent=text;
  return openAction(title,paragraph,submit);
}
async function loadAll(){
  const nodes=await api('GET','/api/v1/nodes');
  document.getElementById('nodes').innerHTML=renderNodes(nodes.nodes||[]);
  const links=await api('GET','/api/v1/links');
  const tps=await api('GET','/api/v1/transit-profiles');
  document.getElementById('links').innerHTML=renderLinks(links.links||[], tps.profiles||[]);
  document.getElementById('profiles').innerHTML=renderProfiles(tps.profiles||[], tps.capabilities||{});
  updateNetworkEditors(nodes.nodes||[], tps.profiles||[], tps.capabilities||{});
  const subs=await api('GET','/api/v1/subscriptions');
  const subsLocalMode=subs.local_edge;
  const connected=new Set((links.links||[]).filter(l=>!l.revoked_at&&(!subsLocalMode||l.edge_id===subsLocalMode)).map(l=>l.exit_id));
  ROUTE_NODES=(nodes.nodes||[]).filter(n=>n.role==='foreign'&&!n.revoked_at&&connected.has(n.id));
  LOCAL_TROJAN=!!subs.trojan;
  const devices=await api('GET','/api/v1/devices');
  const {accounts}=await api('GET','/api/v1/accounts');
  const visibleAccounts=new Set((accounts||[]).map(a=>a.id));
  const visibleDevices=(devices.devices||[]).filter(d=>visibleAccounts.has(d.account_id));
  document.getElementById('accounts').innerHTML=renderAccounts(accounts||[],subs.subscriptions||[]);
  document.getElementById('devices').innerHTML=renderDevices(visibleDevices,!!subsLocalMode);
  const invites=await api('GET','/api/v1/invites');
  document.getElementById('invites').innerHTML=renderInvites(invites.invites||[]);
  loadDiag().catch(panelError);
  loadCertificateSettings().catch(panelError);
  loadSubscriptionEndpoint().catch(panelError);
 loadPublicPage().catch(panelError);
  if(!DRAFT)loadRoutes().catch(panelError);
  const subSection=document.getElementById('subs');
  const opened=pendingSubscriptionFocus||subSection.querySelector('details[data-subscription][open]')?.dataset.subscription;
  pendingSubscriptionFocus='';
  subSection.innerHTML=renderSubs(subs.subscriptions||[],devices.devices||[],subs.local_edge);
  for (const details of subSection.querySelectorAll('details[data-subscription]')) if(opened===details.dataset.subscription)details.open=true;
  updateSubscriptionNodes(nodes.nodes||[], links.links||[],subs.local_edge,subs.ru_only,subs.ready_routes);
  const fed=await api('GET','/api/v1/panel/links');
  document.getElementById('fedcfg').innerHTML=renderFed(fed.links||[], fed.panel_id||'');
  const edge=await api('GET','/api/v1/edge-config');
  document.getElementById('edgecfg').innerHTML='<code style="white-space:pre-wrap">'+esc(JSON.stringify(edge.devices||[],null,2))+'</code>';
  const audit=await api('GET','/api/v1/audit');
  document.getElementById('audit').innerHTML=renderAudit(audit.entries||[]);

}
async function prepareEdgeDeployment(){
 try{
  const [nodes,subs,peers]=await Promise.all([api('GET','/api/v1/nodes'),api('GET','/api/v1/subscriptions'),api('GET','/api/v1/panel/links')]);
  const fields=document.createElement('div');fields.className='settings-form';
  const add=(name,label,options,value='')=>{const l=document.createElement('label');l.textContent=label;const input=document.createElement(options?'select':'input');input.name=name;input.required=true;if(options)for(const [id,text] of options){const o=document.createElement('option');o.value=id;o.textContent=text;input.append(o)}else input.value=value;l.append(input);fields.append(l);return input};
  add('edge_node_id',pi('Входная нода','Ingress node'),(nodes.nodes||[]).filter(n=>!n.revoked_at&&n.ingress_addr).map(n=>[n.id,n.id+' · '+n.country]));
  add('edge_panel_id',pi('Панель обслуживающей ноды','Serving node panel'),(peers.links||[]).filter(p=>!p.revoked_at&&String(p.scopes||'').split(',').includes('quota')).map(p=>[p.panel_id,p.panel_id]));
  add('subscription_id',pi('Подписка для начала обслуживания','Initial served subscription'),(subs.subscriptions||[]).filter(s=>!s.revoked_at&&!s.transferred_to).map(s=>[s.id,s.name+' · '+s.account_id]));
  add('owner_url',pi('HTTPS-адрес владельца, доступный ноде','Owner HTTPS origin reachable from the node'),null,location.origin);
  add('access_listen',pi('Адрес входного слушателя','Ingress listener address'),null,'0.0.0.0:8443');
  add('exit_dns_addr',pi('DNS внутри выхода · адрес:порт','Resolver inside the exit · host:port'),null,'');
  add('tls_cert',pi('Сертификат на входной ноде · полный путь','Certificate on ingress · absolute path'),null,'/etc/ara-edge/tls/fullchain.pem');
  add('tls_key',pi('Ключ сертификата на входной ноде · полный путь','Certificate key on ingress · absolute path'),null,'/etc/ara-edge/tls/key.pem');
  add('ca_cert',pi('Доверенный CA на входной ноде · полный путь','Trusted CA on ingress · absolute path'),null,'/etc/ssl/certs/ca-certificates.crt');
  const note=document.createElement('p');note.className='muted';note.textContent=pi('Пути относятся к входной ноде. Нужны готовые выходы и сертификаты; секреты сюда не вставляйте.','Paths are on the ingress host. Exits and certificates must already be configured; do not paste secrets here.');fields.prepend(note);
  let plan;
  const prepared=await openAction(pi('План входной ноды','Ingress deployment plan'),fields,pi('Проверить план','Validate plan'),async values=>{plan=await api('POST','/api/v1/edge-config/plan',{...values,state_dir:'/var/lib/ara-edge',status_file:'/var/lib/ara-edge/status.json'})});
  if(!prepared||!plan)return;
  const review=document.createElement('div');review.className='settings-form';
  const text=document.createElement('p');text.textContent=pi('Будет опубликована конфигурация для ','Publish the configuration for ')+plan.edge_node_id+' → '+plan.edge_panel_id;review.append(text);
  const hash=document.createElement('code');hash.style.overflowWrap='anywhere';hash.textContent=plan.plan_hash;review.append(hash);
  const details=document.createElement('p');details.textContent=pi('Конфигурация будет доступна только уполномоченной ноде. Службы и маршруты хоста эта кнопка не меняет.','Only the authorized node can fetch the configuration. This action does not change host services or routes.');review.append(details);
  if(await openAction(pi('Проверка публикации','Review publication'),review,pi('Опубликовать','Publish'),()=>api('POST','/api/v1/edge-config/apply',{plan_id:plan.plan_id,plan_hash:plan.plan_hash})))panelMessage(pi('План опубликован. Доставьте его через ara edge sync и проверьте работу ноды.','Plan published. Pull it with ara edge sync and verify the serving node.'));
 }catch(err){panelError(err)}
}
async function changeAdminPassword(){
  const fields=document.createElement('div');
  fields.className='settings-form';
  fields.innerHTML='<label>'+pi('Текущий пароль','Current password')+'<input type="password" name="current" required autocomplete="current-password"></label>'+
    '<label>'+pi('Новый пароль · от 14 символов','New password · 14 characters minimum')+'<input type="password" name="new_password" minlength="14" required autocomplete="new-password"></label>';
  const saved=await openAction(pi('Изменить пароль','Change password'),fields,pi('Сохранить','Save'),values=>api('POST',location.pathname+'/password',values));
  if(saved)location.reload();
}
async function loadPublicPage(){
 const page=await api('GET','/api/v1/public-page'),form=document.getElementById('public-page-form');
 for(const name of ['mode','title','text'])form.elements[name].value=page[name]||'';
}
async function savePublicPage(event){
 await submitSettings(event,'/api/v1/public-page',data=>data);
}
async function loadCertificateSettings(){
  const view=await api('GET','/api/v1/tls'), el=document.getElementById('cert-settings');
  const row=(label,description,value)=>'<div class="setting-row"><span class="setting-label"><strong>'+label+'</strong><small>'+description+
    '</small></span><span class="setting-value">'+value+'</span></div>';
  const file=path=>'<code class="cert-path">'+esc(path)+'</code><button type="button" class="secondary copy-path" data-path="'+
    esc(path)+'" onclick="copyCertificatePath(this)">'+pi('Копировать путь','Copy path')+'</button>';
  const active=view.active;
  const native=view.panel_tls==='native_https';
  el.innerHTML=row(pi('Веб-панель','Control Center'),native?pi('ARA обслуживает HTTPS напрямую.','ARA serves HTTPS directly.'):pi('HTTPS обслуживает обратный прокси. Файл ищите в его конфигурации.','The reverse proxy serves HTTPS. Find the file in its configuration.'),
    '<span class="pill">'+(native?'HTTPS':pi('Внешний прокси','External proxy'))+'</span>')+
    row(pi('Сертификат Edge','Edge certificate'),pi('Путь из свежего статуса локального Edge.','Path from the latest local Edge status.'),
      view.edge_tls?file(view.edge_tls):pi('Нет данных Edge','No Edge status'))+
    row(pi('Хранилище ARA','ARA certificate store'),active?esc((active.dns_names||[]).join(', '))+' · '+
      pi('До ','Expires ')+esc(new Date(active.not_after).toLocaleDateString()):pi('Сертификат не найден в локальном хранилище.','No certificate found in the local store.'),file(view.store_cert_path))+
    '<details class="setting-help"><summary>'+pi('Как установить или обновить сертификат','How to install or renew a certificate')+'</summary>'+
    '<p>'+pi('Откройте «Сеть → Настройка сети» для сценариев ACME, импорта и TLS веб-панели.','Open Network → Network setup for ACME, import and Control Center HTTPS.')+'</p>'+
    '<a href="#network">'+pi('Открыть настройки сети','Open network settings')+'</a></details>';
}
async function copyCertificatePath(button){
  try{await navigator.clipboard.writeText(button.dataset.path);panelMessage(pi('Путь скопирован.','Path copied.'))}
  catch{panelMessage(pi('Выделите путь в строке и скопируйте его.','Select the path in the row and copy it.'))}
}
function pill(state){const m={'healthy':'ok','down':'bad','suspect':'warn','quarantined':'bad'};return '<span class="pill '+(m[state]||'')+'">'+state+'</span>'}
let linkEditors=new Map();
function renderLinks(links, profiles){
  linkEditors=new Map();
  if(!links.length)return '<p class="network-empty">'+pi('Связей пока нет. Добавьте две ноды, чтобы связать вход с выходом.','No links yet. Add two nodes to connect ingress to exit.')+'</p>';
  return '<ul class="network-links">'+links.map(link=>{
    const matches=profiles.filter(p=>p.node_id===link.exit_id&&p.transport===link.transport);
    const options=matches.filter(p=>!p.revoked_at).map(p=>({id:p.id,label:transportLabel(p)+' · '+p.id.slice(0,10)}));
    const current=matches.find(p=>p.id===link.profile_id);
    const currentID=link.profile_id||'';
    const fallback=pi('Стандартный профиль','Default profile');
    if(link.transport==='tcp')options.unshift({id:'',label:fallback});
    const label=current ? transportLabel(current) : (currentID||link.transport!=='tcp'?
      pi('Профиль недоступен','Profile unavailable'):fallback);
    const unavailable=current?.revoked_at||(!current&&(currentID||link.transport!=='tcp'));
    const canChange=!link.revoked_at&&options.some(option=>option.id!==currentID);
    const path=link.edge_id+' → '+link.exit_id;
    if(canChange)linkEditors.set(link.id,{path,currentID,options});
    return '<li class="network-link">'+
      '<div class="network-link-path"><strong>'+esc(path)+'</strong><small>'+esc(link.transport.toUpperCase())+
      ' · '+pi('Приоритет ','Priority ')+esc(link.priority)+'</small></div>'+
      '<div class="network-link-profile"><small>'+pi('Профиль','Profile')+'</small><span>'+esc(label)+'</span>'+
      (link.revoked_at?'<span class="pill bad">'+pi('Связь отозвана','Link revoked')+'</span>':
        unavailable?'<span class="pill warn">'+pi('Требует настройки','Needs setup')+'</span>':'')+'</div>'+
      (canChange?'<button type="button" class="secondary network-link-edit" id="edit-link-'+esc(link.id)+'" data-link="'+esc(link.id)+
        '" aria-label="'+esc(pi('Изменить профиль для ','Change profile for ')+path)+'" onclick="editLinkProfile(this)">'+pi('Изменить','Change')+'</button>':'')+'</li>';
  }).join('')+'</ul><p class="network-links-note">'+pi(
    'После смены профиля подготовьте конфигурацию адаптера и примените её на Edge.',
    'After changing the profile, render and deploy the adapter configuration on Edge.')+'</p>';
}
async function editLinkProfile(button){
  const id=button.dataset.link;
  const editor=linkEditors.get(id);
  if(!editor)return;
  const choices=document.createElement('fieldset');
  choices.className='profile-choices';
  const legend=document.createElement('legend');
  legend.textContent=editor.path;
  choices.append(legend);
  for(const option of editor.options){
    const label=document.createElement('label');
    const input=document.createElement('input');
    input.type='radio';
    input.name='profile';
    input.value=option.id;
    input.required=true;
    input.checked=option.id===editor.currentID;
    label.append(input,document.createTextNode(option.label));
    choices.append(label);
  }
  const result=await openAction(pi('Изменить профиль','Change profile'),choices,pi('Сохранить','Save'));
  if(!result||result.profile===editor.currentID)return;
  button.disabled=true;
  try{
    await api('POST','/api/v1/links/set-profile',{link_id:id,profile_id:result.profile,legacy:!result.profile});
    await loadAll();
    panelMessage(pi('Профиль сохранён','Profile saved'));
  }catch(err){panelError(err)}
  finally{
    button.disabled=false;
    document.getElementById('edit-link-'+id)?.focus();
  }
}
function renderProfiles(ps,caps){
  const protocols=(caps.transit||[]).map(p=>'<span class="protocol-tag">'+esc(transportLabel(p))+'</span>').join('');
  const list=ps.length?'<div class="table-scroll"><table><tr><th>'+pi('Выход','Exit')+'</th><th>'+pi('Протокол','Protocol')+'</th><th></th></tr>'+
    ps.map(p=>'<tr><td>'+esc(p.node_id)+'</td><td>'+esc(transportLabel(p))+'</td>'+
    '<td>'+(p.revoked_at?'<span class="pill bad">'+pi('Отозван','Revoked')+'</span>':'<button class="secondary" data-id="'+esc(p.id)+'" onclick="revokeProfile(this)">'+pi('Отозвать','Revoke')+'</button>')+'</td></tr>').join('')+'</table></div>':
    '<p class="network-empty">'+pi('Сохранённых профилей пока нет.','No saved profiles yet.')+'</p>';
  return '<div class="protocol-tags">'+protocols+'</div>'+list;
}
let availableNodes=[], availableProfiles=[];
function openNetworkDialog(id){
  const dialog=document.getElementById(id);
  if(id==='link-editor')updateLinkChoices(dialog.querySelector('form'));
  dialog.showModal();
}
function fillNetworkChoices(select, values, fallback){
  const previous=select.value;
  select.replaceChildren();
  if(fallback!==undefined)select.add(new Option(fallback,''));
  for(const [id,label] of values)select.add(new Option(label,id));
  if(Array.from(select.options,o=>o.value).includes(previous))select.value=previous;
}
function updateNetworkEditors(nodes,profiles,caps){
  availableNodes=nodes.filter(n=>!n.revoked_at);
  availableProfiles=profiles.filter(p=>!p.revoked_at);
  const form=document.querySelector('#link-editor form');
  fillNetworkChoices(form.elements.edge_id,availableNodes.map(n=>[n.id,n.id]),pi("Выберите вход","Choose an ingress"));
  updateLinkChoices(form);
  document.getElementById('new-link').disabled=availableNodes.length<2;
  const protocols=(caps.transit||[]).map(p=>'<option value="'+esc(p.protocol)+'">'+esc(transportLabel(p))+'</option>').join('');
  document.getElementById('new-profile').disabled=!availableNodes.length||!protocols;
  const dialog=document.getElementById('profile-editor');
  if(dialog.open)return;
  dialog.innerHTML='<form class="settings-form" onsubmit="addProfile(event)"><header><h2 id="profile-editor-title">'+pi('Добавить профиль','Add profile')+'</h2>'+
    '<p>'+pi('Сертификат выхода должен соответствовать его имени SNI.','The exit certificate must match its SNI hostname.')+'</p></header>'+
    '<label>'+pi('Выход','Exit')+'<select name="node_id" required>'+availableNodes.map(n=>'<option value="'+esc(n.id)+'">'+esc(n.id)+'</option>').join('')+'</select></label>'+
    '<label>'+pi('Протокол','Protocol')+'<select name="protocol" onchange="updateCredentialLabel(this.form)">'+protocols+'</select></label>'+
    '<label>'+pi('Имя TLS (SNI)','TLS name (SNI)')+'<input name="server_name" required placeholder="exit.example"></label>'+
    '<label>'+pi('Файл CA на сервере','CA file on server')+'<input name="ca_path" placeholder="/etc/ssl/certs/ara-ca.pem"></label>'+
    '<label><span class="credential-label">UUID</span><input name="secret" type="password" autocomplete="off" required></label>'+
    '<p class="form-status" role="status"></p><footer class="settings-actions">'+
    '<button type="button" class="secondary" onclick="this.form.parentElement.close()">'+pi('Отмена','Cancel')+'</button>'+
    '<button type="submit">'+pi('Сохранить профиль','Save profile')+'</button></footer></form>';
  updateCredentialLabel(dialog.querySelector('form'));
}
function updateLinkChoices(form){
  const f=form.elements;
  fillNetworkChoices(f.exit_id,availableNodes.filter(n=>f.edge_id.value&&n.id!==f.edge_id.value).map(n=>[n.id,n.id]),pi("Выберите выход","Choose an exit"));
  const udp=f.transport.value==='udp';
  const choices=availableProfiles.filter(p=>p.node_id===f.exit_id.value&&p.transport===f.transport.value);
  fillNetworkChoices(f.profile_id,choices.map(p=>[p.id,transportLabel(p)+' · '+p.id.slice(0,10)]),
    udp?pi('Выберите профиль Hysteria2','Choose a Hysteria2 profile'):pi('Стандартный VLESS / внешний туннель','Default VLESS / external tunnel'));
  f.profile_id.required=udp;
  const hint=form.querySelector('.link-profile-hint');
  hint.textContent=udp&&f.exit_id.value&&!choices.length?pi('Для UDP сначала добавьте профиль Hysteria2 этой ноды.','For UDP, add a Hysteria2 profile for this node first.'):'';
}
async function addNetworkLink(event){
  await submitSettings(event,'/api/v1/links',data=>({...data,priority:Number(data.priority),profile_id:data.profile_id||null}));
}
function transportLabel(p){
  const names={vless:'VLESS',trojan:'Trojan',hysteria2:'Hysteria2'};
  return (names[p.protocol]||p.protocol)+' · '+String(p.transport).toUpperCase()+' + '+String(p.security).toUpperCase();
}
function updateCredentialLabel(form){
  form.querySelector('.credential-label').textContent=form.elements.protocol.value==='vless'?'UUID':pi('Пароль','Password');
}
async function submitSettings(event,path,build,afterSave){
  event.preventDefault();
  const form=event.currentTarget;
  const status=form.querySelector('.form-status');
  const submit=form.querySelector('button[type=submit], .settings-actions button');
  submit.disabled=true;
  status.textContent=pi('Сохраняем…','Saving…');
  try{
    const result=await api('POST',path,build(Object.fromEntries(new FormData(form))));
    form.reset();
    status.textContent='';
    const dialog=form.closest('dialog');
    if(dialog&&dialog.open)dialog.close();
    panelMessage(pi('Сохранено','Saved'));
    if(afterSave)afterSave(result);
    await loadAll().catch(panelError);
    return result;
  }catch(err){
    status.textContent=pi('Не удалось сохранить: ','Could not save: ')+err.message;
  }finally{submit.disabled=false}
}
function openNodeAccess(id){
  const dialog=document.getElementById('node-access-editor'), form=dialog.querySelector('form');
  form.reset();clearNodeAccess(form);updateAccessPurpose(form);
  form.dataset.localNode=id?'no':'yes';
  const node=availableNodes.find(n=>n.id===id);
  const port=node?.ingress_addr?.match(/:(\d+)$/)?.[1];
  if(port)form.elements.port.value=port;
  dialog.showModal();
}
function updateAccessPurpose(form){
  const transit=form.elements.kind.value==='transit';
  form.elements.source.required=transit;
  form.elements.source.placeholder=transit?pi('IP связанной ноды','Linked node IP'):pi('Пусто — любой IP','Blank — any IP');
  form.elements.interface.placeholder=transit?'tun0':'ens3';
}
function clearNodeAccess(form){
  form.querySelector('[data-access-result]').hidden=true;
  delete form.dataset.accessPlan;
  form.querySelector('.form-status').textContent='';
}
async function previewNodeAccess(event){
  event.preventDefault();
  const form=event.currentTarget, submit=event.submitter, status=form.querySelector('.form-status');
  clearNodeAccess(form);
  const fields=new FormData(form), data=Object.fromEntries(fields);
  submit.disabled=true;
  try{
    const plan=await api('POST','/api/v1/nodes/access/plan',{...data,port:Number(data.port),source:data.source.trim()});
    if(!form.closest('dialog').open||Array.from(fields).some(([key,value])=>form.elements[key].value!==value))return;
    const result=form.querySelector('[data-access-result]');
    const args=['sudo ara node access apply','--kind '+plan.kind,'--protocol '+plan.protocol,'--port '+plan.port,
      '--interface '+plan.interface,'--table '+plan.table];
    if(plan.source)args.push('--source '+plan.source);
    result.querySelector('textarea').value=args.join(' ');
    form.dataset.accessPlan=JSON.stringify(dataWithPort(plan));
    result.querySelector('[data-access-live]').hidden=!plan.local_helper||form.dataset.localNode!=='yes';
    result.hidden=false;
  }catch(err){status.textContent=pi('Не удалось подготовить правило. Проверьте порт, интерфейс и IP источника.','Could not prepare the rule. Check the port, interface and source IP.')}
  finally{submit.disabled=false}
}
function dataWithPort(plan){
  const {kind,protocol,port,source,table,interface:iface}=plan;
  return {kind,protocol,port,source,table,interface:iface};
}
async function changeNodeAccess(button,action){
  const form=button.form, plan=form.dataset.accessPlan, status=form.querySelector('.form-status');
  if(!plan)return;
  const buttons=form.querySelectorAll('[data-access-live] button');
  buttons.forEach(b=>b.disabled=true);
  try{
    await api('POST','/api/v1/nodes/access/'+action,JSON.parse(plan));
    if(form.dataset.accessPlan===plan)status.textContent=action==='apply'?pi('Правило применено на этой ноде.','Rule applied on this node.'):pi('Правило удалено с этой ноды.','Rule removed from this node.');
  }catch(err){
    if(form.dataset.accessPlan===plan)status.textContent=pi('Правило не применено. Проверьте разрешения и локальный помощник на этой ноде.','Rule not applied. Check permissions and the local helper on this node.');
  }finally{buttons.forEach(b=>b.disabled=false)}
}
async function addNode(event){
  const node=await submitSettings(event,'/api/v1/nodes',data=>({...data,country:data.country.toUpperCase(),priority:Number(data.priority)}));
  if(node)openNodeAccess(node.id);
}
async function addProfile(event){
  await submitSettings(event,'/api/v1/transit-profiles',data=>data);
}
async function revokeProfile(btn){
  if(!await confirmAction(pi('Отозвать профиль?','Revoke profile?'),
    pi('Связи с этим профилем потребуют перенастройки.','Links using this profile will need to be configured again.')))return;
  await api('POST','/api/v1/transit-profiles/revoke',{id:btn.dataset.id}).then(loadAll).catch(panelError);
}
// B38: every EXTERNAL string (panel DB rows, federated peer data, audit,
// errors) is escaped before it can reach an innerHTML sink.
function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function renderNodes(ns){
  if(!ns.length)return '<p class="network-empty">'+pi('Нод пока нет.','No nodes yet.')+'</p>';
  return '<ul class="settings-list node-list">'+ns.map(n=>'<li class="node-with-check"><button type="button" class="setting-row rule-row" data-id="'+esc(n.id)+
    '" data-addr="'+esc(n.ingress_addr||'')+'" data-sni="'+esc(n.ingress_sni||'')+'" onclick="editNodeIngress(this)"'+
    (n.revoked_at?' disabled':'')+'><span class="setting-label"><strong>'+esc(n.id)+'</strong><small>'+
    esc(n.country)+' · <span data-role="'+esc(n.role)+'">'+(n.role==='ru'?pi('Россия','Russia'):pi('Зарубежный выход','Foreign exit'))+
    '</span> · '+pi('Приоритет ','Priority ')+esc(n.priority)+'</small></span><span class="setting-value">'+
    esc(n.revoked_at?pi('Отозвана','Revoked'):n.ingress_addr||pi('Вход не задан','Ingress unset'))+'</span><span class="chevron" aria-hidden="true">›</span></button>'+(!n.revoked_at?'<button type="button" class="secondary" data-id="'+esc(n.id)+'" onclick="checkNodeConnection(this)">'+pi('Проверить','Check')+'</button>':'')+'</li>').join('')+'</ul>';
}
async function editNodeIngress(button){
  const fields=document.createElement('div');fields.className='settings-form';
  fields.innerHTML='<label class="route-wide">'+pi('Адрес входа для клиентов','Client ingress address')+
    '<input name="address" placeholder="edge.example.com:443" value="'+esc(button.dataset.addr)+'"></label>'+
    '<label class="route-wide">'+pi('Имя сертификата · TLS SNI','Certificate name · TLS SNI')+
    '<input name="sni" placeholder="edge.example.com" value="'+esc(button.dataset.sni)+'"></label>'+
    '<p class="muted route-wide">'+pi('Оставьте адрес пустым, если нода не принимает клиентов. Сертификат должен покрывать указанное имя.','Leave the address empty if the node does not accept clients. The certificate must cover the selected name.')+'</p>';
  const saved=await openAction(pi('Вход · ','Ingress · ')+button.dataset.id,fields,pi('Сохранить','Save'),
    values=>api('POST','/api/v1/nodes/ingress',{id:button.dataset.id,address:values.address.trim(),sni:values.sni.trim()}));
  if(saved)await loadAll().catch(panelError);
}
// ---- route rule editor (draft → validate → preview → diff-plan → apply) ----
let DRAFT=null, DRAFT_REV=null, ROUTE_NODES=[];
async function loadRoutes(){
  const pol=await api('GET','/api/v1/policy');
  DRAFT=JSON.parse(JSON.stringify(pol)); DRAFT_REV=pol.revision;
  renderRoutes();
}
async function refreshRoutePool(){
  const slot=document.getElementById('route-pool-status');
  if(!slot||document.getElementById('sec-routes')?.hidden)return;
  const pool=await api('GET','/api/v1/policy/pool');
  if(!slot.isConnected)return;
  slot.textContent=!pool.available?pi('Нет свежих данных Edge','No recent Edge data'):pool.exit_id?
    (pool.country?pool.country+' · ':'')+pool.exit_id:pi('Нет доступного зарубежного выхода','No available foreign exit');
}
setInterval(()=>refreshRoutePool().catch(()=>{}),5000);
function routeLabel(action, exitID){
  if(action==='FOREIGN_EXIT'){
    const node=ROUTE_NODES.find(n=>n.id===exitID);
    return exitID?(node&&node.country?node.country+' · ':'')+exitID:pi('Конкретный выход','Specific exit');
  }
  return ({RU_EXIT:pi('Выход в России','Exit in Russia'),DIRECT:pi('Без VPN · сеть устройства','Without VPN · device network'),
    FOREIGN_POOL:pi('Зарубежный пул · автоматически','Foreign pool · automatic'),BLOCK:pi('Заблокировать','Block')})[action]||action||'—';
}
const routeMatch=r=>[(r.domain_exact||[]).map(x=>'='+x),(r.domain_suffix||[]),(r.cidr||[])].flat().join(', ');
const routePorts=r=>(r.ports||[]).map(p=>p.from===p.to?String(p.from):p.from+'-'+p.to).join(', ');
function defaultExitOptions(){
  const selected=DRAFT.default_action==='FOREIGN_EXIT'?'exit:'+DRAFT.default_exit_id:(DRAFT.default_action||'FOREIGN_POOL');
  const options=[['BLOCK',pi('Блокировать на Edge','Block at Edge')],['RU_EXIT',pi('Россия','Russia')],['FOREIGN_POOL',pi('Зарубежный пул','Foreign pool')],
    ...ROUTE_NODES.map(node=>['exit:'+node.id,routeLabel('FOREIGN_EXIT',node.id)])];
  if(!options.some(([key])=>key===selected))options.push([selected,routeLabel('FOREIGN_EXIT',DRAFT.default_exit_id)]);
  return options.map(([key,label])=>'<option value="'+esc(key)+'"'+(key===selected?' selected':'')+'>'+esc(label)+'</option>').join('');
}
function setDefaultExit(value){
  if(value.startsWith('exit:')){
    DRAFT.default_action='FOREIGN_EXIT';
    DRAFT.default_exit_id=value.slice(5);
  } else {
    DRAFT.default_action=value;
    delete DRAFT.default_exit_id;
  }
  renderRoutes();
}
function renderRoutes(){
  const el=document.getElementById('routes'); if(!el||!DRAFT)return;
  queueMicrotask(()=>refreshRoutePool().catch(()=>{}));
  const rules=DRAFT.rules||[];
  const usesPool=(!DRAFT.default_action||DRAFT.default_action==='FOREIGN_POOL')||rules.some(r=>r.enabled!==false&&r.action==='FOREIGN_POOL');
  const query=document.getElementById('rule-search')?.value||'';
  const domain=document.getElementById('pv-domain')?.value||'';
  const port=document.getElementById('pv-port')?.value||'';
  const rows=rules.map((r,i)=>{
    const conditions=routeMatch(r);
    const title=r.comment||r.id;
    const target=routeLabel(r.action,r.exit_id);
    return '<li data-query="'+esc([title,r.id,conditions,target].join(' '))+'">'+
      '<button class="setting-row rule-row" type="button" onclick="editRule('+i+')">'+
      '<span class="rule-order">'+(i+1)+'</span><span class="setting-label"><strong>'+esc(title)+'</strong>'+
      '<small title="'+esc(conditions)+'">'+esc(conditions||pi('Условия не заданы','No conditions yet'))+'</small></span>'+
      '<span class="setting-value">'+(r.enabled===false?pi('Выключено','Off'):esc(target))+'</span><span class="chevron" aria-hidden="true">›</span></button></li>';
  }).join('');
  el.innerHTML='<div class="route-workspace"><div class="settings-group"><h2>'+pi('Трафик без совпадения','Unmatched traffic')+'</h2>'+
    '<div class="settings-list"><div class="setting-row"><span class="setting-label"><strong>'+pi('Маршрут по умолчанию','Default route')+
    '</strong><small>'+pi('Только для трафика, который уже дошёл до Edge. DIRECT задаётся в клиентском профиле.','For traffic that has already reached Edge. DIRECT is set in the client profile.')+'</small></span>'+
    '<select id="route-default-action" aria-label="'+pi('Маршрут по умолчанию','Default route')+'" onchange="setDefaultExit(this.value)">'+
    defaultExitOptions()+'</select></div>'+
    (usesPool?'<div class="setting-row"><span class="setting-label"><strong>'+pi('Текущий выход пула','Current pool exit')+
    '</strong><small>'+pi('По текущему состоянию Edge. Для отдельного правила можно выбрать ноду вручную.','Based on current Edge health. Individual rules can pin a node.')+
    '</small></span><span class="setting-value" id="route-pool-status" aria-live="polite">'+pi('Проверяем…','Checking…')+'</span></div>'+
    '<label class="setting-row"><span class="setting-label"><strong>'+pi('Резервный выход в России','Russian exit fallback')+
    '</strong><small>'+pi('Если недоступен весь зарубежный пул. Правила на конкретный выход останавливаются при отказе.','Used if the whole foreign pool is unavailable. Rules targeting a specific exit stop on failure.')+
    '</small></span><input class="setting-switch" type="checkbox" '+(DRAFT.allow_ru_fallback?'checked ':'')+'onchange="DRAFT.allow_ru_fallback=this.checked"></label>':'')+'</div></div>'+
    '<div class="settings-group"><h2>'+pi('При отказе выбранной ноды','When the selected exit is unavailable')+'</h2><div class="settings-list"><label class="setting-row">'+
    '<span class="setting-label"><strong>'+pi('Резерв для конкретного выхода','Fallback for a named exit')+'</strong><small>'+
    pi('Для правил на конкретную страну и профилей «через Россию».','For country-specific rules and dedicated transit profiles.')+'</small></span>'+
    '<select id="route-exit-fallback" onchange="DRAFT.foreign_exit_fallback=this.value">'+[
      ['block',pi('Блокировать','Block')],['ru',pi('Выход в России','Exit in Russia')],
      ['foreign',pi('Другая зарубежная нода','Another foreign exit')],['foreign_then_ru',pi('Другая зарубежная, затем Россия','Another foreign exit, then Russia')]
    ].map(([v,label])=>'<option value="'+v+'"'+((DRAFT.foreign_exit_fallback||'block')===v?' selected':'')+'>'+label+'</option>').join('')+
    '</select></label></div></div>'+
    '<div class="settings-group"><div class="settings-group-heading"><div><h2>'+pi('Правила','Rules')+' <small>'+rules.length+'</small></h2>'+
    '<p>'+pi('Срабатывает первое совпадение сверху. Выберите правило, чтобы изменить его.','The first matching rule wins. Select a rule to edit it.')+'</p></div>'+
    '<button type="button" class="secondary" onclick="openRouteLists()">'+pi('Списки правил','Rule lists')+'</button>'+
    '<button type="button" class="secondary" id="route-presets-button" onclick="openRoutePresets()">'+pi('Пресеты','Presets')+'</button>'+
    '<button type="button" class="secondary" onclick="addRule()">'+pi('Добавить правило','Add rule')+'</button></div>'+
    (rows?'<input type="search" id="rule-search" aria-label="'+pi('Поиск правил','Find rules')+'" placeholder="'+pi('Найти правило','Find a rule')+'" value="'+esc(query)+'" oninput="filterRules(this.value)">'+
    '<p class="settings-empty" id="rules-no-results" hidden>'+pi('Совпадений нет','No matches')+'</p><ol class="settings-list rule-list">'+rows+'</ol>':
    '<p class="settings-list empty-setting">'+pi('Пока нет отдельных правил. Добавьте правило или выберите подборку сервисов.','Add a rule or choose a service preset.')+'</p>')+'</div>'+
    '<div class="settings-group"><h2>'+pi('Проверка маршрута','Route check')+'</h2><div class="settings-list route-test-fields">'+
    '<label class="inline-field">'+pi('Домен или IP','Domain or IP')+'<input id="pv-domain" placeholder="example.com" value="'+esc(domain)+'"></label>'+
    '<label class="inline-field">'+pi('Порт','Port')+'<input id="pv-port" type="number" min="1" max="65535" placeholder="443" value="'+esc(port)+'"></label>'+
    '<button type="button" class="secondary" onclick="previewDraft()">'+pi('Проверить маршрут','Test route')+'</button></div></div>'+
    '<p id="routes-msg" role="status"></p><footer class="route-commit"><small>'+pi('Ревизия панели ','Panel revision ')+esc(DRAFT_REV)+'</small>'+
    '<button class="secondary" type="button" onclick="validateDraft()">'+pi('Проверить правила','Validate rules')+'</button>'+
    '<button class="secondary" type="button" onclick="downloadRoutePolicy()">'+pi('Скачать политику','Download policy')+'</button>'+
    '<button type="button" onclick="planApplyDraft()">'+pi('Сохранить на панели','Save to Control Center')+'</button></footer></div>';
  filterRules(query);
}
function filterRules(query){
  const term=query.trim().toLowerCase(), rows=[...document.querySelectorAll('.rule-list [data-query]')];
  for(const row of rows)row.hidden=!row.dataset.query.toLowerCase().includes(term);
  const empty=document.getElementById('rules-no-results');
  if(empty)empty.hidden=rows.some(row=>!row.hidden);
}
function dDraft(){ /* The detail form commits its edits when saved. */ }
function addRule(){editRule(-1)}
async function editRule(i){
  const rules=DRAFT.rules||[];
  let index=rules.length+1;
  while(rules.some(rule=>rule.id==='rule-'+index))index++;
  const r=rules[i]||{id:'rule-'+index,enabled:true,action:'FOREIGN_POOL'};
  const form=document.createElement('div');
  form.className='settings-form route-detail';
  const choices=[['FOREIGN_POOL',routeLabel('FOREIGN_POOL')],['RU_EXIT',routeLabel('RU_EXIT')],['DIRECT',routeLabel('DIRECT')],['BLOCK',routeLabel('BLOCK')]];
  for(const n of ROUTE_NODES)choices.push(['exit:'+n.id,routeLabel('FOREIGN_EXIT',n.id)]);
  const destination=r.action==='FOREIGN_EXIT'?'exit:'+r.exit_id:r.action;
  if(!choices.some(([value])=>value===destination))choices.push([destination,routeLabel(r.action,r.exit_id)+' · '+pi('нет в топологии','not in topology')]);
  form.innerHTML='<label class="route-wide">'+pi('Куда направить','Send traffic to')+'<select name="destination" data-f="action">'+choices.map(([value,label])=>
    '<option value="'+esc(value)+'"'+(value===destination?' selected':'')+'>'+esc(label)+'</option>').join('')+'</select></label>'+
    '<p class="route-wide muted">'+pi('Чтобы закрепить правило, выберите страну и ноду в списке. При отказе применяется выбранный резерв.','To pin a rule, choose a country and node from the list. If the node fails, the configured fallback applies.')+'</p>'+
    '<label class="route-wide">'+pi('Домены и IP-сети','Domains and IP networks')+
    '<textarea name="match" data-f="match" rows="3" placeholder="example.com, =login.example.com, 203.0.113.0/24">'+esc(routeMatch(r))+'</textarea>'+
    '<small>'+pi('Через запятую. «=» означает точный хост. Разные типы условий должны совпасть одновременно.','Separate with commas. “=” means exact host. Different condition types must all match.')+'</small></label>'+
    '<details class="route-wide settings-details"><summary>'+pi('Дополнительные условия','Advanced conditions')+'</summary><div class="settings-form">'+
    '<label>'+pi('Имя правила','Rule ID')+'<input name="id" data-f="id" required value="'+esc(r.id)+'"></label>'+
    '<label>'+pi('Протокол','Protocol')+'<select name="proto" data-f="proto"><option value="">'+pi('Любой','Any')+'</option>'+
    '<option value="tcp"'+(r.proto==='tcp'?' selected':'')+'>TCP</option><option value="udp"'+(r.proto==='udp'?' selected':'')+'>UDP</option></select></label>'+
    '<label>'+pi('Порты','Ports')+'<input name="ports" data-f="ports" pattern="[0-9, –\u002d]+" placeholder="443, 8000-8010" value="'+esc(routePorts(r))+'"></label>'+
    '<label>'+pi('Позиция в списке','Position in the list')+'<input type="number" name="position" min="1" max="'+(i<0?rules.length+1:rules.length)+'" value="'+(i<0?rules.length+1:i+1)+'" required></label></div></details>'+
    '<label class="route-wide setting-row"><span>'+pi('Правило включено','Rule enabled')+'</span><input name="enabled" class="setting-switch" type="checkbox"'+(r.enabled?' checked':'')+'></label>'+
    (i<0?'':'<button class="secondary" type="button" data-remove>'+pi('Удалить из черновика','Remove from draft')+'</button>');
  form.querySelector('[data-remove]')?.addEventListener('click',()=>document.getElementById('action-dialog').close('remove'));
  let candidate;
  const values=await openAction(i<0?pi('Новое правило','New rule'):pi('Настройка правила','Rule settings'),form,
    pi('Сохранить в черновик','Save to draft'),async values=>{
    const next={...r,id:values.id.trim(),enabled:values.enabled==='on',proto:values.proto,
      domain_exact:[],domain_suffix:[],cidr:[],ports:[]};
    for(const tok of values.match.split(',').map(x=>x.trim()).filter(Boolean)){
      if(tok.includes('/'))next.cidr.push(tok);
      else if(tok.startsWith('='))next.domain_exact.push(tok.slice(1));
      else next.domain_suffix.push(tok);
    }
    for(const token of values.ports.split(',').map(x=>x.trim()).filter(Boolean)){
      const parsed=/^(\d+)(?:\s*[-–]\s*(\d+))?$/.exec(token);
      if(!parsed)throw new Error(pi('Укажите порт или диапазон, например 443 или 8000-8010.','Enter a port or range, such as 443 or 8000-8010.'));
      next.ports.push({from:Number(parsed[1]),to:Number(parsed[2]||parsed[1])});
    }
    delete next.exit_id;
    next.action=values.destination;
    if(values.destination.startsWith('exit:')){next.action='FOREIGN_EXIT';next.exit_id=values.destination.slice(5)}
    if(next.action!=='FOREIGN_POOL')delete next.allow_ru_fallback;
    candidate={...DRAFT,rules:rules.slice()};
    if(i>=0)candidate.rules.splice(i,1);
    candidate.rules.splice(Number(values.position)-1,0,next);
    await api('POST','/api/v1/policy/draft/validate',candidate);
  });
  if(!values){
    if(document.getElementById('action-dialog').returnValue==='remove'){rules.splice(i,1);renderRoutes()}
    return;
  }
  DRAFT=candidate;
  renderRoutes();
  document.getElementById('routes-msg').textContent=pi('Правило сохранено в черновик.','Rule saved to the draft.');
}
async function validateDraft(){
  const msg=document.getElementById('routes-msg');
  try{
    dDraft();
    const result=await api('POST','/api/v1/policy/draft/validate',DRAFT);
    msg.textContent=result.valid?pi('Черновик валиден','Draft valid'):result.error;
  }catch(err){msg.textContent=err.message}
}
async function previewDraft(){
  const msg=document.getElementById('routes-msg');
  try{
    dDraft();
    const target=document.getElementById('pv-domain').value.trim();
    const body={candidate:DRAFT,proto:'tcp',port:parseInt(document.getElementById('pv-port').value||'443')};
    body[target.includes(':')||/^[0-9.]+$/.test(target)?'ip':'domain']=target;
    const result=await api('POST','/api/v1/policy/preview',body);
    msg.textContent=[
      pi('Правило: ','Rule: ')+(result.matched_rule_id||pi('по умолчанию','default')),
      pi('Запрошено: ','Requested: ')+routeLabel(result.desired_action,result.requested_exit_id),
      pi('Фактически по данным панели: ','Result from Control Center data: ')+routeLabel(result.actual_action,result.exit_id)+
        (result.exit_id?' · '+result.exit_id:''),
      result.reason_code==='SELECTED_EXIT_UNAVAILABLE'?pi('Нет подтверждения доступности выбранного выхода.','No confirmed availability for the selected exit.'):(result.reason_code||''),
      pi('Предпросмотр по данным этой панели. Применение на Edge проверяется отдельно.','Preview uses this panel’s data. Deployment to Edge is verified separately.')
    ].filter(Boolean).join('\n');
  }catch(err){msg.textContent=err.message}
}
async function planApplyDraft(){
  const msg=document.getElementById('routes-msg');
  try{
    dDraft();
    const plan=await api('POST','/api/v1/policy/diff-plan',DRAFT);
    if(!await confirmAction(pi('Применить правила маршрутизации?','Apply routing rules?'),
      pi('Политика сохранится на панели. Для Edge опубликуйте новую конфигурацию, для DIRECT загрузите политику на клиент ARA. Правил: ','The policy is saved on this panel. Deploy a new Edge configuration and load the policy on the ARA client for DIRECT. Rules: ')+(DRAFT.rules||[]).length,
      pi('Применить','Apply')))return;
    const result=await api('POST','/api/v1/policy/apply',{plan_id:plan.plan_id,plan_hash:plan.plan_hash});
    await loadRoutes();
    document.getElementById('routes-msg').textContent=pi('Сохранено на панели, ревизия ','Saved to Control Center, revision ')+result.new_revision;
  }catch(err){
    const stale=err.message.includes('PLAN_STALE')||err.message.includes('revision');
    msg.textContent=err.message+(stale?pi(' · обновите черновик',' · reload the draft'):'');
  }
}
// ---- diagnostics graphs (real speedtest history, no synthetic data) ----
async function loadDiag(){
  const h=await api('GET','/api/v1/diagnostics/history');
  const el=document.getElementById('diag'); if(!el)return;
  const recs=h.records||[];
  if(!recs.length){
    el.innerHTML='<article class="network-panel diagnostic-empty"><header><div><h2>'+pi('Измерений пока нет','No measurements yet')+
      '</h2><p>'+pi('Здесь появятся результаты замеров скорости.','Speed measurements will appear here.')+
      '</p></div></header><div class="network-panel-body"><p class="muted">'+
      pi('Проверить доступность входа можно в разделе «Сеть».','You can check ingress connectivity in Network.')+
      '</p><a href="#network">'+pi('Открыть сеть','Open Network')+'</a></div></article>';return;
  }
  let html='<p class="muted">'+pi('Источник: ','Source: ')+esc(h.source)+' · '+recs.length+' '+pi('измерений','records')+'</p>';
  // per-direction series: goodput by time
  const down=[],up=[],labels=[];
  recs.forEach(rec=>{ (rec.results||[]).forEach(r=>{
    const m=(r.metrics||{}); const v=m.goodput_mbps; if(typeof v!=='number')return;
    const at=(rec.at||''); (r.direction==='down'?down:up).push({at,v});
  });});
  html+='<p>goodput Mbit/s — <b>'+pi('загрузка','download')+'</b></p><div class="spark" id="g-down"></div>';
  if(up.length)html+='<p>goodput Mbit/s — <b>'+pi('отдача','upload')+'</b></p><div class="spark" id="g-up"></div>';
  html+='<table><tr><th>'+pi('время','time')+'</th><th>exit</th><th>'+pi('напр.','dir')+'</th><th>Mbit/s</th><th>RTT p50/p95</th><th>'+pi('ошибки проб','failed probes')+'</th><th>'+pi('лимит','limited')+'</th></tr>';
  recs.slice(-10).reverse().forEach(rec=>(rec.results||[]).forEach(r=>{
    const m=r.metrics||{};
    html+='<tr><td>'+esc((rec.at||'').replace('T',' ').slice(0,19))+'</td><td>'+esc(r.dest)+'</td><td>'+esc(r.direction)+'</td><td>'+(typeof m.goodput_mbps==='number'?m.goodput_mbps.toFixed(1):'—')+'</td><td>'+(m.rtt_p50_idle_ms||0).toFixed(0)+'/'+(m.rtt_p95_idle_ms||0).toFixed(0)+' ms</td><td>'+((m.failed_probe_ratio||0)*100).toFixed(1)+'%</td><td>'+(r.rate_limited?'<span class="pill warn">'+pi('да','yes')+'</span>':'')+'</td></tr>';
  }));
  html+='</table>';
  el.innerHTML=html;
  const draw=(id,arr)=>{const e2=document.getElementById(id); if(!e2)return;
    spark(e2, arr.map(x=>x.v));};
  draw('g-down',down); if(up.length)draw('g-up',up);
}
// B43: full subscription lifecycle through the UI — create (token/URL/QR
// shown ONCE), rotate, transfer, rate, device limit, revoke — over the
// same service layer as the CLI/API.
function renderSubs(ss,devices,localEdge){
  let html='<details class="settings-details"><summary>'+pi('Выдать подписку','Issue a subscription')+'</summary>'+
  '<form class="settings-form" onsubmit="createSub(event)">'+
  '<label>'+pi('Имя пользователя','Username')+'<input name="account_id" required placeholder="my_test" maxlength="80">'+
  (localEdge?'<small>'+pi('Если пользователя ещё нет, ARA создаст его при выдаче.','ARA creates the user when issuing access if needed.')+'</small>':'')+'</label>'+
  '<label>'+pi('Название подписки','Subscription name')+'<input name="name" required></label>'+
  '<fieldset id="sub-routes" class="profile-choices route-wide"><legend>'+pi('Конфиги в одной подписке','Configs in one subscription')+'</legend><p class="muted">'+pi('Можно выбрать несколько маршрутов. Клиент получит каждый отдельным конфигом по одной ссылке.','Select multiple routes to receive separate configs through one link.')+'</p></fieldset>'+
  '<label>'+pi('Устройства · максимум','Device slots · maximum')+'<input name="max_devices" type="number" min="1" placeholder="'+pi('Без ограничения','Unlimited')+'"></label>'+
  '<label>'+pi('Общий объём, МБ','Total quota, MB')+'<input name="quota_mb" type="number" min="0" step="any" placeholder="'+pi('Без лимита','Unlimited')+'"></label>'+
  '<label>'+pi('Срок, секунды','Lifetime, seconds')+'<input name="ttl_seconds" type="number" min="0" placeholder="'+pi('Без срока','No expiry')+'"></label>'+
  '<label>'+pi('Формат первой ссылки','Initial link format')+'<select name="share_format">'+
  '<option value="mobile">VLESS + TLS</option>'+(LOCAL_TROJAN?'<option value="trojan">Trojan + TLS</option>':'')+
  '<option value="ara">'+pi('Клиент ARA','ARA client')+'</option></select></label>'+
  '<div class="settings-actions"><button id="sub-create">'+pi('Создать подписку','Create subscription')+'</button></div>'+
  '<p class="form-status" role="status"></p></form></details>';
  if(!ss.length)return html+'<p class="settings-empty">'+pi('Подписок пока нет.','No subscriptions yet.')+'</p>';
  const formatBytes=value=>{
    const bytes=Number(value);
    if(bytes<1024)return bytes+' '+pi('Б','B');
    const power=Math.min(4,Math.floor(Math.log(bytes)/Math.log(1024)));
    return (bytes/1024**power).toLocaleString(undefined,{maximumFractionDigits:2})+' '+(pi('Б КиБ МиБ ГиБ ТиБ','B KiB MiB GiB TiB').split(' ')[power]);
  };
  const limit=value=>value==null?pi('Без лимита','Unlimited'):formatBytes(value);
  const rate=value=>value==null?pi('Без лимита','Unlimited'):(value/1000000).toLocaleString()+pi(' Мбит/с',' Mbps');
  html+='<div class="settings-list access-ledger">';
  ss.forEach(x=>{
    const expired=x.expires_at&&Date.parse(x.expires_at)<=Date.now();
    const active=!x.revoked_at&&!x.transferred_to&&!expired&&x.active!==false;
    const badge=x.revoked_at?pi('Отозвана','Revoked'):x.transferred_to?pi('Передана','Transferred'):expired?pi('Истекла','Expired'):
      x.active===false?pi('Ожидает активации','Pending activation'):pi('Активна','Active');
    const usage=localEdge&&!x.local_usage&&active?pi('Нет данных Edge','No Edge data'):x.usage_available?(formatBytes(x.used_bytes??0)+' / '+limit(x.limits_bytes)):pi('Нет данных владельца','Owner data unavailable');
    html+='<details class="ledger-entry" name="selected-subscription" data-subscription="'+esc(x.id)+'" ontoggle="openSubscriptionDetails(this)"><summary class="setting-row"><span class="setting-label"><strong>'+esc(x.name)+'</strong><small>'+
      esc(x.account_id)+' · '+esc(x.owner_panel)+'</small><small data-live-state>'+
      (x.local_usage?(x.local_usage.connections?pi('Онлайн','Online'):pi('Нет открытых соединений','No open connections')):'')+'</small></span><span class="setting-value ledger-usage">'+esc(usage)+'</span><span class="pill '+(active?'ok':'warn')+'">'+
      badge+'</span><span class="chevron" aria-hidden="true">›</span></summary><div class="ledger-detail">'+
      '<header class="subscription-focus"><div><small>'+pi('Открыта подписка','Selected subscription')+'</small><h3>'+esc(x.name)+'</h3>'+
      '<p>'+pi('Пользователь','User')+' · '+esc(x.account_id)+'</p></div>'+
      (active&&x.usage_available?'<div class="subscription-primary">'+
        '<button type="button" data-id="'+esc(x.id)+'" onclick="subscriptionShare(this)">'+pi('Ссылка и QR','Link and QR')+'</button>'+
        '<button type="button" class="secondary" data-id="'+esc(x.id)+'" onclick="editSubscriptionProfiles(this)">'+pi('Конфигурации','Configurations')+'</button>'+'</div>':'')+
      '</header>'+
      (active&&x.usage_available?'<div class="subscription-current-configs" data-config-summary aria-live="polite"></div>':'');
    if(x.usage_available){
      html+='<section class="subscription-activity" data-activity><header><h3>'+pi('Активность','Activity')+
        '</h3><select aria-label="'+pi('Период активности','Activity period')+'" onchange="loadSubscriptionActivity(this.closest(\'details\'))"><option value="1">'+
        pi('24 часа','24 hours')+'</option><option value="7">'+pi('7 дней','7 days')+'</option></select></header>'+
        '<div data-activity-plot aria-live="polite"></div><p class="muted">'+
        pi('По времени поступления отчёта. Устройства считаются по уникальным ключам с трафиком за интервал.','Grouped by report time. Devices count distinct credentials that reported traffic in the interval.')+'</p></section>';
      html+='<div class="ledger-rates"><span>'+pi('Загрузка','Download')+' <strong>'+esc(rate(x.rate_down_bps))+'</strong></span><span>'+
        pi('Отдача','Upload')+' <strong>'+esc(rate(x.rate_up_bps))+'</strong></span>'+
        (active?'<button type="button" class="secondary" data-id="'+esc(x.id)+'" data-down="'+esc(x.rate_down_bps??'')+
        '" data-up="'+esc(x.rate_up_bps??'')+'" onclick="editSubscriptionRate(this)">'+pi('Изменить скорость','Edit speed limits')+'</button>':'')+'</div>';
      html+='<div class="ledger-rates"><span>'+pi('Объём за месяц','Monthly quota')+' <strong>'+esc(limit(x.limits_bytes))+'</strong></span>'+
        (active?'<button type="button" class="secondary" data-id="'+esc(x.id)+'" data-limit="'+esc(x.limits_bytes??'')+
        '" onclick="editSubscriptionQuota(this)">'+pi('Изменить объём','Edit quota')+'</button>':'')+'</div>';
      const deviceIDs=new Set([...Object.keys(x.device_usage||{}),...Object.keys(x.device_limits||{}),
        ...devices.filter(d=>d.account_id===x.account_id).map(d=>d.id)]);
      const registered=devices.filter(d=>d.account_id===x.account_id&&!d.revoked_at).length;
      html+='<div class="setting-row device-usage"><span class="setting-label"><strong>'+pi('Зарегистрированные устройства','Registered devices')+
        '</strong><small>'+pi('Для каждого телефона или компьютера выдавайте отдельную ссылку. Копии одного ключа считаются одним устройством.','Issue a separate link for each phone or computer. Copies of one key count as one device.')+'</small></span><span class="setting-value">'+
        registered+' / '+esc(x.max_devices??pi('Без ограничения','Unlimited'))+'</span>'+
        (active?'<button type="button" class="secondary" data-id="'+esc(x.id)+'" data-max="'+esc(x.max_devices??'')+
         '" onclick="editDeviceSlots(this)">'+pi('Слоты','Slots')+'</button><button type="button" class="secondary" data-id="'+esc(x.id)+'" onclick="addSubscriptionDevice(this)">'+pi('Добавить устройство','Add device')+'</button>':'')+'</div>';
      html+='<p class="muted">'+pi('Учтённый объём включает загрузку и отдачу. Показания поступают из журнала владельца.','Accounted volume includes download and upload. Values come from the owner ledger.')+'</p>';
      for(const id of deviceIDs){
        const device=devices.find(d=>d.id===id);
        const bytes=x.device_usage?.[id];
        const expiry=device?.expires_unix?new Date(device.expires_unix*1000):null;
        const state=device?.revoked_at?pi('Отозвано','Revoked'):expiry&&expiry<=new Date()?pi('Срок истёк','Expired'):'';
        const accessArgs=' data-id="'+esc(x.id)+'" data-device="'+esc(id)+'" data-expiry="'+esc(device?.expires_unix||'')+'"';
        const deviceLink=active&&!device?.revoked_at?'<button type="button" class="secondary"'+accessArgs+' data-name="'+esc(device?.name||id)+'" onclick="showDeviceLink(this)">'+pi('Ссылка устройства','Device link')+'</button>':'';
        html+='<div class="setting-row device-usage"><span class="setting-label"><strong>'+esc(device?.name||id)+'</strong><small>'+
          esc(state||id)+(expiry?' · '+esc(expiry.toLocaleString()):'')+'</small><small data-seen-device="'+esc(id)+'"></small></span><span class="setting-value">'+
          esc((bytes==null?pi('Нет записей','No records'):formatBytes(bytes))+' / '+limit(x.device_limits?.[id]))+'</span>'+
          (active&&device&&!device.revoked_at?'<div class="node-actions">'+deviceLink+'<button type="button" class="secondary"'+accessArgs+
            ' data-limit="'+esc(x.device_limits?.[id]??'')+'" onclick="editDeviceLimit(this)">'+pi('Лимит','Limit')+'</button>'+
            '<button type="button" class="secondary"'+accessArgs+' onclick="editSubscriptionDeviceAccess(this,\'expiry\')">'+pi('Срок','Expiry')+'</button>'+
            
            '<button type="button" class="danger"'+accessArgs+' onclick="editSubscriptionDeviceAccess(this,\'revoke\')">'+pi('Отозвать устройство','Revoke device')+'</button>'+'</div>':'')+'</div>';
      }
    }
    if(active&&x.usage_available)html+='<div class="settings-actions ledger-actions">'+
      '<button type="button" class="secondary" data-id="'+esc(x.id)+'" onclick="transferSub(this)">'+pi('Передать','Transfer')+'</button>'+
      '<button type="button" class="danger" data-id="'+esc(x.id)+'" onclick="revokeSub(this)">'+pi('Отозвать подписку','Revoke subscription')+'</button></div>';
    if(x.revoked_at&&x.usage_available)html+='<div class="settings-actions ledger-actions">'+
      '<button type="button" class="danger" data-id="'+esc(x.id)+'" onclick="deleteSub(this)">'+pi('Удалить из списка','Remove from list')+'</button></div>';
    html+='</div></details>';
  });
  return html+'</div>';
}
function parseMbps(value){return value===''?null:Math.round(Number(value)*125000)*8}
function quotaBytes(mb){
  if(mb==='')return null;
  const bytes=Math.round(Number(mb)*1000000);
  if(!Number.isSafeInteger(bytes)||bytes<0)throw new Error(pi('Введите допустимый объём в МБ.','Enter a valid quota in MB.'));
  return bytes;
}
async function editSubscriptionQuota(button){
  const fields=document.createElement('div');
  fields.className='settings-form';
  fields.innerHTML='<label>'+pi('Объём за месяц, МБ','Monthly quota, MB')+'<input name="quota_mb" type="number" min="0" step="any" value="'+
    esc(button.dataset.limit===''?'':Number(button.dataset.limit)/1000000)+'" placeholder="'+pi('Без лимита','Unlimited')+'"></label>'+
    '<p class="muted">'+pi('Общий лимит загрузки и отдачи для всех конфигов. Пусто — без лимита, 0 — остановить трафик.','Shared download and upload quota across all configs. Leave blank for unlimited, or enter 0 to stop traffic.')+'</p>';
  const saved=await openAction(pi('Объём подписки','Subscription quota'),fields,pi('Сохранить','Save'),
    values=>api('POST','/api/v1/subscriptions/quota',{id:button.dataset.id,limits_bytes:quotaBytes(values.quota_mb)}));
  if(saved)await loadAll().catch(panelError);
}
async function deleteSub(button){
  if(!await confirmAction(pi('Удалить отозванную подписку из списка? История расхода и аудит сохранятся.','Remove the revoked subscription from the list? Usage history and audit will be retained.'), '', pi('Удалить','Remove')))return;
  await api('POST','/api/v1/subscriptions/delete',{id:button.dataset.id}).then(loadAll).catch(panelError);
}
async function editSubscriptionRate(button){
  const fields=document.createElement('div');
  fields.className='settings-form';
  fields.innerHTML='<label>'+pi('Название для клиента','Client display name')+'<input data-cap="name" maxlength="120" type="text"></label>'+
        '<label>'+pi('Загрузка, Мбит/с','Download, Mbps')+'<input name="download_bps" type="number" min="0.01" step="any" value="'+
    esc(button.dataset.down===''?'':Number(button.dataset.down)/1000000)+'" placeholder="'+pi('Без лимита','Unlimited')+'"></label><label>'+pi('Отдача, Мбит/с','Upload, Mbps')+
    '<input name="upload_bps" type="number" min="0.01" step="any" value="'+esc(button.dataset.up===''?'':Number(button.dataset.up)/1000000)+'" placeholder="'+pi('Без лимита','Unlimited')+'"></label>';
  const saved=await openAction(pi('Общая скорость подписки','Shared subscription speed'),fields,pi('Сохранить','Save'),
    values=>api('POST','/api/v1/subscriptions/rate',{id:button.dataset.id,download_bps:parseMbps(values.download_bps),
      upload_bps:parseMbps(values.upload_bps)}));
  if(saved)await loadAll().catch(panelError);
}
async function editDeviceLimit(button){
  const fields=document.createElement('div');
  fields.className='settings-form';
  fields.innerHTML='<label>'+pi('Объём, МБ','Quota, MB')+'<input name="quota_mb" type="number" min="0" step="any" value="'+
    esc(button.dataset.limit===''?'':Number(button.dataset.limit)/1000000)+'" placeholder="'+pi('Без отдельного лимита','No separate limit')+'"></label>';
  const saved=await openAction(pi('Лимит устройства','Device quota'),fields,pi('Сохранить','Save'),
    values=>api('POST','/api/v1/subscriptions/device-limit',{id:button.dataset.id,device_id:button.dataset.device,
      limit_bytes:quotaBytes(values.quota_mb)}));
  if(saved)await loadAll().catch(panelError);
}
async function addSubscriptionDevice(button){
 const id=button.dataset.id;let issued;
 const fields=document.createElement('div');fields.className='settings-form';
 fields.innerHTML='<label class="route-wide">'+pi('Название устройства','Device name')+'<input name="name" type="text" required maxlength="120" placeholder="iPhone"></label>';
 const result=await openAction(pi('Новое устройство','New device')+' · '+subscriptionContext(id),fields,
 pi('Создать и выдать ссылку','Create and issue link'),async values=>{
  issued=await api('POST','/api/v1/subscriptions/device-access',{id,action:'add',name:values.name.trim()});
 });
 if(result){await loadAll();showSubscriptionLink(id,issued.url,'mobile',issued.device_name,false)}
}
async function showDeviceLink(button){
 try{const result=await api('POST','/api/v1/subscriptions/device-access',{id:button.dataset.id,device_id:button.dataset.device,action:'link'});
 showSubscriptionLink(button.dataset.id,result.url,'mobile',button.dataset.name,false)}catch(err){panelError(err)}
}
async function editDeviceSlots(button){
  const fields=document.createElement('div');
  fields.className='settings-form';
  fields.innerHTML='<label class="route-wide">'+pi('Количество устройств','Number of devices')+'<input name="max_devices" type="number" min="1" step="1" value="'+
    esc(button.dataset.max)+'" placeholder="'+pi('Без ограничения','Unlimited')+'"></label>';
  const saved=await openAction(pi('Слоты устройств','Device slots'),fields,pi('Сохранить','Save'),
    values=>api('POST','/api/v1/subscriptions/device-slots',{id:button.dataset.id,max_devices:values.max_devices===''?null:Number(values.max_devices)}));
  if(saved)await loadAll().catch(panelError);
}
function updateSubscriptionNodes(nodes, links, localEdge, ruOnly, readyRoutes){
  const list=document.getElementById('sub-routes'), submit=document.getElementById('sub-create');
  const active=nodes.filter(n=>!n.revoked_at);
  const byID=new Map(active.map(n=>[n.id,n]));
  const country=countryLabel;
  const add=(profile,title,detail)=>{
    const row=document.createElement('label'), box=document.createElement('input'), copy=document.createElement('span');
    row.className='subscription-route';
    box.type='checkbox';box.name='profile';box.value=JSON.stringify(profile);
    box.dataset.kind=profile.kind;box.dataset.edge=profile.edge_node_id||profile.node_id;
    box.dataset.source=byID.get(profile.edge_node_id||profile.node_id)?.remote_panel||pi('Эта панель','This panel');
    const name=document.createElement('strong'), description=document.createElement('small');
    name.textContent=title;description.textContent=detail;
    copy.append(name,description);row.append(box,copy);list.append(row);
    return box;
  };
  const edges=new Set(links.filter(l=>!l.revoked_at&&byID.has(l.exit_id)).map(l=>l.edge_id));
  for(const node of active.filter(n=>n.ingress_addr&&n.role==='ru'&&(localEdge?localEdge===n.id:edges.has(n.id)))){
    const box=add({kind:'policy',node_id:node.id},pi('По правилам сервера','Server routing rules')+' · '+node.id,
      pi('Выход определяют правила этого входа.','The ingress routing rules select the exit.')+' · '+(node.remote_panel||pi('Эта панель','This panel')));
    if(localEdge)box.checked=true;
  }
  for(const link of links){
    const edge=byID.get(link.edge_id), exit=byID.get(link.exit_id);
    if(link.revoked_at||!edge||!exit||edge.role!=='ru'||!edge.ingress_addr||localEdge&&localEdge!==edge.id||readyRoutes&&!readyRoutes[exit.id])continue;
    add({kind:'transit',node_id:exit.id,edge_node_id:edge.id},country(exit.country)+pi(' · вход: ',' · ingress: ')+country(edge.country),
      edge.id+' → '+exit.id+' · '+(edge.remote_panel||pi('Эта панель','This panel')));
  }
  for(const node of active.filter(n=>n.ingress_addr)){
    if(localEdge){
      if(node.id===localEdge&&ruOnly)add({kind:'direct',node_id:node.id},pi('Только Россия','Russia only'),
        pi('Подключение и выход через российскую ноду.','Connect and exit through the Russian node.'));
    } else if(node.role!=='ru'){
      add({kind:'direct',node_id:node.id},country(node.country)+pi(' напрямую',' direct'),
        node.id+' · '+(node.remote_panel||pi('Эта панель','This panel')));
    }
  }
  const boxes=[...list.querySelectorAll('input')];
  const refresh=()=>{
    const linked=new Set(boxes.filter(box=>box.checked&&box.dataset.kind==='transit').map(box=>box.dataset.edge));
    for(const box of boxes.filter(box=>box.dataset.kind==='policy')){
      box.disabled=!localEdge&&!linked.has(box.dataset.edge);
      if(box.disabled)box.checked=false;
    }
    submit.disabled=!boxes.some(box=>box.checked);
  };
  if(!boxes.length||!localEdge){
    const note=document.createElement('p');note.className='muted';
    note.textContent=!boxes.length?pi('Сначала настройте входную ноду в разделе «Сеть».','Set up an ingress node in Network first.'):
      pi('Чтобы включить правила сервера, добавьте хотя бы один разрешённый зарубежный выход.','To enable server routing rules, select at least one permitted foreign exit.');
    list.append(note);
  }
  list.addEventListener('change',refresh);refresh();
}
async function refreshSubscriptionMetrics(){
  if(document.getElementById('sec-access')?.hidden||document.hidden)return;
  const data=await api('GET','/api/v1/subscriptions');
  if(!data.local_edge)return;
  for(const sub of data.subscriptions||[]){
    const row=document.querySelector('details[data-subscription="'+CSS.escape(sub.id)+'"]');
    if(!row)continue;
    const state=row.querySelector('[data-live-state]');
    if(state)state.textContent=sub.local_usage?(sub.local_usage.connections?pi('Онлайн','Online'):pi('Нет открытых соединений','No open connections')):'';
    const usage=row.querySelector('.ledger-usage');
    if(usage&&sub.local_usage){
      const format=n=>n>=1048576?(n/1048576).toLocaleString(undefined,{maximumFractionDigits:1})+' MiB':n.toLocaleString()+' B';
      usage.textContent=format(sub.local_usage.used_bytes)+' / '+(sub.limits_bytes==null?pi('Без лимита','Unlimited'):format(sub.limits_bytes));
    }
  }
}
setInterval(()=>refreshSubscriptionMetrics().catch(()=>{}),5000);
setInterval(()=>{
  if(document.getElementById('sec-access')?.hidden||document.hidden)return;
  const entry=document.querySelector('details.ledger-entry[open]');
  if(entry)void loadSubscriptionActivity(entry,true);
},15000);
async function openSubscriptionDetails(entry){
  if(!entry.open)return;
  // Also enforce single selection on browsers without named details groups.
  for(const other of entry.parentElement.querySelectorAll('details.ledger-entry[open]')){
    if(other!==entry)other.open=false;
  }
  void loadSubscriptionActivity(entry);
  const summary=entry.querySelector('[data-config-summary]');
  if(!summary)return;
  try{
    const {profiles,origin_panel}=await api('GET','/api/v1/subscriptions/profiles?id='+encodeURIComponent(entry.dataset.subscription));
    if(!entry.open||!entry.isConnected)return;
    const label=document.createElement('strong');
    label.textContent=pi('В подписке','In this subscription')+' · '+profiles.length;
    const list=document.createElement('ul');
    for(const profile of profiles){
      const item=document.createElement('li');
      const rates=[profile.download_bps,profile.upload_bps];
      const cap=value=>value==null?'∞':(value/1000000).toLocaleString();
      item.textContent=pi(profile.label_ru,profile.label_en)+' · '+profile.node_id+(profile.source_panel?' · '+pi('Источник: ','Source: ')+(profile.source_panel===origin_panel?pi('эта панель','this panel'):profile.source_panel):'')+(profile.ingress_addr?' · '+profile.ingress_addr:'')+(rates.some(value=>value!=null)?' · '+cap(rates[0])+' ↓ / '+cap(rates[1])+' ↑ '+pi('Мбит/с','Mbps'):'');
      list.append(item);
    }
    summary.replaceChildren(label,list);
  }catch(err){summary.textContent=pi('Не удалось загрузить конфиги','Could not load configs')}
}
function subscriptionContext(id){
  const entry=document.querySelector('details[data-subscription="'+CSS.escape(id)+'"]');
  return entry?.querySelector('.subscription-focus h3')?.textContent||'';
}
function parseProfileMiB(value){
 if(value.trim()==='')return null;
 const n=Number(value)*1048576;if(!Number.isSafeInteger(n)||n<0)throw new Error(pi('Укажите объём в МиБ с точностью до байта.','Enter a MiB volume with byte precision.'));return n;
}
async function editSubscriptionProfiles(button){
  try{
    const id=button.dataset.id;
    const {profiles,origin_panel}=await api('GET','/api/v1/subscriptions/profiles?id='+encodeURIComponent(id));
    const choices=document.getElementById('sub-routes').cloneNode(true);
    choices.removeAttribute('id');
    choices.classList.add('subscription-config-picker');
    for(const p of choices.querySelectorAll(':scope > p'))p.remove();
    choices.querySelector('legend')?.classList.add('visually-hidden');
    const boxes=[...choices.querySelectorAll('input[name="profile"]')];
    for(const box of boxes){
      const option=JSON.parse(box.value);
      const profile=profiles.find(p=>p.node_id===option.node_id&&
        (option.kind==='direct'?p.kind==='direct':p.kind==='transit'&&Boolean(p.route_port)===(option.kind==='transit')&&(!option.edge_node_id||p.edge_node_id===option.edge_node_id)));
      box.checked=!!profile;box.disabled=false;
      const row=box.closest('label');
      const fields=document.createElement('div');
      fields.className='settings-form profile-cap-fields';
      fields.innerHTML='<label>'+pi('Название для клиента','Client display name')+'<input data-cap="name" maxlength="120" type="text"></label>'+
        '<label>'+pi('Загрузка, Мбит/с','Download, Mbps')+'<input data-cap="down" type="number" min="0" step="any"></label>'+
        '<label>'+pi('Отдача, Мбит/с','Upload, Mbps')+'<input data-cap="up" type="number" min="0" step="any"></label>'+
        '<label>'+pi('Объём за месяц, МиБ','Monthly volume, MiB')+'<input data-cap="volume" type="number" min="0" step="any"></label>';
      row.after(fields);
      fields.querySelector('[data-cap=name]').value=profile?(LANG==='ru'?profile.label_ru:profile.label_en):'';
      fields.querySelector('[data-cap=name]').placeholder=pi('Автоматическое название','Automatic name');
      const origin=document.createElement('p');origin.className='muted';origin.textContent=pi('Нода: ','Node: ')+(option.edge_node_id?option.edge_node_id+' → ':'')+option.node_id+' · '+pi('Источник: ','Source: ')+(profile?.source_panel===origin_panel?pi('эта панель','this panel'):(profile?.source_panel||box.dataset.source||''));fields.prepend(origin);
      for(const [key,value] of [['down',profile?.download_bps],['up',profile?.upload_bps]]){
        const input=fields.querySelector('[data-cap="'+key+'"]');
        input.placeholder=pi('Без лимита','Unlimited');
        if(value!=null)input.value=value/1000000;
      }
      const volume=fields.querySelector('[data-cap=volume]');volume.placeholder=pi('Без лимита','Unlimited');if(profile?.limit_bytes!=null)volume.value=profile.limit_bytes/1048576;
      fields.hidden=!box.checked;
      for(const input of fields.querySelectorAll('input'))input.disabled=!box.checked;
      box.onchange=()=>{
        fields.hidden=!box.checked;
        for(const input of fields.querySelectorAll('input'))input.disabled=!box.checked;
      };
    }
    const hint=document.createElement('p');
    hint.className='muted';
    hint.textContent=pi('Выберите конфигурации и задайте имена для клиента. Пустые лимиты — без дополнительных ограничений; 0 запрещает передачу. Общий лимит подписки действует всегда. Объём сбрасывается в начале месяца по UTC.','Choose configurations and their client names. Blank caps add no restriction; 0 forbids traffic. Shared subscription limits always apply. Volume resets at the start of each UTC month.');
    choices.prepend(hint);
    const saved=await openAction(pi('Конфиги · ','Configs · ')+subscriptionContext(id),choices,pi('Сохранить конфиги','Save configs'),()=>{
      const selected=boxes.filter(box=>box.checked).map(box=>{
        const fields=box.closest('label').nextElementSibling;
        return {...JSON.parse(box.value),name:fields.querySelector('[data-cap=name]').value.trim(),download_bps:parseMbps(fields.querySelector('[data-cap=down]').value),
          upload_bps:parseMbps(fields.querySelector('[data-cap=up]').value),limit_bytes:parseProfileMiB(fields.querySelector('[data-cap=volume]').value)};
      });
      return api('POST','/api/v1/subscriptions/profiles',{id,profiles:selected});
    });
    if(saved)await loadAll();
  }catch(err){panelError(err)}
}
let LOCAL_TROJAN=false;
const sessionSubscriptionLinks=new Map();
let pendingSubscriptionFocus='';
function showSubscriptionLink(id,url,format='mobile',name=subscriptionContext(id),cache=true){
  if(!url){panelError(new Error(pi('Задайте HTTPS-адрес подписок в настройках.','Set the subscription HTTPS address in Settings.')));return}
  if(cache)sessionSubscriptionLinks.set(id,{url,format});
  const content=document.createElement('div');
  const entry=document.querySelector('details[data-subscription="'+CSS.escape(id)+'"]');
  if(entry)entry.open=true;
  else pendingSubscriptionFocus=id;
  fillSubscriptionLink(content,url,{format,showQR:true});
  void openAction(pi('Ссылка и QR','Link and QR')+(name?' · '+name:''),content,pi('Закрыть','Close'),undefined,true).finally(()=>content.replaceChildren());
}
async function subscriptionShare(button){
  const id=button.dataset.id;
  const existing=sessionSubscriptionLinks.get(id);
  if(existing){showSubscriptionLink(id,existing.url,existing.format);return}
  try{
    const saved=await api('GET','/api/v1/subscriptions/link?id='+encodeURIComponent(id));
    if(saved.saved){showSubscriptionLink(id,saved.url);return}
    await rotateSub(button);
  }catch(err){panelError(err)}
}
async function createSub(event){
  const form=new FormData(event.currentTarget);
  const format=form.get('share_format');
  const profiles=form.getAll('profile').map(value=>JSON.parse(value));
  profiles.sort((a,b)=>Number(b.kind==='policy')-Number(a.kind==='policy'));
  await submitSettings(event,'/api/v1/subscriptions',data=>{
    const body={account_id:data.account_id.trim(),name:data.name.trim(),ttl_seconds:Number(data.ttl_seconds),
      profiles};
    if(data.max_devices!=='')body.max_devices=Number(data.max_devices);
    body.limits_bytes=quotaBytes(data.quota_mb);
    return body;
  },result=>showSubscriptionLink(result.subscription.id,result.url,format,result.subscription.name));
}
async function rotateSub(btn){const id=btn.dataset.id;
  if(!await confirmAction(pi('Показать новую ссылку и QR? Старая ссылка перестанет обновляться.','Show a new link and QR? The old URL will stop updating immediately.')))return;
  const r=await api('POST','/api/v1/subscriptions/rotate',{id,grace_seconds:0});
  if(r&&r.error){panelError(new Error(r.error));return}
  showSubscriptionLink(id,r.url);
  await loadAll().catch(panelError);
}
async function transferSub(btn){const id=btn.dataset.id;
  const fields=document.createElement('div');
  fields.className='settings-form';
  fields.innerHTML='<label>'+pi('Идентификатор панели','Panel ID')+'<input name="target_panel" required></label>'+
    '<label>'+pi('Адрес панели','Panel URL')+'<input name="target_base" type="url" placeholder="https://panel.example" required></label>';
  const data=await openAction(pi('Передать подписку','Transfer subscription'),fields,pi('Передать','Transfer'));
  if(!data)return;
  await api('POST','/api/v1/subscriptions/transfer',{id,...data}).then(loadAll).catch(panelError);
}
async function revokeSub(btn){const id=btn.dataset.id;
  if(!await confirmAction(pi('Отозвать подписку? Обслуживание прекратится на всех edge.','Revoke subscription? Service stops on every edge.')))return;
  const r=await api('POST','/api/v1/subscriptions/revoke',{id});
  if(r&&r.error){panelError(new Error(r.error));return} sessionSubscriptionLinks.delete(id);loadAll();
}
// B43: federation flows through the UI (invite create/share, links).
function renderFed(links,panelID){
  let html='<p class="muted">'+pi('Связь панелей использует HTTPS. Через OpenVPN укажите HTTPS-имя удалённой панели, которое доступно внутри туннеля и указано в её сертификате.','Panels communicate over HTTPS. With OpenVPN, use the peer HTTPS name reachable inside the tunnel and covered by its certificate.')+'</p>'+
  '<div class="row"><input id="fed-panel" aria-label="'+pi('ID удалённой панели','Peer panel ID')+'" placeholder="panel-de">'+
  '<input id="fed-scopes" placeholder="nodes,subscriptions,quota" size="22">'+
  '<button onclick="createFedInvite()">'+pi('Выдать приглашение','Create invite')+'</button><button type="button" class="secondary" onclick="redeemFedInvite()">'+pi('Принять приглашение','Accept invite')+'</button></div>'+
  '<p><button type="button" class="secondary" onclick="shareFedTopology()">'+pi('Передать выбранные ноды','Share selected nodes')+'</button></p>'+
  '<div id="fed-secret" class="muted"></div>'+
  '<p class="muted">panel: <b>'+esc(panelID)+'</b></p>';
  if(links&&links.length){
    html+='<table><tr><th>panel</th><th>'+pi('статус','state')+'</th><th>scopes</th></tr>'+
    links.map(l=>'<tr><td>'+esc(l.panel_id||l.id||'')+'</td><td>'+esc(l.state||'linked')+'</td><td>'+esc(l.scopes||'')+'</td></tr>').join('')+'</table>';
  }
  return html;
}
async function shareFedTopology(){
 try{
  const [topology,fed]=await Promise.all([api('GET','/api/v1/nodes'),api('GET','/api/v1/panel/links')]);
  const peers=(fed.links||[]).filter(p=>!p.revoked_at&&String(p.scopes||'').split(',').includes('nodes'));
  if(!peers.length)throw new Error(pi('Сначала свяжите панели с правом nodes.','Link a peer with nodes permission first.'));
  const fields=document.createElement('div');fields.className='settings-form';
  fields.innerHTML='<label>'+pi('Связанная панель','Linked panel')+'<select name="panel_id">'+peers.map(p=>'<option value="'+esc(p.panel_id)+'">'+esc(p.panel_id)+'</option>').join('')+'</select></label>'+
   '<label>'+pi('HTTPS-адрес панели','Panel HTTPS address')+'<input name="base" type="url" required placeholder="https://panel.example:29445"></label>'+
   '<p class="muted">'+pi('Будут переданы только выбранные ноды. Секреты и доступ к серверу не передаются.','Only selected nodes are shared. No secrets or server access are transferred.')+'</p>';
  const selected=[];
  for(const n of (topology.nodes||[]).filter(n=>!n.revoked_at&&!n.remote_panel&&(n.ingress_addr||n.role==='foreign'))){
   const label=document.createElement('label');label.className='route-choice';
   const box=document.createElement('input');box.type='checkbox';box.value=n.id;
   const text=document.createElement('span');text.textContent=n.id+' · '+countryLabel(n.country);
   label.append(box,text);fields.append(label);selected.push(box);
  }
  const saved=await openAction(pi('Обмен нодами','Share nodes'),fields,pi('Передать','Share'),values=>{
   const node_ids=selected.filter(b=>b.checked).map(b=>b.value);
   if(!node_ids.length)throw new Error(pi('Выберите хотя бы одну ноду.','Select at least one node.'));
   return api('POST','/api/v1/panel/share',{...values,node_ids});
  });if(saved)await loadAll();
 }catch(err){panelError(err)}
}
async function createFedInvite(){
  const body={invited_panel:document.getElementById('fed-panel').value.trim(),
    scopes:document.getElementById('fed-scopes').value.trim()||'nodes,subscriptions,quota',ttl_seconds:3600};
  const r=await api('POST','/api/v1/panel/invites',body);
  if(r&&r.error){panelError(new Error(r.error));return}
  document.getElementById('fed-secret').innerHTML='<p>'+pi('Одноразовый токен приглашения (показан один раз): ','One-time invite token (shown once): ')+'<code>'+esc(r.token)+'</code></p>'+
  '<p class="muted">'+pi('Передайте его доверенной панели: она вызовет POST /api/fed/v1/link/redeem.','Hand it to the trusted panel: it calls POST /api/fed/v1/link/redeem.')+'</p>';
}
async function redeemFedInvite(){
  const fields=document.createElement('div');fields.className='settings-form';
  fields.innerHTML='<label class="route-wide">'+pi('HTTPS-адрес панели, выдавшей приглашение','Inviting panel HTTPS address')+
    '<input name="base" type="url" placeholder="https://panel.example" required></label>'+
    '<label class="route-wide">'+pi('Одноразовый токен','One-time token')+'<input name="token" type="password" autocomplete="off" required></label>';
  const saved=await openAction(pi('Связать панели','Link panels'),fields,pi('Связать','Link'),
    values=>api('POST','/api/v1/panel/redeem',{base:values.base.trim(),token:values.token.trim()}));
  if(saved)await loadAll().catch(panelError);
}
function renderAccounts(accounts,subscriptions){
  if(!accounts.length)return pi('Пользователей нет','No users');
  const inUse=new Set(subscriptions.filter(s=>!s.revoked_at&&!s.transferred_to).map(s=>s.account_id));
  return '<div class="settings-list">'+accounts.map(a=>'<div class="setting-row"><span class="setting-label"><strong>'+esc(a.id)+'</strong></span>'+
    (inUse.has(a.id)?'<small class="muted">'+pi('Сначала отзовите подписки','Revoke subscriptions first')+'</small>':
      '<button type="button" class="secondary" data-id="'+esc(a.id)+'" onclick="deleteAccount(this)">'+pi('Удалить пользователя','Remove user')+'</button>')+'</div>').join('')+'</div>';
}
async function deleteAccount(button){
  const id=button.dataset.id;
  if(!await confirmAction(pi('Удалить пользователя','Remove user')+' · '+id,
    pi('Устройства будут отозваны. История и аудит сохранятся.','Devices will be revoked. History and audit are retained.'),pi('Удалить','Remove')))return;
  await api('POST','/api/v1/accounts/delete',{id}).then(loadAll).catch(panelError);
}
function renderDevices(ds,local){if(!ds.length)return pi('Устройств нет','No devices');
  return '<table><tr><th>id</th><th>'+pi('имя','name')+'</th><th>account</th><th></th></tr>'+
  ds.map(d=>'<tr><td>'+esc(d.id)+'</td><td>'+esc(d.name)+'</td><td>'+esc(d.account_id)+'</td><td>'+
  (d.revoked_at?'<span class="pill bad">'+pi('отозвано','revoked')+'</span>':local?'':'<button class="danger" data-id="'+esc(d.id)+'" onclick="revokeDevice(this)">'+pi('отозвать','revoke')+'</button>')+'</td></tr>').join('')+'</table>'}
async function revokeDevice(btn){if(!await confirmAction(pi('Отозвать устройство? Доступ прекратится на data plane.','Revoke device? Access ends on the data plane.')))return;
  await api('POST','/api/v1/devices/revoke',{id:btn.dataset.id}); loadAll()}
function renderInvites(inv){if(!inv.length)return pi('Приглашений нет','No invites');
  return '<table><tr><th>id</th><th>device</th><th>'+pi('истекает','expires')+'</th><th>'+pi('статус','status')+'</th></tr>'+
  inv.map(i=>'<tr><td>'+esc(i.id)+'</td><td>'+esc(i.device_id)+'</td><td>'+esc(new Date(i.expires_at).toLocaleString())+'</td><td>'+
  (i.revoked_at?'<span class="pill bad">revoked</span>':(i.consumed_at?'<span class="pill">used</span>':'<span class="pill ok">active</span>')+
  ' <button class="secondary" data-id="'+esc(i.id)+'" onclick="revokeInvite(this)">'+pi('отозвать','revoke')+'</button>')+'</td></tr>').join('')+'</table>'}
async function revokeInvite(btn){if(!await confirmAction(pi('Отозвать приглашение?','Revoke invite?')))return;
  await api('POST','/api/v1/invites/revoke',{id:btn.dataset.id}); loadAll()}
function renderAudit(es){return '<table><tr><th>'+pi('время','time')+'</th><th>actor</th><th>'+pi('действие','action')+'</th><th>'+pi('результат','result')+'</th></tr>'+
  es.map(e=>'<tr><td>'+esc(new Date(e.at).toLocaleString())+'</td><td>'+esc(e.actor)+'</td><td>'+esc(e.action)+'</td><td>'+(e.result==='ok'?'<span class="pill ok">ok</span>':'<span class="pill bad">'+esc(e.result)+'</span>')+'</td></tr>').join('')+'</table>'}
// Keep browser navigation and deep links in sync with the selected section.
function showSection(){
  clearSubscriptionLinks();
  if(new URLSearchParams(location.hash.slice(1)).has('key'))history.replaceState(null,'',location.pathname);
  const selected=location.hash.slice(1);
  const section=['overview','network','access','routes','diagnostics','settings'].includes(selected)?selected:'overview';
  document.querySelectorAll('main > section').forEach(el=>{el.hidden=el.id!=='sec-'+section});
  if(section==='routes')void refreshRoutePool().catch(()=>{});
  document.querySelectorAll('.sidenav a[data-sec]').forEach(a=>{
    const active=a.dataset.sec===section;
    a.classList.toggle('active',active);
    if(active)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');
  });
}
window.addEventListener('hashchange',()=>{showSection();window.scrollTo(0,0)});
showSection();
` + dashboardJS + "\n" + routePresetsJS + "\n" + subActivityJS + `
loadAll().catch(panelError);

</script>`)
	return b.String()
}

func pi(lang, ru, en string) string {
	if lang == "en" {
		return en
	}
	return ru
}
