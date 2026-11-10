package main

import (
	_ "embed"
	"net/http"

	"aravpn/internal/webui"
)

//go:embed public.css
var publicCSS string

const publicKeyIcon = `<span class="public-card-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="9" r="4"/><path d="m11 12 8 8m-4-4 2-2m0 4 2-2"/></svg></span>`

func publicShell(lang, body string) string {
	return `<style>` + publicCSS + `</style><div class="public-shell">
<header class="public-header">
  <nav class="public-wrap public-nav" aria-label="` + pi(lang, "Навигация", "Navigation") + `">
    <a href="/" class="public-brand" aria-label="` + pi(lang, "ARA VPN · на главную", "ARA VPN · Home") + `"><span class="public-brand-mark" aria-hidden="true">A</span>ARA VPN</a>
    <button type="button" class="public-language" lang="` + pi(lang, "en", "ru") + `" onclick="langToggle()">` + pi(lang, "English", "Русский") + `</button>
  </nav>
</header>
<main class="public-main"><div class="public-wrap">` + body + `</div></main></div>`
}

func (s *server) handleGuest(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	p, err := readStartPage(s.stateDir)
	if err != nil {
		http.Error(w, "Page unavailable", http.StatusServiceUnavailable)
		return
	}
	if p.Mode == "neutral" {
		p.Title = "Welcome"
		p.Text = "A quiet place on the web."
	}
	if p.Mode == "index" {
		p.Title = "Index"
		p.Text = ""
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
	if r.Method == http.MethodHead {
		return
	}
	_ = startPageTemplate.Execute(w, p)
}

// The link carries the invitation in its fragment. Redeem it only after
// the visitor explicitly chooses to enroll the device.
func (s *server) handleEnrollPage(w http.ResponseWriter, r *http.Request) {
	adminPageHeaders(w)
	lang := pageLang(r)
	body := `<div class="public-flow">
<h1>` + pi(lang, "Регистрация устройства", "Device enrollment") + `</h1>
<section class="public-card">` + publicKeyIcon + `
<h2 id="enroll-heading">` + pi(lang, "Откройте приглашение", "Open your invitation") + `</h2>
<p id="enroll-hint">` + pi(lang, "Попросите администратора прислать ссылку, затем откройте её целиком в браузере.", "Ask your administrator for an invitation, then open the complete link in your browser.") + `</p>
<p id="status" role="status"></p>
<button id="go" class="public-button" type="button" hidden>` + pi(lang, "Зарегистрировать устройство", "Enroll this device") + `</button>
</section></div>`
	script := `<script>
const enrollButton=document.getElementById('go');
const enrollHeading=document.getElementById('enroll-heading');
const enrollHint=document.getElementById('enroll-hint');
const enrollStatus=document.getElementById('status');
const invitation=location.hash.slice(1);
if(invitation){
  enrollHeading.textContent=t('Приглашение открыто','Invitation opened');
  enrollHint.textContent=t('Подтвердите регистрацию на этом устройстве. Ссылка действует один раз.','Confirm enrollment on this device. The link can only be used once.');
  enrollButton.hidden=false;
}
enrollButton.addEventListener('click',async()=>{
  if(!invitation||enrollButton.disabled)return;
  enrollButton.disabled=true;
  enrollStatus.dataset.result='';
  enrollStatus.textContent=t('Регистрируем…','Enrolling…');
  try{
    const response=await fetch('/api/v1/invites/redeem',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:invitation}),redirect:'error',cache:'no-store',referrerPolicy:'no-referrer'});
    if(!response.ok){
      enrollStatus.dataset.result='error';
      enrollStatus.textContent=response.status===401
        ? t('Приглашение недействительно или уже использовано. Попросите новую ссылку.','This invitation is invalid or already used. Ask for a new link.')
        : t('Регистрация недоступна. Попробуйте ещё раз.','Enrollment is unavailable. Try again.');
      return;
    }
    history.replaceState(null,'',location.pathname+location.search);
    enrollHeading.textContent=t('Устройство зарегистрировано','Device enrolled');
    enrollHint.textContent=t('Для подключения импортируйте профиль, который выдаст администратор.','To connect, import the profile provided by your administrator.');
    enrollStatus.textContent=t('Регистрация завершена.','Enrollment complete.');
    enrollButton.hidden=true;
  }catch{
    enrollStatus.dataset.result='error';
    enrollStatus.textContent=t('Не удалось связаться с сервером. Попробуйте ещё раз.','Could not reach the server. Try again.');
  }finally{
    if(!enrollButton.hidden)enrollButton.disabled=false;
  }
});
</script>`
	w.Write([]byte(webui.HTML(lang, pi(lang, "Регистрация · ARA VPN", "Enrollment · ARA VPN"), publicShell(lang, body)+script)))
}
