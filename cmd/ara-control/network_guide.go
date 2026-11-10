package main

func networkFormActions(lang, ru, en string) string {
	return `<p class="form-status" role="status"></p><footer class="settings-actions">
<button type="button" class="secondary" onclick="this.form.parentElement.close()">` + pi(lang, "Отмена", "Cancel") + `</button>
<button type="submit">` + pi(lang, ru, en) + `</button></footer>`
}

func networkGuide(lang string) string {
	return `<dialog class="network-dialog network-guide" id="network-guide" aria-labelledby="network-guide-title">
<header class="guide-heading"><div><h2 id="network-guide-title">` + pi(lang, "Настройка двух нод", "Set up two nodes") + `</h2>
<p>` + pi(lang, "Клиент → входная нода → внешний выход → интернет", "Client → ingress → foreign exit → internet") + `</p></div>
<form method="dialog"><button class="secondary">` + pi(lang, "Закрыть", "Close") + `</button></form></header>
<section class="guide-tls"><h3>` + pi(lang, "Сначала выберите адрес панели", "First choose a Control Center address") + `</h3>
<ul><li>` + pi(lang, "С доменом: направьте DNS на сервер, настройте HTTPS на прокси и проверьте сертификат. Затем укажите адрес панели через --admin-origin или admin.origin и получите ссылку, логин и пароль через --admin-credentials.",
		"With a domain: point DNS at the server, configure HTTPS on the proxy, and verify the certificate. Set the origin using --admin-origin or admin.origin, then use --admin-credentials to get the link, username, and password.") + `</li>
<li>` + pi(lang, "Без домена: настройте HTTPS на IP-адресе. Сертификат должен содержать этот IP в SAN. Для частного CA добавьте его в доверенные на обеих панелях и на подключаемых устройствах. Используйте https://IP для панели и федерации, а адрес подписок задайте в «Настройках».",
		"Without a domain: configure HTTPS on the IP address. The certificate must include that IP in its SAN. For a private CA, install it in the trust stores of both panels and connecting devices. Use https://IP for Control Center and federation, and set the subscription origin in Settings.") + `</li>
<li>` + pi(lang, "Для локального управления можно открыть HTTP через SSH-туннель. Для связи разных панелей по сети нужен HTTPS, в том числе поверх OpenVPN или WireGuard.",
		"For local management, you can open HTTP through an SSH tunnel. Panel federation across hosts requires HTTPS, including over OpenVPN or WireGuard.") + `</li></ul>
</section>
<ol class="setup-steps">
<li><strong>` + pi(lang, "Подготовьте внешний Exit", "Prepare the foreign Exit") + `</strong><p>` + pi(lang,
		"Зарегистрируйте de-exit. Выберите DNS-имя или IP для входа на ноду. Для VLESS, Trojan или Hysteria2 выпустите сертификат на это имя и настройте выход. Для OpenVPN используйте PKI своего туннеля, для WireGuard — ключи.",
		"Register de-exit and choose a DNS name or IP address for the node. For VLESS, Trojan or Hysteria2, issue a certificate for this hostname and configure the exit. Use your tunnel PKI for OpenVPN and keys for WireGuard.") + `</p></li>
<li><strong>` + pi(lang, "Подготовьте входной Edge", "Prepare the ingress Edge") + `</strong><p>` + pi(lang,
		"Зарегистрируйте ru-edge. Выпустите отдельный сертификат на адрес входного сервера. Укажите публичный адрес, порт и то же TLS-имя через ara node set-ingress.",
		"Register ru-edge and issue a separate certificate for the ingress address. Set its public address, port and TLS name with ara node set-ingress.") + `</p></li>
<li><strong>` + pi(lang, "Соедините Edge → Exit", "Connect Edge → Exit") + `</strong><p>` + pi(lang,
		"Создайте профиль транзита и связь ru-edge → de-exit. Для существующего OpenVPN или WireGuard укажите SOCKS5 и интерфейс в --backbones-file. Подготовьте и примените план Edge на панели, затем выполните ara edge sync на входе.",
		"Create a transit profile and link ru-edge → de-exit. For an existing OpenVPN or WireGuard tunnel, specify its SOCKS5 endpoint and interface in --backbones-file. Create and apply the Edge plan in the control state, then run ara edge sync on ingress.") + `</p></li>
<li><strong>` + pi(lang, "Настройте маршруты и проверьте подключение", "Configure routes and verify access") + `</strong><p>` + pi(lang,
		"В «Маршруты → Пресеты» выберите группы, раскройте список доменов и добавьте их в черновик. Проверьте тестовые адреса, примените правила и доставьте политику на Edge и клиент. Затем проверьте выход на живом подключении.",
		"In Routes → Presets, select groups, review their domains and add them to the draft. Test addresses, apply the rules and deploy policy to Edge and the client. Then check the exit on a live connection.") + `</p></li>
</ol>
<section class="guide-tls"><h3>` + pi(lang, "Выпуск TLS на каждой ноде", "Issue TLS on each node") + `</h3>
<p>` + pi(lang, "Выполните команду сначала на Exit с его доменом, затем на Edge со своим. Сертификат HTTPS для панели настраивается на её прокси отдельно.",
		"Run this on Exit with its hostname, then on Edge with its own hostname. Configure the Control Center HTTPS certificate separately on its proxy.") + `</p>
<pre><code>ara --state-dir /path/to/private-state tls renew \
  --acme-dir https://acme-v02.api.letsencrypt.org/directory \
  --hostname exit.example.com</code></pre>
<p>` + pi(lang, "Для HTTP-01 домен должен вести на нужную ноду, а публичный TCP 80 — быть доступным. Если его уже обслуживает сайт, используйте его ACME-клиент или DNS-01 и импортируйте PEM через ara tls import.",
		"For HTTP-01, DNS must resolve to the corresponding node and public TCP 80 must be reachable. If an existing site uses it, use its ACME client or DNS-01 and import the PEM via ara tls import.") + `</p>
</section>
</dialog>`
}
