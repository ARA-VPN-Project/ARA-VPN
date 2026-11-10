package main

func routePresetDialog(lang string) string {
	return `<dialog class="network-dialog preset-dialog" id="route-presets" aria-labelledby="route-presets-title">
<form onsubmit="submitRoutePresets(event)">
<div class="preset-scroll">
<header><h2 id="route-presets-title">` + pi(lang, "Пресеты маршрутизации", "Routing presets") + `</h2>
<p>` + pi(lang, "Выберите подборку, затем проверьте сервисы и домены. Правила попадут в черновик.", "Choose a collection, then review its services and domains. Rules are added to the draft.") + `</p></header>
<div class="preset-packs">
<button type="button" class="secondary" onclick="choosePresetPack('stream')">` + pi(lang, "Стриминги+", "Streaming+") + `</button>
<button type="button" class="secondary" onclick="choosePresetPack('ai')">` + pi(lang, "ИИ", "AI") + `</button>
<button type="button" class="secondary" onclick="choosePresetPack('google')">` + pi(lang, "Весь Google", "All Google") + `</button>
<button type="button" class="secondary" onclick="choosePresetPack('attachment')">` + pi(lang, "Весь расширенный список", "Full expanded list") + `</button>
</div>
<p class="muted">` + pi(lang, "Расширенный список включает Apple с зарубежным выходом. DeepSeek, Kimi и российские сервисы по-прежнему выбираются отдельно.",
		"The expanded list includes Apple through a foreign exit. DeepSeek, Kimi and Russian services are still selected separately.") + `</p>
<label>` + pi(lang, "Поиск по сервису, домену или IP-сети", "Find a service, domain or IP network") + `
<input type="search" class="preset-search" oninput="filterRoutePresets(this.value)"></label>
<p class="muted preset-no-results" hidden>` + pi(lang, "Совпадений нет", "No matches") + `</p>
<div class="preset-list" onchange="updatePresetCount()"></div>
<p class="muted">` + pi(lang, "Ранее добавленные правила остаются выше. «Без VPN» действует в клиенте ARA и выводит трафик в локальную сеть. Доменные правила не гарантируют вход в аккаунт или работу звонков.",
		"Existing rules stay ahead of presets. Without VPN uses the ARA client's local network. Domain rules do not guarantee sign-in or calls.") + `</p>
</div><p class="form-status" role="status"></p><footer class="settings-actions">
<button type="button" data-preset-cancel class="secondary" onclick="this.form.parentElement.close()">` + pi(lang, "Отмена", "Cancel") + `</button>
<button type="submit">` + pi(lang, "Добавить в черновик", "Add to draft") + `</button></footer>
</form></dialog>`
}
