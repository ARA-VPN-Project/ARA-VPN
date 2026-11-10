let presetCatalog;
function preloadRoutePresets(){
  if(!presetCatalog)presetCatalog=api('GET','/api/v1/policy/presets').catch(err=>{presetCatalog=null;throw err});
  return presetCatalog;
}
window.addEventListener("DOMContentLoaded",()=>preloadRoutePresets().catch(()=>{}));
async function openRoutePresets() {
  const dialog = document.getElementById('route-presets');
  const container = dialog.querySelector('.preset-list');
  const status = dialog.querySelector('.form-status');
  const submit = dialog.querySelector('button[type=submit]');
  dialog.querySelector('.preset-search').value = '';
  container.replaceChildren();
  submit.disabled = true;
  status.textContent = pi('Загружаем каталог…', 'Loading the catalog…');
  dialog.showModal();
  try {
    const {presets} = await preloadRoutePresets();
    if (!dialog.open) return;
    container.innerHTML = presets.map(preset => {
      const suffixes = preset.suffix.concat(preset.extra_suffix || []);
      const hosts = preset.exact.concat(preset.extra_exact || []);
      const suffix = suffixes.map(esc).join(', ');
      const exact = hosts.map(esc).join(', ');
      const networks = preset.cidr || [];
      const cidr = networks.map(esc).join(', ');
      const examples = preset.examples.map(esc).join(', ');
      const size = suffixes.length + hosts.length;
      const direct = preset.action === 'DIRECT';
      return '<article class="preset-option"><label><input type="checkbox" name="selected" value="'+esc(preset.id)+
        '" data-pack="'+esc(preset.pack)+'"><strong>'+esc(preset.title)+'</strong><span class="pill '+(direct?'warn':'')+'">'+
        (direct?pi('Без VPN','Without VPN'):pi('За рубеж','Foreign exit'))+'</span></label>'+
        (preset.optional?'<span class="preset-optional">'+pi('Отдельная опция','Optional')+'</span>':'')+
        '<details><summary>'+pi('Домены','Domains')+' · '+size+
        (networks.length?' · '+pi('IP-сети','IP networks')+' · '+networks.length:'')+'</summary>'+
        (suffix?'<p>'+pi('Домены с поддоменами','Domains and their subdomains')+'<code>'+suffix+'</code></p>':'')+
        (exact?'<p>'+pi('Только эти хосты','Exact hosts only')+'<code>'+exact+'</code></p>':'')+
        (cidr?'<p>'+pi('Диапазоны IP-адресов','IP address ranges')+'<code>'+cidr+'</code></p>':'')+
        (examples?'<p>'+pi('Примеры, которые покрывает список','Examples covered by the list')+'<code>'+examples+'</code></p>':'')+
        '</details></article>';
    }).join('');
    updatePresetCount();
  } catch (err) {
    status.textContent = err.message;
  }
}

function filterRoutePresets(query) {
  const term = query.trim().toLowerCase();
  let found = false;
  for (const option of document.querySelectorAll('#route-presets .preset-option')) {
    option.hidden = !option.textContent.toLowerCase().includes(term);
    found = found || !option.hidden;
  }
  document.querySelector('#route-presets .preset-no-results').hidden = found || !term;
}

function choosePresetPack(pack) {
  for (const box of document.querySelectorAll('#route-presets input[name=selected]')) {
    if (box.dataset.pack.split(' ').includes(pack)) box.checked = true;
  }
  updatePresetCount();
}

function updatePresetCount() {
  const form = document.querySelector('#route-presets form');
  const count = form.querySelectorAll('input[name=selected]:checked').length;
  form.querySelector('button[type=submit]').disabled = count === 0;
  form.querySelector('.form-status').textContent = pi('Выбрано групп: ', 'Groups selected: ') + count;
}

async function submitRoutePresets(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button[type=submit]');
  const cancel = form.querySelector('button[data-preset-cancel]');
  const status = form.querySelector('.form-status');
  const dialog = form.closest('dialog');
  const selected = new FormData(form).getAll('selected');
  if (!selected.length || submit.disabled) return;
  submit.disabled = true;
  cancel.disabled = true;
  const lockDialog = event => event.preventDefault();
  dialog.addEventListener('cancel', lockDialog);
  try {
    dDraft();
    const result = await api('POST', '/api/v1/policy/presets', {candidate: DRAFT, selected});
    DRAFT = result.candidate;
    dialog.close();
    renderRoutes();
    document.getElementById('route-presets-button')?.focus();
    const message = document.getElementById('routes-msg');
    message.textContent = (result.added.length
      ? pi('Добавлено в черновик: ', 'Added to the draft: ') + result.added.join(', ') + '. '
      : '') + (result.existing.length
      ? pi('Оставлены ваши существующие правила: ', 'Existing rules preserved: ') + result.existing.join(', ') + '. '
      : '') + pi('Чтобы включить изменения, проверьте черновик и нажмите «Применить».',
        'To activate changes, validate the draft and click Apply.');
  } catch (err) {
    status.textContent = err.message;
  } finally {
    dialog.removeEventListener('cancel', lockDialog);
    cancel.disabled = false;
    submit.disabled = false;
  }
}

async function downloadRoutePolicy() {
  try {
    const active = await api('GET', '/api/v1/policy');
    const url = URL.createObjectURL(new Blob([JSON.stringify(active, null, 2) + '\n'], {type: 'application/json'}));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'ara-policy.json';
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (err) {
    panelError(err);
  }
}

async function openRouteLists(){
  const content=document.createElement('div');
  const hint=document.createElement('p');
  hint.textContent=pi('Новые списки добавляются выключенными. Включите нужное правило в черновике и примените. Обновление GitHub не меняет активные правила.',
    'New lists are added disabled. Enable a rule in the draft and apply it. GitHub refresh leaves active rules intact.');
  const select=document.createElement('select');
  select.setAttribute('aria-label',pi('Список','List'));
  const stamp=document.createElement('p');stamp.className='muted';
  const refresh=document.createElement('button');refresh.type='button';refresh.className='secondary';
  refresh.textContent=pi('Обновить с GitHub','Refresh from GitHub');
  const render=data=>{
    select.replaceChildren();
    for(const list of data.lists){
      const title=document.documentElement.lang==='ru'?list.title:list.title_en;
      const item=new Option(title+' · '+list.count,list.id);
      item.disabled=!list.count;
      select.add(item);
    }
    const first=[...select.options].find(item=>!item.disabled);
    select.value=first?.value||'';
    stamp.textContent=data.lists.some(list=>list.count)?new Date(data.updated_at).toLocaleString():pi('Каталог ещё не скачан.','Catalog not downloaded yet.');
  };
  refresh.onclick=async()=>{
    refresh.disabled=true;
    try{render(await api('POST','/api/v1/policy/lists/refresh',{}))}
    catch(err){stamp.textContent=err.message}
    finally{refresh.disabled=false}
  };
  content.append(hint,select,stamp,refresh);
  try{
    render(await api('GET','/api/v1/policy/lists'));
    const saved=await openAction(pi('Списки правил','Rule lists'),content,pi('В черновик','Add to draft'),async()=>{
      if(!select.value)throw new Error(pi('Сначала обновите каталог.','Refresh the catalog first.'));
      dDraft();
      const result=await api('POST','/api/v1/policy/lists',{id:select.value,candidate:DRAFT});
      DRAFT=result.candidate;
    });
    if(saved){
      renderRoutes();
      document.getElementById('routes-msg').textContent=pi('Черновик обновлён. Новый список выключен.','Draft updated. New lists are disabled.');
    }
  }catch(err){panelError(err)}
}
