async function loadSubscriptionActivity(details, quiet=false) {
  if (!details.open) return;
  const section = details.querySelector('[data-activity]');
  if (!section) return;
  const days = section.querySelector('select').value;
  const plot = section.querySelector('[data-activity-plot]');
  if(!quiet)plot.textContent = pi('Загружаем историю…','Loading history…');
  try {
    const data = await api('GET','/api/v1/subscriptions/activity?id='+encodeURIComponent(details.dataset.subscription)+'&days='+days);
    if (!details.isConnected || section.querySelector('select').value!==days) return;
    for (const row of details.querySelectorAll('[data-seen-device]')) {
      const at = data.last_reported_unix?.[row.dataset.seenDevice];
      row.textContent = at ? pi('Последняя передача · ','Last reported traffic · ')+new Date(at*1000).toLocaleString()
        : pi('Передача ещё не зафиксирована','No traffic reported yet');
    }
    renderSubscriptionActivity(plot,data);
  } catch (err) {
    if (details.isConnected && section.querySelector('select').value===days)
      plot.textContent = pi('История недоступна. Повторите попытку.','History unavailable. Try again.');
  }
}

function renderSubscriptionActivity(plot,data) {
  const points = data.buckets || [];
  if (!points.length) {
    plot.textContent = pi('За этот период нет подтверждённых передач.','No reported transfers for this period.');
    return;
  }
  const time = at => new Date(at*1000).toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
  const amount = bytes => {
    const units = pi('Б КиБ МиБ ГиБ ТиБ','B KiB MiB GiB TiB').split(' ');
    const power = Math.min(4,Math.max(0,Math.floor(Math.log(Math.max(1,bytes))/Math.log(1024))));
    return (bytes/1024**power).toLocaleString([], {maximumFractionDigits:1})+' '+units[power];
  };
  const span = Math.round((data.until_unix-data.from_unix)/data.bucket_seconds);
  const fmt = x => Number(x).toFixed(2);
  const start = time(data.from_unix), end = time(data.until_unix);
  const peak = points.reduce((a,b)=>a.bytes>=b.bytes?a:b);
  const active = Math.max(...points.map(p=>p.devices));
  const width = 720;
  const interval = pi(' за ',' per ')+(data.bucket_seconds/60)+pi(' мин',' min');
  const svg = (field,max,label,klass) => {
    const bars = points.map(p=>{
      const x=(p.at_unix-data.from_unix)/data.bucket_seconds*width/span;
      const h=52*p[field]/max;
      const description = time(p.at_unix)+' · '+(field==='devices'?p.devices:amount(p[field]));
      return '<rect x="'+fmt(x)+'" y="'+fmt(54-h)+'" width="'+fmt(Math.max(1,width/span-0.5))+'" height="'+fmt(h)+'"><title>'+esc(description)+'</title></rect>';
    }).join('');
    return '<div class="activity-lane"><strong>'+label+'</strong><svg class="'+klass+'" role="img" aria-label="'+esc(label)+
      '" viewBox="0 0 720 56" preserveAspectRatio="none"><path d="M0 54H720"></path>'+bars+'</svg></div>';
  };
  const totalRU=points.reduce((n,p)=>n+p.ru_bytes,0);
  const totalForeign=points.reduce((n,p)=>n+p.foreign_bytes,0);
  const unknown=points.reduce((n,p)=>n+p.bytes-p.ru_bytes-p.foreign_bytes,0);
  const ru=pi('Выход RU','RU exit'), foreign=pi('Зарубежный выход','Foreign exit');
  plot.innerHTML='<div class="activity-summary"><span>'+pi('Пик трафика','Traffic peak')+
    ' <strong>'+esc(amount(peak.bytes)+interval)+'</strong> · '+esc(time(peak.at_unix))+'</span><span>'+
    pi('Максимум устройств','Peak devices')+' <strong>'+active+'</strong>'+esc(interval)+'</span></div>'+
    '<div class="activity-summary"><span>'+ru+' <strong>'+esc(amount(totalRU))+'</strong></span><span>'+
    foreign+' <strong>'+esc(amount(totalForeign))+'</strong></span>'+
    (unknown>0?'<span>'+pi('Выход не указан','Exit unspecified')+' <strong>'+esc(amount(unknown))+'</strong></span>':'')+'</div>'+
    svg('ru_bytes',peak.bytes,ru,'activity-ru')+
    svg('foreign_bytes',peak.bytes,foreign,'activity-foreign')+
    svg('devices',active,pi('Устройства с передачей','Devices with traffic'),'activity-devices')+
    '<div class="activity-axis"><span>'+esc(start)+'</span><span>'+esc(end)+'</span></div>';
}

async function editSubscriptionDeviceAccess(button,action) {
  const id = button.dataset.id, device_id = button.dataset.device;
  if (action==='revoke') {
    if (!await confirmAction(pi('Отозвать устройство?','Revoke this device?'),
      pi('Ключ и ссылки устройства перестанут работать во всех подписках этого аккаунта.','This device’s key and links will stop working across this account’s subscriptions.'))) return;
    await api('POST','/api/v1/subscriptions/device-access',{id,device_id,action}).then(loadAll).catch(panelError);
    return;
  }
  if (action==='link') {
    try {
      const result=await api('POST','/api/v1/subscriptions/device-access',{id,device_id,action});
      const content=document.createElement('div');
      fillSubscriptionLink(content,result.url);
      await openAction(pi('Ссылка устройства','Device link'),content,pi('Готово','Done'));
    } catch(err) { panelError(err); }
    return;
  }
  const content=document.createElement('div');
  const label=document.createElement('label');
  label.textContent=pi('Срок доступа · местное время','Access expiry · local time');
  const input=document.createElement('input');
  input.type='datetime-local';
  input.name='expiry';
  const expiry=Number(button.dataset.expiry);
  if(expiry){
    const date=new Date(expiry*1000);
    input.value=new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,16);
  }
  label.append(input);
  const hint=document.createElement('p');
  hint.className='muted';
  hint.textContent=pi('Пустое поле — без срока. Изменение действует во всех подписках аккаунта.','Leave blank for no expiry. Applies across this account’s subscriptions.');
  content.append(label,hint);
  const saved=await openAction(pi('Срок доступа устройства','Device access expiry'),content,pi('Сохранить','Save'),
    values=>api('POST','/api/v1/subscriptions/device-access',{id,device_id,action,expires_unix:values.expiry?Math.floor(new Date(values.expiry).getTime()/1000):0}));
  if(saved)await loadAll().catch(panelError);
}

async function checkNodeConnection(button) {
  const content=document.createElement('div');
  const message=document.createElement('p');
  message.textContent=pi('Проверяем…','Checking…');
  content.append(message);
  const report=openAction(pi('Проверка подключения','Connection check')+' · '+button.dataset.id,
    content,pi('Готово','Done'));
  try {
    const result=await api('GET','/api/v1/nodes/check?id='+encodeURIComponent(button.dataset.id));
    message.textContent=pi('DNS, TCP и TLS проверены с панели. Проверка выхода — последнее наблюдение Edge.',
      'DNS, TCP and TLS are tested from this panel. Exit check is the latest Edge observation.');
    const labels={dns:'DNS',tcp:'TCP',tls:'TLS',exit_canary:pi('Выход в интернет','Internet exit')};
    const statuses={ok:pi('Работает','Working'),failed:pi('Ошибка','Failed'),skipped:pi('Нет проверки','Not checked')};
    const reasons={no_ingress:pi('Нет клиентского входа','No client ingress'),ip_literal:pi('Задан IP','IP address configured'),
      resolve_failed:pi('Имя не разрешилось','Name did not resolve'),invalid_endpoint:pi('Некорректный адрес','Invalid address'),
      non_public_address:pi('Адрес непубличный','Address is not public'),connect_failed:pi('Порт недоступен','Port is unreachable'),
      handshake_failed:pi('TLS или сертификат не прошёл проверку','TLS or certificate validation failed'),
      no_exit_observation:pi('Нет свежего отчёта Edge','No recent Edge report'),exit_unhealthy:pi('Последняя проба выхода не прошла','Latest exit probe failed')};
    const list=document.createElement('ul');
    for(const step of result.steps){
      const item=document.createElement('li');
      item.textContent=labels[step.name]+' · '+statuses[step.status]+(step.reason?' · '+(reasons[step.reason]||step.reason):'')+
        (step.duration_ms?' · '+step.duration_ms+' '+pi('мс','ms'):'');
      list.append(item);
    }
    content.append(list);
  }catch(err){message.textContent=pi('Проверка недоступна.','Check unavailable.')}
  await report;
}

function previewSubscriptionEndpoint(form){
  const origin=form.elements.origin.value.trim().replace(/\/$/,'');
  const name=form.elements.name.value.trim();
  form.querySelector('output').textContent=origin&&name?origin+'/'+name+'/'+pi('<ключ>','<key>'):pi('Заполните домен и имя сервиса','Enter the domain and service name');
}

let subscriptionEndpointLoaded=false;
async function loadSubscriptionEndpoint(){
  if(subscriptionEndpointLoaded)return;
  const endpoint=await api('GET','/api/v1/subscriptions/endpoint');
  const form=document.getElementById('subscription-endpoint-form');
  form.elements.origin.value=endpoint.origin;
  form.elements.name.value=endpoint.name;
  previewSubscriptionEndpoint(form);
  subscriptionEndpointLoaded=true;
}

async function saveSubscriptionEndpoint(event){
  event.preventDefault();
  const form=event.currentTarget, status=form.querySelector('.form-status'), button=event.submitter;
  button.disabled=true;
  try{
    const endpoint=await api('POST','/api/v1/subscriptions/endpoint',Object.fromEntries(new FormData(form)));
    form.elements.origin.value=endpoint.origin;
    form.elements.name.value=endpoint.name;
    previewSubscriptionEndpoint(form);
    status.textContent=pi('Сохранено','Saved');
    clearSubscriptionLinks();
  }catch(err){status.textContent=pi('Проверьте HTTPS-адрес и имя сервиса.','Check the HTTPS address and service name.')}
  finally{button.disabled=false}
}

function clearSubscriptionLinks(){
  sessionSubscriptionLinks.clear();
}
function fillSubscriptionLink(target,url,settings={}){
  target.replaceChildren();
  if(!url)return;
  const box=document.createElement('div');box.className='settings-empty subscription-share';
  const options=document.createElement('select');
  options.setAttribute('aria-label',pi('Формат подключения','Connection format'));
  const formats=[['mobile',pi('VLESS · мобильные клиенты','VLESS · mobile clients')]];
  if(LOCAL_TROJAN)formats.push(['trojan',pi('Trojan · мобильные клиенты','Trojan · mobile clients')]);
  formats.push(['ara',pi('Клиент ARA','ARA client')]);
  for(const [value,label] of formats)options.add(new Option(label,value));
  const current=()=>{
    const link=new URL(url);
    if(options.value!=='ara')link.searchParams.set('format','links');
    if(options.value==='trojan')link.searchParams.set('protocol','trojan');
    return link.href;
  };
  options.value=formats.some(([value])=>value===settings.format)?settings.format:'mobile';
  const input=document.createElement('input');
  input.type='url';input.readOnly=true;input.value=current();
  input.setAttribute('aria-label',pi('Ссылка подписки','Subscription link'));
  const actions=document.createElement('div');actions.className='subscription-share-actions';
  const button=(label,handler)=>{
    const el=document.createElement('button');el.type='button';el.className='secondary';
    el.textContent=label;el.onclick=handler;return el;
  };
  const copy=button(pi('Скопировать ссылку','Copy link'),async()=>{
    try{await navigator.clipboard.writeText(current());copy.textContent=pi('Скопировано','Copied')}
    catch(err){panelError(err)}
  });
  const qrSlot=document.createElement('div');
  const qr=button(pi('Показать QR','Show QR'),async()=>{
    if(qrSlot.firstChild){qrSlot.replaceChildren();return}
    const requested=current();
    try{
      const result=await api('POST','/api/v1/subscriptions/qr',{url:requested});
      if(!box.isConnected||current()!==requested)return;
      const img=document.createElement('img');img.alt=pi('QR подключения','Connection QR');
      img.src='data:image/png;base64,'+result.png;qrSlot.replaceChildren(img);
    }catch(err){if(box.isConnected)panelError(err)}
  });
  options.onchange=()=>{input.value=current();qrSlot.replaceChildren();copy.textContent=pi('Скопировать ссылку','Copy link');if(settings.showQR)void qr.onclick()};
  actions.append(options,copy);
  if(!settings.showQR)actions.append(qr);
  box.append(actions,input,qrSlot);target.append(box);
  if(settings.showQR)void qr.onclick();
}
