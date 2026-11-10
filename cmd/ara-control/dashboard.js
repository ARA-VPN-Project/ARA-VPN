(() => {
  const byID = id => document.getElementById('ov-' + id);
  const targetSelect = byID('target');
  const refresh = byID('refresh');
  const period = byID('period');
  const hour = 3600000;
  const spans = {'1h': hour, '24h': 24*hour, '7d': 168*hour, '30d': 720*hour, '1y': 8760*hour};
  const calendar = new Intl.DateTimeFormat(document.documentElement.lang, {month: 'short', day: 'numeric'});
  let chartHistory;
  let loadedPeriod;
  const number = new Intl.NumberFormat(document.documentElement.lang, {maximumFractionDigits: 2});
  const clock = new Intl.DateTimeFormat(document.documentElement.lang, {hour: '2-digit', minute: '2-digit'});
  let observations;
  let pending = false;

  const fmt = value => Number.isFinite(value) ? number.format(value) : '—';
  const stateLabel = state => ({
    healthy: pi('Доступен', 'Reachable'),
    suspect: pi('Нестабильно', 'Unstable'),
    recovering: pi('Восстанавливается', 'Recovering'),
    degraded: pi('Ухудшение', 'Degraded'),
    quarantined: pi('Карантин', 'Quarantined'),
    down: pi('Недоступен', 'Unreachable'),
    stale: pi('Устарело', 'Stale'),
  })[state] || pi('Нет наблюдений', 'No observation');

  function empty(title, hint) {
    return '<div class="plot-area plot-empty"><strong>' + title + '</strong><span>' + hint + '</span></div>';
  }

  function graph(series, unit, start, end, interval) {
    const width = 600, height = 150;
    const max = Math.max(1, ...series.flatMap(line => line.points.map(point => point.value).filter(Number.isFinite)));
    const x = at => 6 + (at - start) / (end - start) * (width - 12);
    const y = value => height - 9 - value / max * (height - 18);
    const grids = [0, 0.5, 1].map(t =>
      '<path class="plot-grid" d="M0 ' + y(max * t) + ' H' + width + '" vector-effect="non-scaling-stroke"/>').join('');
    const lines = series.map(line => {
      let previous = -Infinity;
      let path = '';
      let marks = '';
      let lastMark = '';
      for (const point of line.points) {
        if (!Number.isFinite(point.value)) {
          previous = -Infinity;
          continue;
        }
        const px = x(point.at).toFixed(2);
        const py = y(point.value).toFixed(2);
        const segmentStart = point.at - previous > interval * 2.25;
        path += (segmentStart ? 'M' : 'L') + px + ' ' + py + ' ';
        lastMark = '<circle class="' + line.style + '" cx="' + px + '" cy="' + py + '" r="2.3"/>';
        if (segmentStart) marks += lastMark;
        previous = point.at;
      }
      return '<path class="' + line.style + '" d="' + path + '" stroke-width="2" vector-effect="non-scaling-stroke"/>' + marks + lastMark;
    }).join('');
    return '<div class="plot-area"><svg role="img" aria-label="' + pi('История за выбранный период', 'History over the selected period') +
      '" viewBox="0 0 ' + width + ' ' + height + '" preserveAspectRatio="none">' + grids + lines + '</svg>' +
      '<span class="plot-scale">' + fmt(max) + ' ' + unit + '</span></div><div class="plot-times">' +
      [start, (start + end) / 2, end].map(at => '<span>' + (period.value==='1h'?clock:calendar).format(at) + '</span>').join('') + '</div>';
  }

  function row(sample, history, now, interval) {
    const stale = now - sample.time > 3 * interval;
    const state = stale ? 'stale' : sample.state;
    const tone = state === 'healthy' ? 'ok' : ['down', 'quarantined'].includes(state) ? 'bad' : 'warn';
    const strip = history.slice(-12).map(s => {
      const tone = s.state === 'healthy' ? 'ok' : ['down', 'quarantined'].includes(s.state) ? 'bad' : 'warn';
      return '<i class="' + tone + '" title="' + clock.format(s.time) + ' · ' + stateLabel(s.state) + '"></i>';
    }).join('');
    const summary = history.slice(-12).map(s => clock.format(s.time) + ' ' + stateLabel(s.state)).join(', ');
    return '<div class="monitor-node"><strong>' + esc(sample.target) + '</strong>' +
      '<span class="monitor-strip" role="img" aria-label="' + esc(summary) + '">' + strip + '</span>' +
      '<span class="muted">' + (Number.isFinite(sample.rtt_ms) ? fmt(sample.rtt_ms) + ' ms · ' : '') +
      clock.format(sample.time) + '</span><span class="pill ' + tone + '">' + stateLabel(state) + '</span></div>';
  }

  function render() {
    const now = Date.now();
    const start = now - spans[period.value];
    const interval = (observations.interval_seconds || 30) * 1000;
    const chartInterval = (chartHistory.interval_seconds || 30) * 1000;
    const normalize = samples => (samples || []).map(s => ({...s, time: Date.parse(s.at)}))
      .filter(s => s.time <= now && ['edge_exit_probe', 'edge_payload', 'panel_tcp'].includes(s.source))
      .sort((a, b) => a.time - b.time);
    const records = normalize(observations.samples).filter(s => s.time >= now - hour);
    const chart = normalize(chartHistory.samples).filter(s => s.time >= start);
    const traffic = chart.filter(s => s.kind === 'traffic' && s.source === 'edge_payload');
    const probes = records.filter(s => s.kind !== 'traffic');
    const latest = new Map(probes.map(s => [s.kind + ':' + s.target, s]));
    const nodes = Array.from(latest.values()).filter(s => s.kind === 'node');
    const external = ['Cloudflare', 'Facebook', 'Yandex'].map(name => latest.get('target:'+name)).filter(Boolean);
    const freshNodes = nodes.filter(s => now - s.time <= 3 * interval);
    const reachable = freshNodes.filter(s => s.state === 'healthy').length;
    byID('summary').innerHTML =
      '<span class="pill ok">' + pi('Панель доступна', 'Control Center reachable') + '</span>' +
      '<b>' + (freshNodes.length ? reachable + ' / ' + freshNodes.length + ' ' + pi('наблюдаемых выходов доступны', 'observed exits reachable')
        : pi('Нет свежих наблюдений выходов', 'No fresh exit observations')) + '</b>' +
      (records.length ? '<span class="muted">' + pi('Последняя точка · ', 'Latest sample · ') + clock.format(records.at(-1).time) + '</span>' : '');

    if (traffic.length) {
      const last = traffic.at(-1);
      byID('traffic').innerHTML = '<div class="plot-legend"><span><i class="legend-swatch"></i>' +
        pi('Загрузка', 'Download') + ' <b>' + fmt(last.down_mbps) + '</b> Mbit/s</span><span><i class="legend-swatch upload"></i>' +
        pi('Отдача', 'Upload') + ' <b>' + fmt(last.up_mbps) + '</b> Mbit/s</span></div>' +
        graph([{style: 'plot-primary', points: traffic.map(s => ({at: s.time, value: s.down_mbps}))},
          {style: 'plot-upload', points: traffic.map(s => ({at: s.time, value: s.up_mbps}))}], 'Mbit/s', start, now, chartInterval) +
        '<p class="monitor-note">' + pi('Среднее за интервал сбора · последняя точка ', 'Mean over collection interval · latest sample ') + clock.format(last.time) + '</p>';
    } else {
      byID('traffic').innerHTML = empty(pi('Нет данных за этот период', 'No data for this period'),
        observations.edge_enabled ? pi('Нужны два свежих снимка счётчиков Edge.', 'Waiting for two fresh Edge counter snapshots.')
          : pi('Подключите файл статуса Edge в настройках запуска панели.', 'Connect the Edge status file in Control Center startup settings.'));
    }

    const selection = targetSelect.value;
    const keys = [...latest.keys()];
    if (keys.join('\n') !== Array.from(targetSelect.options, option => option.value).join('\n')) {
      targetSelect.replaceChildren();
      for (const [key, value] of latest) targetSelect.add(new Option(value.target, key));
      if (latest.has(selection)) targetSelect.value = selection;
    }
    targetSelect.hidden = !latest.size;
    const selected = latest.get(targetSelect.value);
    const latency = chart.filter(s => s.kind + ':' + s.target === targetSelect.value);
    const successful = latency.filter(s => Number.isFinite(s.rtt_ms));
    if (successful.length) {
      const ordered = successful.map(s => s.rtt_ms).sort((a, b) => a - b);
      const percentile = p => fmt(ordered[Math.ceil(p * ordered.length) - 1]);
      const percentiles = period.value==='1h' && ordered.length >= 20 ? '<span>p50 <b>' + percentile(.5) + '</b> · p95 <b>' +
        percentile(.95) + '</b> ms</span>' : '';
      byID('latency').innerHTML = '<div class="plot-legend"><span><i class="legend-swatch"></i>' +
        (period.value==='1h'?pi('Последний замер', 'Latest measurement'):pi('Среднее в последнем интервале','Mean in last interval')) + ' <b>' + fmt(successful.at(-1).rtt_ms) + ' ms</b></span>' + percentiles + '</div>' +
        graph([{style: 'plot-primary', points: latency.map(s => ({at: s.time, value: s.rtt_ms}))}], 'ms', start, now, chartInterval) +
        '<p class="monitor-note">' + (selected?.kind === 'node'
          ? pi('Тестовый HTTP-обмен через выход от Edge', 'HTTP canary through the exit from Edge')
          : pi('Время установки TCP-соединения от панели', 'TCP connect time from Control Center')) + '</p>';
    } else {
      byID('latency').innerHTML = empty(pi('Нет успешных замеров', 'No successful measurements'),
        pi('Точки появятся после успешных проверок.', 'Points appear after successful probes.'));
    }
    byID('nodes').innerHTML = nodes.length ? nodes.map(s => row(s, probes.filter(p => p.kind === 'node' && p.target === s.target), now, interval)).join('') :
      '<p class="muted">' + pi('Пока нет данных от Edge.', 'Waiting for observations from Edge.') + '</p>';
    byID('external').innerHTML = external.length ? external.map(target => row(target, probes.filter(s => s.kind === 'target' && s.target === target.target), now, interval)).join('') :
      '<p class="muted">' + (observations.cloudflare_enabled
        ? pi('Ожидаем первую проверку.', 'Waiting for the first probe.')
        : pi('Проверка выключена. Включение: --monitor-cloudflare.', 'Probe is off. Enable with --monitor-cloudflare.')) + '</p>';
  }

  async function load() {
    if (pending) return;
    const requestedPeriod = period.value;
    pending = true;
    refresh.disabled = true;
    try {
      const choice = period.value;
      const raw = api('GET', '/api/v1/monitoring/history?n=2000');
      [observations, chartHistory] = await Promise.all([raw, choice==='1h' ? raw : api('GET', '/api/v1/monitoring/history?period='+choice)]);
      loadedPeriod = choice;
      if (choice===period.value) render();
    } catch {
      byID('summary').textContent = pi('История мониторинга недоступна. Повторите обновление.', 'Monitoring history unavailable. Try refreshing.');
      if (!observations) {
        byID('traffic').innerHTML = byID('latency').innerHTML = empty(pi('Данные недоступны', 'Data unavailable'), '');
      }
    } finally {
      pending = false;
      refresh.disabled = false;
      if (loadedPeriod && loadedPeriod !== period.value && !document.hidden && requestedPeriod !== period.value) load();
    }
  }

  refresh.addEventListener('click', load);
  targetSelect.addEventListener('change', () => { if (loadedPeriod===period.value) render(); });
  period.addEventListener('change', load);
  load();
  setInterval(() => {
    if (!document.hidden && !document.getElementById('sec-overview').hidden) load();
  }, 15000);
})();
