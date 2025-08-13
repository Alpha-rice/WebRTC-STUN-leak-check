/* WebRTC IP Leak Tester 2025-08
   - フィルタロジックを「行の表示／非表示方式」に一新
   - 進捗バー・JSONコピー・mDNS分類を追加
   - 出典: RFC 8445 / Chromium mDNS Design Doc ほか */
(() => {
  /* ==== 要素取得 ==== */
  const $ = s => document.querySelector(s);
  const stunInput = $('#stunUrl');
  const startBtn  = $('#startBtn');
  const stopBtn   = $('#stopBtn');
  const copyBtn   = $('#copyBtn');
  const statusEl  = $('#status');
  const progress  = $('#progress');
  const progBar   = progress.querySelector('span');
  const tableBody = $('#resultTable tbody');
  const cardList  = $('#cardList');
  const filterChecks = document.querySelectorAll('[data-filter]');

  /* ==== 状態 ==== */
  let pc        = null;
  let dc        = null;
  let candidates= [];      // 収集済み {type, subtype(host/mdns/...), ...}
  let timer     = null;

  /* ==== ユーティリティ ==== */
  const esc = s => String(s).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]));
  const setStatus = m => statusEl.textContent = m;

  /* ---- 候補の描画 ---- */
  function drawCandidate(c){
    // テーブル行
    const tr = document.createElement('tr');
    tr.dataset.type = c.subtype;
    tr.innerHTML = `<td><span class="badge ${c.subtype}">${c.subtype}</span></td>
      <td>${esc(c.address)}</td><td>${esc(c.port)}</td>
      <td>${esc(c.proto)}</td><td>${esc(c.prio)}</td>
      <td>${c.raddr?esc(`${c.raddr}:${c.rport}`):'-'}</td>`;
    tableBody.appendChild(tr);

    // カード
    const li = document.createElement('li');
    li.className = 'card';
    li.dataset.type = c.subtype;
    li.innerHTML = `
      <div class="row"><strong><span class="badge ${c.subtype}">${c.subtype}</span></strong><span>${esc(c.proto)}</span></div>
      <div class="row"><span class="key">IP/mDNS</span><span>${esc(c.address)}</span></div>
      <div class="row"><span class="key">Port</span><span>${esc(c.port)}</span></div>
      <div class="row"><span class="key">Prio</span><span>${esc(c.prio)}</span></div>
      <div class="row"><span class="key">Related</span><span>${c.raddr?esc(`${c.raddr}:${c.rport}`):'-'}</span></div>`;
    cardList.appendChild(li);
  }

  /* ---- フィルタ適用 ---- */
  function applyFilter(){
    const show = {};
    filterChecks.forEach(cb => show[cb.dataset.filter] = cb.checked);

    document.querySelectorAll('[data-type]').forEach(el=>{
      el.hidden = !show[el.dataset.type];
    });
  }
  filterChecks.forEach(cb=>cb.addEventListener('change', applyFilter));

  /* ---- candidate 文字列パース ---- */
  function parse(line){
    const p = line.trim().split(/\s+/);
    if(!p[0].startsWith('candidate:')) return null;
    const c = {
      proto : (p[2]||'').toUpperCase(),
      prio  : p[3],
      address:p[4],
      port  : p[5],
      type  : '', raddr:'', rport:'',
      subtype:'', raw:line
    };
    for(let i=6;i<p.length;i++){
      if(p[i]==='typ')   c.type  = p[++i];
      if(p[i]==='raddr') c.raddr = p[++i];
      if(p[i]==='rport') c.rport = p[++i];
    }
    // mDNS 判定
    const mdns = /\.local\.?$/i.test(c.address);
    c.subtype = mdns ? 'mdns' : c.type;
    return c;
  }

  /* ---- 収集開始 ---- */
  async function start(){
    // リセット
    tableBody.innerHTML = ''; cardList.innerHTML = '';
    candidates.length = 0;
    setStatus('ICE 収集中…'); progBar.style.width='0'; progress.hidden=false;
    startBtn.disabled=true; stopBtn.disabled=false; copyBtn.disabled=true;
    document.activeElement.blur();

    pc = new RTCPeerConnection({iceServers:[{urls:stunInput.value.trim()}]});
    dc = pc.createDataChannel('chk');

    pc.onicecandidate = e=>{
      if(e.candidate){
        const c = parse(e.candidate.candidate);
        if(c && !candidates.some(x=>x.raw===c.raw)){
          candidates.push(c);
          drawCandidate(c); applyFilter();
        }
      }else{
        finish('完了');
      }
    };
    pc.onicegatheringstatechange = ()=> {
      const st = pc.iceGatheringState;
      if(st==='gathering') progBar.style.width='50%';
      else if(st==='complete') progBar.style.width='100%';
    };

    try{
      await pc.setLocalDescription(await pc.createOffer());
    }catch(err){
      finish('エラー: '+err.message);
    }

    // タイムアウト（15秒）
    timer = setTimeout(()=>finish('タイムアウト (15秒)'),15000);
  }

  /* ---- 終了処理 ---- */
  function finish(msg){
    clearTimeout(timer);
    try{pc&&pc.close()}catch{}
    pc=null; dc=null;
    setStatus(msg);
    progress.hidden=true;
    document.getElementById('doneMsg').hidden=false;
    startBtn.disabled=false; stopBtn.disabled=true;
    copyBtn.disabled = !candidates.length;
  }

  /* ---- 停止 ---- */
  function stop(){
    finish('手動停止');
  }

  /* ---- JSON コピー ---- */
  function copyJSON(){
    navigator.clipboard.writeText(JSON.stringify(candidates,null,2))
      .then(()=>setStatus('クリップボードにコピーしました'))
      .catch(()=>setStatus('コピーに失敗しました'));
  }

  /* ==== イベント ==== */
  startBtn.addEventListener('click', start);
  stopBtn .addEventListener('click', stop);
  copyBtn.addEventListener('click', copyJSON);
})();
