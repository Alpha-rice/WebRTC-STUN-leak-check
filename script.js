/*
  WebRTC IP Leak Tester (Improved)
  - mDNS 表示対応、候補型フィルタ、コピー、停止、カード表示、強化パーサ
  - 仕様参考: mDNSに関するChromeの告知/フラグ[1][2][5]、ICE候補の形式[7][13][19]
*/
(() => {
  const $ = sel => document.querySelector(sel);
  const startBtn   = $('#startButton');
  const stopBtn    = $('#stopButton');
  const copyBtn    = $('#copyButton');
  const stunInput  = $('#stunUrl');
  const statusEl   = $('#status');
  const tableBody  = $('#resultTable tbody');
  const cardList   = $('#cardList');
  const completeEl = $('#completeMessage');

  const filterHost = $('#filterHost');
  const filterSrflx= $('#filterSrflx');
  const filterRelay= $('#filterRelay');

  let pc = null;
  let dc = null;
  let allCandidates = [];
  let gatheringComplete = false;

  // 簡易URLバリデーション（stun: のみ許可）
  function validateStunUrl(url){
    try{
      if(!/^stun:/.test(url)) return false;
      // 形式の厳格性は実装側に依存するため最低限とする[10]
      return true;
    }catch{ return false; }
  }

  function setStatus(msg){ statusEl.textContent = msg; }
  function resetUI(){
    tableBody.innerHTML = '';
    cardList.innerHTML  = '';
    allCandidates = [];
    gatheringComplete = false;
    completeEl.hidden = true;
    copyBtn.disabled = true;
  }

  function toggleRunning(running){
    startBtn.disabled = running;
    stopBtn.disabled  = running;
    copyBtn.disabled  = !(!running && allCandidates.length);
    stopBtn.disabled  = !running;
  }

  // candidate文字列のRFCベースの簡易パース[7][13][19]
  function parseCandidate(line){
    // 例: candidate:842163049 1 udp 1677729535 192.168.0.2 60769 typ host
    const parts = line.trim().split(/\s+/);
    if(!parts[0].startsWith('candidate:')) return null;
    // ABNF順序: foundation component transport priority address port typ type [raddr addr] [rport port] ...
    const obj = {
      foundation: parts[0].split(':')[1] || '',
      component:  parts[1] || '',
      protocol:   (parts[2]||'').toUpperCase(),
      priority:   parts[3] || '',
      address:    parts[4] || '',
      port:       parts[5] || '',
      type:       '',
      raddr:      '',
      rport:      '',
      raw:        line
    };
    for(let i=6;i<parts.length;i++){
      if(parts[i]==='typ' && parts[i+1]) obj.type = parts[i+1];
      if(parts[i]==='raddr' && parts[i+1]) obj.raddr = parts[i+1];
      if(parts[i]==='rport' && parts[i+1]) obj.rport = parts[i+1];
    }
    // mDNS検出（ローカルIP匿名化時は .local やmdns様式になることがある）[1][2][5]
    obj.isMdns = /\.local\.?$/i.test(obj.address) || /^[a-f0-9-]{6,}\.local$/i.test(obj.address);
    return obj;
  }

  function matchFilter(type){
    if(type==='host' && !filterHost.checked) return false;
    if(type==='srflx'&& !filterSrflx.checked) return false;
    if(type==='relay'&& !filterRelay.checked) return false;
    return true;
  }

  function addRow(c){
    if(!matchFilter(c.type)) return;

    const tr = document.createElement('tr');
    const badgeClass = c.isMdns ? 'mdns' : c.type;
    tr.innerHTML = `
      <td><span class="badge ${badgeClass}">${c.isMdns ? 'host(mDNS)' : c.type}</span></td>
      <td>${escapeHtml(c.address)}</td>
      <td>${escapeHtml(c.port)}</td>
      <td>${escapeHtml(c.protocol)}</td>
      <td>${escapeHtml(c.priority)}</td>
      <td>${c.raddr ? `${escapeHtml(c.raddr)}:${escapeHtml(c.rport)}` : '-'}</td>
    `;
    tableBody.appendChild(tr);

    const li = document.createElement('li');
    li.className = 'card';
    li.innerHTML = `
      <div class="row"><div><span class="badge ${badgeClass}">${c.isMdns ? 'host(mDNS)' : c.type}</span></div><div class="key">${escapeHtml(c.protocol)}</div></div>
      <div class="row"><div class="key">IP/mDNS</div><div>${escapeHtml(c.address)}</div></div>
      <div class="row"><div class="key">Port</div><div>${escapeHtml(c.port)}</div></div>
      <div class="row"><div class="key">Priority</div><div>${escapeHtml(c.priority)}</div></div>
      <div class="row"><div class="key">Related</div><div>${c.raddr ? `${escapeHtml(c.raddr)}:${escapeHtml(c.rport)}` : '-'}</div></div>
    `;
    cardList.appendChild(li);
  }

  function escapeHtml(s){
    return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
  }

  function renderAll(){
    tableBody.innerHTML = '';
    cardList.innerHTML  = '';
    for(const c of allCandidates) addRow(c);
    copyBtn.disabled = allCandidates.length===0;
  }

  async function start(){
    resetUI();

    const url = stunInput.value.trim();
    if(!validateStunUrl(url)){
      setStatus('STUN URL が不正です。例: stun:stun.l.google.com:19302');
      return;
    }

    setStatus('ICE 収集中...');
    toggleRunning(true);

    try{
      pc = new RTCPeerConnection({ iceServers: [{ urls: url }] });
      // 一部ブラウザではトラック/データチャネルが必要
      dc = pc.createDataChannel('probe');

      pc.onicecandidate = e => {
        if(e.candidate){
          const parsed = parseCandidate(e.candidate.candidate);
          if(parsed){
            // 重複除去
            const key = `${parsed.type}|${parsed.address}|${parsed.port}|${parsed.protocol}`;
            if(!allCandidates.some(x => `${x.type}|${x.address}|${x.port}|${x.protocol}` === key)){
              allCandidates.push(parsed);
              addRow(parsed);
            }
          }
        }else{
          // 完了
          gatheringComplete = true;
          completeEl.hidden = false;
          setStatus('完了（必要に応じてフィルタで絞り込み可）');
          toggleRunning(false);
          pc && pc.close();
          pc = null;
        }
      };

      pc.onicegatheringstatechange = () => {
        setStatus(`ICE 状態: ${pc.iceGatheringState}`);
      };

      const offer = await pc.createOffer({offerToReceiveAudio:false, offerToReceiveVideo:false});
      await pc.setLocalDescription(offer);

      // 念のためのタイムアウト（15秒で終了扱い）
      setTimeout(() => {
        if(pc && pc.iceGatheringState !== 'complete'){
          setStatus('タイムアウト: ネットワークやSTUNの応答を確認してください。');
          completeEl.hidden = false;
          toggleRunning(false);
          pc.close();
          pc = null;
        }
      }, 15000);

    }catch(err){
      setStatus(`エラー: ${err && err.message ? err.message : err}`);
      toggleRunning(false);
      try{ pc && pc.close(); }catch{}
      pc = null;

      // ブラウザ別のヒント（mDNSや権限関連）[1][2][5][11]
      console.warn('Hint: mDNS/権限/ネットワーク設定を確認してください。ChromeはローカルIP匿名化が既定です。');
    }
  }

  function stop(){
    if(pc){
      try{ pc.close(); }catch{}
      pc = null;
    }
    setStatus('停止しました。');
    toggleRunning(false);
  }

  function copyResults(){
    const lines = allCandidates.map(c => {
      const t = c.isMdns ? 'host(mDNS)' : c.type;
      const rel = c.raddr ? ` raddr ${c.raddr} rport ${c.rport}` : '';
      return `typ ${t} ${c.address}:${c.port} ${c.protocol} prio ${c.priority}${rel}`;
    }).join('\n');
    navigator.clipboard.writeText(lines).then(()=>{
      setStatus('クリップボードにコピーしました。');
    },()=>{
      setStatus('コピーに失敗しました。');
    });
  }

  // イベント
  startBtn.addEventListener('click', start);
  stopBtn.addEventListener('click', stop);
  copyBtn.addEventListener('click', copyResults);

  for(const el of [filterHost, filterSrflx, filterRelay]){
    el.addEventListener('change', renderAll);
  }

  // キーボード操作
  document.addEventListener('keydown', e => {
    if(e.key==='Enter' && !startBtn.disabled) start();
    if(e.key==='Escape' && !stopBtn.disabled) stop();
  });
})();
