'use strict';
// Rustorrent web UI. Everything renders client-side from the /events JSON stream.
const $=id=>document.getElementById(id);
const store={
  get(k,d=''){try{const v=localStorage.getItem('rustorrent-'+k);return v==null?d:v}catch(e){return d}},
  set(k,v){try{v==null?localStorage.removeItem('rustorrent-'+k):localStorage.setItem('rustorrent-'+k,v)}catch(e){}}
};
const ICONS={
  plus:'M12 5v14M5 12h14',down:'M12 5v14m-5.5-5.5L12 19l5.5-5.5',up:'M12 19V5M6.5 10.5 12 5l5.5 5.5',
  pause:'M9 6.5v11M15 6.5v11',play:'M8 5.5v13L19 12z',
  folder:'M3.5 6.5a1 1 0 0 1 1-1h5l2 2h8a1 1 0 0 1 1 1v9.5a1 1 0 0 1-1 1h-15a1 1 0 0 1-1-1z',
  trash:'M4.5 7h15M10 4h4M6.5 7l.8 11.2a1.5 1.5 0 0 0 1.5 1.3h6.4a1.5 1.5 0 0 0 1.5-1.3L17.5 7M10 11v5M14 11v5',
  chev:'m9.5 6.5 5.5 5.5-5.5 5.5',list:'M9 6.5h11M9 12h11M9 17.5h11M4.5 6.5h.01M4.5 12h.01M4.5 17.5h.01',
  dl:'M12 4v10.5m-4.5-4.5 4.5 4.5 4.5-4.5M5 19.5h14',
  alert:'M10.3 4.3 2.9 17.5A2 2 0 0 0 4.6 20.5h14.8a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0zM12 9.5v4M12 17h.01',
  tag:'M3.5 12V5a1.5 1.5 0 0 1 1.5-1.5h7l8.5 8.5-8.5 8.5zM8.2 8.2h.01',
  search:'M10.5 17a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13zM20 20l-4.8-4.8',
  rss:'M5.5 18.5h.01M5 11.5a7.5 7.5 0 0 1 7.5 7.5M5 5a14 14 0 0 1 14 14',
  sliders:'M4 7.5h9M17 7.5h3M15 5v5M4 16.5h3M11 16.5h9M9 14v5',
  sun:'M12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM12 3v2M12 19v2M5.6 5.6 7 7M17 17l1.4 1.4M3 12h2M19 12h2M5.6 18.4 7 17M17 7l1.4-1.4',
  moon:'M19.5 14.6A7.5 7.5 0 0 1 9.4 4.5a7.8 7.8 0 1 0 10.1 10.1z',
  x:'M6.5 6.5l11 11M17.5 6.5l-11 11',recheck:'M19.5 12a7.5 7.5 0 1 1-2.2-5.3M19.5 4.5v4h-4',
  stop:'M7 7h10v10H7z',
  archive:'M4.5 9h15v9.5a1 1 0 0 1-1 1h-13a1 1 0 0 1-1-1zM3.5 4.5h17V9h-17zM10 12.5h4',
  file:'M13.5 3.5H7A1.5 1.5 0 0 0 5.5 5v14A1.5 1.5 0 0 0 7 20.5h10a1.5 1.5 0 0 0 1.5-1.5V8.5zM13.5 3.5v5h5M12 17.5v-6m-2.5 2.5L12 11.5l2.5 2.5',
  pen:'M4.5 19.5h4l10-10a2 2 0 0 0-4-4l-10 10zM13.5 6.5l4 4',ok:'m5.5 12.5 4 4 9-9'
};
const ic=n=>`<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="${ICONS[n]}"/></svg>`;
const tpl=document.createElement('template');
function icon(n){tpl.innerHTML=ic(n);return tpl.content.firstChild}
// h('div.a.b',{attr:value,text:'…'},...children); the attribute object is optional.
function h(sel,...kids){
  const [tag,...cls]=sel.split('.'),e=document.createElement(tag),a=kids[0];
  if(cls.length)e.className=cls.join(' ');
  if(a&&a.constructor===Object){kids.shift();for(const k in a){const v=a[k];if(v==null||v===false)continue;if(k==='text')e.textContent=v;else e.setAttribute(k,v===true?'':v)}}
  e.append(...kids.flat().filter(c=>c!=null&&c!==false));
  return e;
}
function txt(e,v){v=v==null?'':String(v);if(e.textContent!==v)e.textContent=v}
function attr(e,k,v){if(v==null||v===false)e.removeAttribute(k);else if(e.getAttribute(k)!==(v=v===true?'':String(v)))e.setAttribute(k,v)}
const ibtn=(n,label,a,cls='',data={})=>h('button.ib'+cls,{'aria-label':label,title:label,'data-a':a,...data},icon(n));
const btn=(label,n,a,cls='')=>h('button.btn.sm'+cls,{'data-a':a},icon(n),label);
const li=(...kids)=>h('div.li',...kids);
const empty=text=>[h('p.muted',{text})];

/* formatting */
function bytes(v){v=Math.max(0,+v||0);let i=0;while(v>=1024&&i<4){v/=1024;i++}return (i?v.toFixed(v<10?2:v<100?1:0):v)+' '+['B','KB','MB','GB','TB'][i]}
const rate=v=>v>=1?bytes(v)+'/s':'–';
function dur(s){s=Math.round(s);if(!(s>0))return '–';const d=s/86400|0,hr=s%86400/3600|0,m=s%3600/60|0;return d?`${d}d ${hr}h`:hr?`${hr}h ${m}m`:m?`${m}m`:`${s}s`}
const pctText=p=>p>=100?'100%':(Math.floor(p*10)/10).toFixed(1)+'%';
const ratioText=t=>t.downloaded_bytes>0?(t.uploaded_bytes/t.downloaded_bytes).toFixed(2):t.uploaded_bytes>0?'∞':'–';
const plural=(n,w)=>n+' '+w+(n===1?'':'s');

/* api */
let token=(document.querySelector('meta[name="rustorrent-api-token"]')||{}).content||'';
async function refreshToken(){
  try{const r=await fetch('/api-token',{cache:'no-store'}),d=await r.json();if(r.ok&&d.token){token=d.token;return true}}catch(e){}
  return false;
}
async function post(url,body,type){
  for(let retry=0;;retry++){
    const headers={'X-Rustorrent-Token':token};
    if(body!=null)headers['Content-Type']=type||'application/x-www-form-urlencoded';
    const r=await fetch(url,{method:'POST',headers,body,cache:'no-store'}),d=await r.json().catch(()=>({}));
    if(r.ok)return d;
    const msg=d.error||'HTTP '+r.status;
    if(!retry&&r.status===403&&/api token/.test(msg)&&await refreshToken())continue;
    throw new Error(msg);
  }
}
async function getJSON(url){
  const r=await fetch(url,{cache:'no-store'}),d=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(d.error||'HTTP '+r.status);
  return d;
}
const q=o=>new URLSearchParams(o).toString();
// Posts a form and reports the outcome; resolves to the response, or undefined on failure.
const act=(url,body,title,msg)=>post(url,body==null?body:q(body)).then(d=>{if(title)toast(title,msg);return d},e=>{toast('Action failed',e.message,true)});

/* toasts */
const toasts=h('div.toasts',{role:'status','aria-live':'polite'});
function toast(title,msg,bad){
  const e=h('div.toast'+(bad?'.bad':''),icon(bad?'alert':'ok'),h('div',h('b',{text:title}),msg&&h('span',{text:msg})));
  const kill=()=>{e.classList.add('out');setTimeout(()=>e.remove(),200)};
  e.onclick=kill;toasts.append(e);setTimeout(kill,bad?6000:3200);
  while(toasts.children.length>4)toasts.firstChild.remove();
}

/* skeleton: static markup only; dynamic text is set with textContent */
const NAV=[['all','All','list'],['downloading','Downloading','down'],['seeding','Seeding','up'],['paused','Paused','pause'],['completed','Completed','ok'],['error','Errors','alert']];
const TITLES={all:'All transfers',downloading:'Downloading',seeding:'Seeding',paused:'Paused',completed:'Completed',error:'Errors',search:'Search',rss:'RSS feeds',settings:'Settings'};
const navBtn=(n,label,data)=>`<button class="nav" ${data}>${ic(n)}<span>${label}</span><b class="c"></b></button>`;
const field=(id,label,control,note='')=>`<div class="field"><label for="${id}">${label}</label>${control}${note&&`<small>${note}</small>`}</div>`;
const num=(id,max,step,u)=>`<div class="unit"><input id="${id}" class="in" type="number" min="0" max="${max}" step="${step}"><span class="muted">${u}</span></div>`;
const choice=(id,opts)=>`<select id="${id}" class="in">${opts.map(([v,l])=>`<option value="${v}">${l}</option>`).join('')}</select>`;
$('app').outerHTML=`<div class="app" id="app">
<nav class="side" aria-label="Sections">
 <div class="brand"><span class="logo"><svg class="mark" viewBox="8 6 112 112" aria-hidden="true"><g fill="#fff" stroke="#fff" opacity=".25"><rect x="59" y="15" width="10" height="13" rx="3"/><rect x="59" y="15" width="10" height="13" rx="3" transform="rotate(36 64 62)"/><rect x="59" y="15" width="10" height="13" rx="3" transform="rotate(72 64 62)"/><rect x="59" y="15" width="10" height="13" rx="3" transform="rotate(108 64 62)"/><rect x="59" y="15" width="10" height="13" rx="3" transform="rotate(144 64 62)"/><rect x="59" y="15" width="10" height="13" rx="3" transform="rotate(180 64 62)"/><rect x="59" y="15" width="10" height="13" rx="3" transform="rotate(216 64 62)"/><rect x="59" y="15" width="10" height="13" rx="3" transform="rotate(252 64 62)"/><rect x="59" y="15" width="10" height="13" rx="3" transform="rotate(288 64 62)"/><rect x="59" y="15" width="10" height="13" rx="3" transform="rotate(324 64 62)"/><circle cx="64" cy="62" r="38" fill="none" stroke-width="6"/></g><path d="M54.5 37v45M46.5 74l8 8 8-8M54.5 37h13a12 12 0 0 1 0 24h-13M68.5 61l13 21" fill="none" stroke="#fff" stroke-width="10" stroke-linecap="round" stroke-linejoin="round"/></svg></span>Rustorrent</div>
 <div class="nav-h">Library</div>${NAV.map(([f,l,n])=>navBtn(n,l,`data-f="${f}"`)).join('')}
 <div class="labels" id="labels"></div>
 <div class="nav-h">Tools</div>${navBtn('search','Search','data-v="search"')}${navBtn('rss','RSS','data-v="rss"')}${navBtn('sliders','Settings','data-v="settings"')}
 <div class="foot"><button class="net" id="net" data-a="net"><i></i><span id="netT"></span></button><svg class="spark" viewBox="0 0 100 34" preserveAspectRatio="none" role="img" aria-label="Recent transfer rates"><path class="sd"/><path class="su"/></svg><div class="tot"><span id="totDown"></span><span id="totUp"></span></div></div>
</nav>
<main class="main">
 <header class="bar">
  <h1 id="title">All transfers</h1>
  <div class="rates"><span>${ic('down')}<span class="vh">Download rate</span><b id="rDown">–</b></span><span>${ic('up')}<span class="vh">Upload rate</span><b id="rUp">–</b></span></div>
  <label class="find" id="findWrap">${ic('search')}<input id="find" class="in" type="search" placeholder="Filter" aria-label="Filter transfers" autocomplete="off" spellcheck="false"></label>
  <button class="ib" id="theme" aria-label="Toggle theme"></button>
  <button class="btn primary" id="addBtn" data-a="add" title="Add torrent (A)">${ic('plus')}Add</button>
 </header>
 <div class="conn" id="conn" role="status" hidden>Connection lost. Reconnecting to Rustorrent…</div>
 <section class="view" id="v-library" aria-labelledby="title">
  <div class="lh" id="lh" aria-hidden="true"><span>Name</span><span>Status</span><span>Progress</span><span class="c-down">Down</span><span class="c-up">Up</span><span class="c-eta">ETA</span><span class="c-ratio">Ratio</span><span></span></div>
  <div id="list" role="list" aria-label="Transfers"></div>
  <div class="empty" id="empty" hidden>${ic('dl')}<h2>No transfers yet</h2><p>Add a .torrent file or paste a magnet link. You can also drop a .torrent file anywhere in this window.</p><button class="btn primary" data-a="add">${ic('plus')}Add your first torrent</button></div>
  <div class="empty" id="nomatch" hidden>${ic('search')}<h2>No matches</h2><p>No transfers match this view.</p><button class="btn" data-a="clear">Show all transfers</button></div>
 </section>
 <section class="view" id="v-search" aria-labelledby="title" hidden><div class="pad">
  <form class="sform" data-f="search"><input id="sq" class="in" type="search" aria-label="Search query" placeholder="Search with your plugins" autocomplete="off"><select id="scat" class="in" aria-label="Category">${['All categories','Anime','Books','Games','Movies','Music','Pictures','Software','TV'].map((c,i)=>`<option value="${i?c.toLowerCase():'all'}">${c}</option>`).join('')}</select><button class="btn primary" id="sGo">Search</button></form>
  <p class="muted gap" id="sStatus">Loading search plugins…</p>
  <div class="note" id="sWarn" hidden><b>No search plugins installed.</b> Rustorrent doesn't ship with search providers. Install a public plugin to start searching.<br><button class="btn" data-a="plugins">Manage plugins</button></div>
  <div id="sResults"></div>
  <details class="card gap" id="plugins"><summary>Plugins</summary>
   <p class="muted">Search plugins run third-party Python code on this computer. Install only plugins you trust.</p>
   <div class="list" id="pList"></div>
   <form class="inline" data-f="purl"><input id="pUrl" class="in" type="url" aria-label="Plugin URL" placeholder="https://…/plugin.py"><button class="btn">Install</button><label class="btn">Upload .py<input id="pFile" class="vh" type="file" accept=".py"></label><button class="btn" type="button" data-a="pupdate">Update all</button></form>
   <div class="sect"><h3>Community catalog <button class="ib" data-a="pcat" aria-label="Refresh catalog" title="Refresh catalog">${ic('recheck')}</button></h3>
   <input id="cFilter" class="in wide" type="search" aria-label="Filter catalog" placeholder="Filter plugins"><p class="muted gap" id="cMeta"></p><div class="list scroll" id="cList"></div></div>
  </details>
 </div></section>
 <section class="view" id="v-rss" aria-labelledby="title" hidden><div class="pad">
  <section class="card"><h2>Feeds</h2><p class="muted">Rustorrent checks each feed on a schedule.</p><div class="list" id="rFeeds"></div>
   <form class="inline" data-f="rfeed"><input id="rUrl" class="in" type="url" aria-label="Feed URL" placeholder="https://example.com/feed.xml"><select id="rInt" class="in" aria-label="Check interval">${[[900,'15 min'],[1800,'30 min'],[3600,'hour'],[21600,'6 hours']].map(([v,l])=>`<option value="${v}">Every ${l}</option>`).join('')}</select><button class="btn">Add feed</button></form></section>
  <section class="card"><h2>Download rules</h2><p class="muted">New feed items whose titles match a pattern are added automatically.</p><div class="list" id="rRules"></div>
   <form class="inline" data-f="rrule"><input id="rName" class="in" aria-label="Rule name" placeholder="Name"><input id="rPat" class="in" aria-label="Title pattern" placeholder="Pattern"><button class="btn">Add rule</button></form></section>
 </div></section>
 <section class="view" id="v-settings" aria-labelledby="title" hidden><div class="pad">
  <section class="card"><h2>Connectivity</h2><div class="reach" id="reach" role="status"><i></i><div><b id="reachT"></b><p id="reachD"></p></div></div><button class="btn" id="fwBtn" data-a="fw" hidden>Allow incoming connections</button></section>
  <section class="card"><h2>Bandwidth</h2><p class="muted">Limits apply to all transfers. Use 0 for unlimited.</p>${field('limDown','Download limit',num('limDown',102400,64,'KiB/s'))}${field('limUp','Upload limit',num('limUp',102400,64,'KiB/s'))}</section>
  <section class="card"><h2>Seeding</h2>${field('ratio','Stop seeding at ratio',num('ratio',10,0.1,'0 = keep seeding'))}</section>
  <section class="card"><h2>Connections</h2>${field('profile','Peer profile',choice('profile',[['conservative','Conservative'],['balanced','Balanced'],['aggressive','Aggressive']]),'<span id="profileNote"></span>')}</section>
  <section class="card"><h2>Appearance</h2>${field('appearance','Theme',choice('appearance',[['system','Match system'],['light','Light'],['dark','Dark']]))}</section>
  <section class="card"><h2>Session</h2><dl class="kv" id="session"></dl></section>
  <section class="card"><h2>Keyboard shortcuts</h2><p class="muted">${[['/','filter'],['A','add'],['↑ ↓','move'],['Enter','details'],['Space','pause or resume'],['Delete','remove'],['Esc','close']].map(([k,v])=>`<kbd>${k}</kbd> ${v}`).join(' · ')}</p></section>
 </div></section>
</main></div>
<dialog class="dlg" id="addDlg" aria-labelledby="addTitle"><div class="dc">
 <div class="dh"><h2 id="addTitle">Add torrent</h2><button class="ib" data-a="close" aria-label="Close">${ic('x')}</button></div>
 <label class="drop" id="drop"><input id="tFile" class="vh" type="file" accept=".torrent,application/x-bittorrent" aria-label="Torrent file">${ic('file')}<b id="dropName"></b><span id="dropHint"></span></label>
 <div class="or">or paste a magnet link</div>
 <input id="magnet" class="in" aria-label="Magnet link" placeholder="magnet:?xt=urn:btih:…" autocomplete="off" spellcheck="false">
 <p class="muted" id="addSummary"></p>
 <div class="rv" id="review" hidden></div>
 <div class="fld"><label for="dir">Save to</label><div class="inrow"><input id="dir" class="in" autocomplete="off" spellcheck="false"><button class="btn" id="browse" data-a="browse" hidden>Choose…</button></div></div>
 <div class="checks"><label class="chk"><input id="start" type="checkbox" checked>Start immediately</label><label class="chk"><input id="prealloc" type="checkbox">Preallocate disk space</label></div>
 <p class="err" id="addErr" role="alert" hidden></p>
 <div class="df"><button class="btn" data-a="close">Cancel</button><button class="btn primary" id="addGo" data-a="submit-add" disabled>Add</button></div>
</div></dialog>
<dialog class="dlg sm" id="rmDlg" aria-labelledby="rmTitle"><div class="dc">
 <h2 id="rmTitle">Remove transfer?</h2><p id="rmText" class="muted"></p>
 <label class="chk"><input id="rmFiles" type="checkbox">Also delete downloaded files</label>
 <div class="df"><button class="btn" id="rmCancel" data-a="close">Cancel</button><button class="btn danger" id="rmGo" data-a="rm-go">Remove transfer</button></div>
</div></dialog>
<div class="overlay" id="overlay"><div>Drop to add torrent</div></div>`;
document.body.append(toasts);
const list=$('list'),addDlg=$('addDlg'),rmDlg=$('rmDlg');

/* theme: no stored preference follows the system appearance */
const mq=matchMedia('(prefers-color-scheme: dark)');
const themePref=()=>{const t=store.get('theme');return t==='light'||t==='dark'?t:''};
function applyTheme(pref){
  const t=pref||(mq.matches?'dark':'light'),r=document.documentElement,b=$('theme');
  r.dataset.theme=t;
  b.innerHTML=ic(t==='dark'?'sun':'moon');b.title=`Switch to ${t==='dark'?'light':'dark'} appearance`;
  $('appearance').value=pref||'system';
}
mq.addEventListener&&mq.addEventListener('change',()=>applyTheme(themePref()));

/* state */
let G={},ready=false,view='library',filter=store.get('filter','all'),findText=store.get('find',''),lastTab=store.get('tab','files');
const T=new Map(),I=new Map(),rows=new Map(),dirty=new Set();
let order=[],structural=false,raf=0,selected=null,expanded=new Set();
try{expanded=new Set(JSON.parse(store.get('open','[]')))}catch(e){}
const INIT=/^(queued|loading|fetching metadata|pending)$/;
const LABELS={'fetching metadata':'Metadata',announcing:'Connecting','waiting for peers':'Waiting',deleting:'Removing',complete:'Verifying',seeding:'Verifying'};
// Derives the one visible state of a transfer from the raw engine status.
function infoOf(t){
  const s=t.status||'',done=(t.total_pieces>0&&t.completed_pieces>=t.total_pieces)||(t.total_bytes>0&&t.completed_bytes>=t.total_bytes);
  const stopping=s==='stopping',resume=!!t.paused||s==='stopped'||s==='shutdown';
  let k='downloading',label=LABELS[s]||(s&&s[0].toUpperCase()+s.slice(1))||'Downloading',note;
  if(resume||s==='paused'||stopping){k='paused';label=stopping?'Stopping':s==='paused'||t.paused?'Paused':'Stopped'}
  else if(/error|failed/.test(s)){k='error';label='Error'}
  else if(s==='queued'){k='queued';label='Queued'}
  else if(done){k='seeding';label='Seeding'}
  if(k==='paused')note=stopping?'Stopping…':label;
  else if(k==='error')note='Needs attention';
  else if(k==='queued')note='Waiting for a free slot';
  else if(s==='fetching metadata')note='Fetching metadata from peers';
  else if(k==='seeding')note=t.upload_rate_bps>0?`Sharing with ${plural(t.active_peers,'peer')}`:'Ready to share when peers ask';
  else if(s==='complete'||s==='seeding')note='Verifying pieces';
  else note=t.active_peers>0?`${plural(t.active_peers,'peer')} connected`:t.tracker_peers>0?'Finding reachable peers':'Looking for peers';
  const size=t.total_bytes?(done?bytes(t.total_bytes):`${bytes(t.completed_bytes)} of ${bytes(t.total_bytes)}`)+' · ':'';
  return {k,label,done,resume,stopping,init:INIT.test(s),note:size+note,cat:k==='queued'?'downloading':k,
    pct:done?100:t.total_bytes>0?Math.min(100,t.completed_bytes*100/t.total_bytes):0};
}
function matches(t,f){
  const s=I.get(t.id);
  return !!s&&(f==='all'||f===s.cat||(f==='completed'&&s.done)||(f.startsWith('label:')&&t.label===f.slice(6)));
}

/* live stream: status events carry deltas (see src/ui.rs) */
function apply(d){
  if(d.g)G=d.g;
  if(d.t)for(const t of d.t){T.set(t.id,t);I.set(t.id,infoOf(t));dirty.add(t.id)}
  if(d.ids){order=d.ids;const keep=new Set(order);for(const id of [...T.keys()])if(!keep.has(id)){T.delete(id);I.delete(id)}structural=true}
  ready=true;
  if(!raf)raf=requestAnimationFrame(render);
}
let es,connTimer=0;
function connect(){
  es=new EventSource('/events');
  es.addEventListener('status',e=>{try{apply(JSON.parse(e.data))}catch(err){console.warn(err)}});
  es.onopen=()=>{clearTimeout(connTimer);$('conn').hidden=true};
  es.onerror=()=>{
    clearTimeout(connTimer);connTimer=setTimeout(()=>{$('conn').hidden=false},600);
    if(es.readyState===2){es.close();setTimeout(connect,2000)}
  };
}

/* rendering */
function render(){
  raf=0;
  txt($('rDown'),rate(G.download_rate_bps));txt($('rUp'),rate(G.upload_rate_bps));
  renderSide();renderReach();
  if(structural){
    for(const [id,r] of rows)if(!T.has(id)){r.el.remove();rows.delete(id)}
    let prev=null;
    for(const id of order){
      let r=rows.get(id);if(!r){rows.set(id,r=makeRow(id));dirty.add(id)}
      const want=prev?prev.nextSibling:list.firstChild;
      if(r.el!==want)list.insertBefore(r.el,want);
      prev=r.el;
    }
  }
  for(const id of dirty){const r=rows.get(id),t=T.get(id);if(r&&t)updateRow(r,t)}
  dirty.clear();structural=false;
  applyFilter();
  if(view==='settings')renderSettings();
}
function renderSide(){
  const c={all:T.size,downloading:0,seeding:0,paused:0,completed:0,error:0},labels=new Map();
  for(const t of T.values()){const s=I.get(t.id);c[s.cat]++;if(s.done)c.completed++;if(t.label)labels.set(t.label,(labels.get(t.label)||0)+1)}
  const names=[...labels.keys()].sort(),box=$('labels'),key=names.join('\n');
  if(box.dataset.k!==key){
    box.dataset.k=key;
    box.replaceChildren(...(names.length?[h('div.nav-h',{text:'Labels'})]:[]),...names.map(n=>h('button.nav',{'data-f':'label:'+n},icon('tag'),h('span',{text:n}),h('b.c'))));
    markNav();
  }
  for(const b of document.querySelectorAll('.nav[data-f]')){const f=b.dataset.f;txt(b.lastChild,f.startsWith('label:')?labels.get(f.slice(6))||0:c[f])}
  const dh=G.download_history_bps||[],uh=G.upload_history_bps||[],n=Math.max(dh.length,uh.length),max=Math.max(1,...dh,...uh);
  const pts=a=>a.map((v,i)=>`${((i+n-a.length)/(n-1)*100).toFixed(1)},${(33-v/max*31).toFixed(1)}`).join(' L');
  const sp=document.querySelector('.spark');
  attr(sp.firstChild,'d',n>1&&dh.length?`M0,34 L${pts(dh)} L100,34 Z`:'M0,33 L100,33');
  attr(sp.lastChild,'d',n>1&&uh.length?'M'+pts(uh):'');
  txt($('totDown'),'↓ '+bytes(G.session_downloaded_bytes));txt($('totUp'),'↑ '+bytes(G.session_uploaded_bytes));
}
function makeRow(id){
  const r={id,name:h('span.nm'),tag:h('span.badge',{hidden:true}),sub:h('span.sub'),pill:h('span.pill'),fill:h('i'),pct:h('span.pct'),
    dl:h('span.n.c-down'),ul:h('span.n.c-up'),eta:h('span.n.c-eta'),ratio:h('span.n.c-ratio'),toggle:h('button.ib',{'data-a':'toggle'}),err:h('div.rerr',{role:'alert',hidden:true})};
  r.btn=h('button.rn',{'data-a':'expand','aria-expanded':'false'},icon('chev'),h('span.nw',h('span.nm-row',r.name,r.tag),r.sub));
  r.el=h('div.row',{role:'listitem','data-id':id},
    h('div.rm',r.btn,r.pill,h('div.prog',h('div.track',{'aria-hidden':'true'},r.fill),r.pct),r.dl,r.ul,r.eta,r.ratio,
      h('div.acts',r.toggle,ibtn('folder','Open folder','folder'),ibtn('trash','Remove','remove','.danger'))),r.err);
  return r;
}
function cellText(e,v){txt(e,v);e.classList.toggle('z',v==='–')}
function bar(fill,pct,p){const w=p.toFixed(2)+'%';if(fill.style.width!==w)fill.style.width=w;txt(pct,pctText(p))}
function updateRow(r,t){
  const s=I.get(t.id);r.t=t;
  r.el.className='row k-'+s.k+(s.done?' done':'')+(selected===t.id?' sel':'');
  txt(r.name,t.name||'Unnamed transfer');attr(r.name,'title',t.name);
  r.tag.hidden=!t.label;txt(r.tag,t.label);txt(r.sub,s.note);txt(r.pill,s.label);
  bar(r.fill,r.pct,s.pct);
  cellText(r.dl,rate(t.download_rate_bps));cellText(r.ul,rate(t.upload_rate_bps));
  cellText(r.eta,s.k==='downloading'&&t.download_rate_bps>0?dur(t.eta_secs):'–');cellText(r.ratio,ratioText(t));
  const label=s.resume?'Resume':'Pause',lock=s.stopping?'Transfer is stopping':s.init?'Available once the transfer has started':'';
  if(r.mode!==label){r.mode=label;r.toggle.replaceChildren(icon(s.resume?'play':'pause'));attr(r.toggle,'aria-label',label)}
  r.toggle.disabled=!!lock;attr(r.toggle,'title',lock||label);
  const err=s.k==='error'?t.last_error||'This transfer stopped because of an error.':'';
  r.err.hidden=!err;txt(r.err,err);
  const open=expanded.has(keyOf(t));
  attr(r.btn,'aria-expanded',String(open));
  if(open&&!r.dt)makeDetail(r);
  if(r.dt){r.dt.hidden=!open;if(open)updateDetail(r,t,s)}
}
const keyOf=t=>t.info_hash||'id:'+t.id;
function applyFilter(){
  const needle=findText.trim().toLowerCase();let any=false;
  for(const [id,r] of rows){
    const t=T.get(id),show=!!t&&matches(t,filter)&&(!needle||(t.name+' '+t.label).toLowerCase().includes(needle));
    if(r.el.hidden===show)r.el.hidden=!show;any=any||show;
  }
  $('empty').hidden=!ready||T.size>0;$('nomatch').hidden=!ready||!T.size||any;$('lh').hidden=!any;
}

/* detail pane: tabs are built once per row and updated in place */
const TABS=[['files','Files'],['trackers','Trackers'],['peers','Peers'],['info','Info']];
function kv(pairs){const f={},dl=h('dl.kv');for(const [k,label] of pairs)dl.append(h('dt',{text:label}),f[k]=h('dd'));return [dl,f]}
function makeDetail(r){
  const id=r.id,tl=h('div.tabs',{role:'tablist','aria-label':'Transfer details'});
  r.tabs={};r.panels={};r.dt=h('div.dt',tl);
  for(const [k,label] of TABS){
    tl.append(r.tabs[k]=h('button.tab',{role:'tab',id:`t${id}${k}`,'aria-controls':`p${id}${k}`,'data-a':'tab','data-tab':k,text:label}));
    r.dt.append(r.panels[k]=h('div.tp',{role:'tabpanel',id:`p${id}${k}`,'aria-labelledby':`t${id}${k}`,tabindex:'0'}));
  }
  r.fl=h('div.fl',empty('Loading files…'));r.frows=[];r.panels.files.append(r.fl);
  r.trk=h('div.list');
  r.panels.trackers.append(r.trk,h('form.inline',{'data-f':'tracker'},h('input.in',{'aria-label':'Tracker URL',placeholder:'udp://tracker.example.org:1337/announce'}),h('button.btn',{text:'Add tracker'})));
  let dl;[dl,r.peers]=kv([['conn','Connected'],['known','Known'],['int','Interested in us'],['served','Requests served'],['down','Download'],['up','Upload']]);
  r.cc=h('div.chips');r.diag=h('p.mono');
  r.panels.peers.append(dl,r.ccs=h('div.sect',{hidden:true},h('h3',{text:'Peers by country'}),r.cc),r.diags=h('div.sect',{hidden:true},h('h3',{text:'Diagnostics'}),r.diag));
  [dl,r.info]=kv([['dir','Save to'],['size','Size'],['pieces','Pieces'],['down','Downloaded'],['up','Uploaded'],['ratio','Ratio'],['hash','Info hash'],['ver','Format'],['pre','Preallocated']]);
  r.info.hash.className='mono';
  r.labelIn=h('input.in',{'aria-label':'Transfer label',placeholder:'No label',maxlength:'128'});
  r.panels.info.append(dl,h('div.sect',h('h3',{text:'Label'}),h('form.inline',{'data-f':'label'},r.labelIn,h('button.btn',{text:'Save label'}))),
    h('div.dacts',btn('Open folder','folder','folder'),r.stop=btn('Stop','stop','stop'),btn('Recheck','recheck','recheck'),btn('Archive','archive','archive'),btn('Remove transfer…','trash','remove','.danger')));
  r.el.append(r.dt);selectTab(r,lastTab);
}
function selectTab(r,k,focus){
  if(!r.tabs[k])k='files';r.tab=k;
  for(const [n] of TABS){const on=n===k;attr(r.tabs[n],'aria-selected',String(on));r.tabs[n].tabIndex=on?0:-1;r.panels[n].hidden=!on}
  if(focus)r.tabs[k].focus();
  if(r.t)updateDetail(r,r.t,I.get(r.id));
}
function updateDetail(r,t,s){
  if(r.tab==='info'){
    const f=r.info;
    txt(f.dir,t.download_dir||'–');txt(f.size,bytes(t.total_bytes));txt(f.pieces,`${t.completed_pieces} of ${t.total_pieces}`);
    txt(f.down,bytes(t.downloaded_bytes));txt(f.up,bytes(t.uploaded_bytes));txt(f.ratio,ratioText(t));txt(f.hash,t.info_hash||'–');
    txt(f.ver,t.meta_version===2?'v2':t.meta_version===3?'Hybrid v1 + v2':'v1');txt(f.pre,t.preallocate?'Yes':'No');
    if(document.activeElement!==r.labelIn&&!r.labelIn.dataset.dirty&&r.labelIn.value!==t.label)r.labelIn.value=t.label;
    r.stop.disabled=s.stopping||/^(loading|fetching metadata)$/.test(t.status);txt(r.stop.lastChild,s.stopping?'Stopping…':'Stop');
  }else if(r.tab==='trackers'){
    const key=t.trackers.join('\n');
    if(r.trk.dataset.k!==key){
      r.trk.dataset.k=key;
      r.trk.replaceChildren(...(t.trackers.length?t.trackers.map(u=>li(h('span.grow.mono',{title:u,text:u}),ibtn('x','Remove tracker '+u,'untrack','.danger',{'data-url':u})))
        :empty('No trackers. Peers are found through DHT and peer exchange where the torrent allows it.')));
    }
  }else if(r.tab==='peers'){
    const f=r.peers,cc=t.peer_countries||[],key=cc.map(c=>c.code+c.count).join(),diag=s.k!=='error'?t.last_error:'';
    txt(f.conn,t.active_peers);txt(f.known,t.tracker_peers);txt(f.int,t.interested_peers);txt(f.served,t.upload_requests_served);
    txt(f.down,rate(t.download_rate_bps));txt(f.up,rate(t.upload_rate_bps));
    r.ccs.hidden=!cc.length;
    if(r.cc.dataset.k!==key){r.cc.dataset.k=key;r.cc.replaceChildren(...cc.map(c=>h('span.badge',{text:`${c.flag||''} ${c.code} · ${c.count}`.trim()})))}
    r.diags.hidden=!diag;txt(r.diag,diag);
  }else if(t.files_rev!==r.frev)loadFiles(r);
}
// File lists are fetched on demand while the Files tab is open, not streamed.
function loadFiles(r){
  if(r.fbusy)return void(r.fagain=true);
  r.fbusy=true;const rev=r.t.files_rev;
  getJSON('/torrent/files?id='+r.id).then(d=>{r.frev=d.files_rev;renderFiles(r,d.files||[])},e=>{r.frev=rev;r.frows=[];r.fl.replaceChildren(h('p.err',{text:'Could not load files: '+e.message}))})
    .finally(()=>{r.fbusy=false;if(r.fagain){r.fagain=false;if(r.tab==='files'&&r.t.files_rev!==r.frev)loadFiles(r)}});
}
function renderFiles(r,files){
  if(!files.length){r.frows=[];return r.fl.replaceChildren(...empty('File details appear once metadata is available.'))}
  if(!r.frows.length)r.fl.replaceChildren();
  const s=I.get(r.id)||{},prefix=(r.t.name||'')+'/';
  files.forEach((f,i)=>{
    let fr=r.frows[i];
    if(!fr){
      fr=r.frows[i]={name:h('span.grow'),size:h('span.meta.num'),fill:h('i'),pct:h('span.pct'),
        sel:h('select.in.prio',{'data-i':i,'aria-label':'File priority'},...['Skip','Low','Normal','High'].map((text,value)=>h('option',{value,text})))};
      r.fl.append(fr.el=h('div.li',{'data-i':i},fr.name,fr.size,h('div.prog',h('div.track',{'aria-hidden':'true'},fr.fill),fr.pct),fr.sel,ibtn('pen','Rename file','rename','.ren')));
    }
    fr.path=f.path;
    if(!fr.editing){txt(fr.name,f.path.startsWith(prefix)?f.path.slice(prefix.length):f.path);attr(fr.name,'title',f.path)}
    txt(fr.size,bytes(f.length));bar(fr.fill,fr.pct,f.length?Math.min(100,f.completed*100/f.length):100);
    if(document.activeElement!==fr.sel&&fr.sel.value!==String(f.priority))fr.sel.value=String(f.priority);
    fr.sel.disabled=!!s.init;attr(fr.sel,'title',s.init?'Priority can be changed once metadata is ready':null);
  });
  while(r.frows.length>files.length)r.frows.pop().el.remove();
}
function startRename(r,i){
  const fr=r.frows[i];if(!fr||fr.editing)return;fr.editing=true;
  const shown=fr.name.textContent,base=fr.path.split('/').pop(),input=h('input.in',{value:base,'aria-label':'New file name'});
  fr.name.replaceChildren(input);input.focus();input.select();
  const finish=save=>{
    if(!fr.editing)return;fr.editing=false;const v=input.value.trim();txt(fr.name,shown);
    if(!save||!v||v===base)return;
    if(/[\\/]/.test(v)||v==='.'||v==='..')return toast('Invalid file name','Names cannot contain slashes.',true);
    txt(fr.name,shown.replace(/[^/]*$/,v));r.frev=null;
    act('/rename-file',{id:r.id,index:i,name:v},'File renamed',v);
  };
  input.onkeydown=e=>{if(e.key==='Enter'||e.key==='Escape'){e.preventDefault();e.stopPropagation();finish(e.key==='Enter')}};
  input.onblur=()=>finish(true);
}

/* views and selection */
function markNav(){for(const b of document.querySelectorAll('.nav'))attr(b,'aria-current',(view==='library'?b.dataset.f===filter:b.dataset.v===view)&&'page')}
function go(v,f){
  view=['search','rss','settings'].includes(v)?v:'library';store.set('view',view);
  if(f!=null){filter=f;store.set('filter',f)}
  for(const n of ['library','search','rss','settings'])$('v-'+n).hidden=n!==view;
  markNav();
  txt($('title'),view!=='library'?TITLES[view]:filter.startsWith('label:')?'Label: '+filter.slice(6):TITLES[filter]||TITLES.all);
  $('findWrap').hidden=view!=='library';
  if(view==='search')loadSearch();
  if(view==='rss')loadRss();
  if(view==='settings')renderSettings(true);
  applyFilter();
}
function select(id){
  const old=rows.get(selected),r=rows.get(id);
  if(old)old.el.classList.remove('sel');
  selected=id;if(r)r.el.classList.add('sel');
}
function move(d){
  const v=order.map(id=>rows.get(id)).filter(r=>r&&!r.el.hidden);if(!v.length)return;
  let i=v.findIndex(r=>r.id===selected);i=i<0?(d>0?0:v.length-1):Math.max(0,Math.min(v.length-1,i+d));
  select(v[i].id);v[i].btn.focus();v[i].el.scrollIntoView({block:'nearest'});
}
function toggleExpand(r){
  const k=keyOf(r.t);
  expanded.has(k)?expanded.delete(k):expanded.add(k);
  store.set('open',JSON.stringify([...expanded].slice(-50)));
  updateRow(r,r.t);
}

/* transfer actions */
function torrentAction(a,r){
  const t=r.t,id=t.id;
  if(a==='toggle')return act(`/torrent/${I.get(id).resume?'resume':'pause'}?id=${id}`);
  if(a==='folder')return act('/torrent/open-folder?id='+id);
  if(a==='remove')return confirmRemove(t);
  if(a==='stop')return act('/torrent/stop?id='+id,null,'Stopping transfer',t.name);
  if(a==='recheck')return act('/torrent/recheck?id='+id,null,'Checking files',t.name);
  if(a==='archive')return act('/torrent/archive?id='+id,null,'Transfer archived',t.name);
}
let rmTarget=null;
function confirmRemove(t){
  rmTarget=t;
  txt($('rmText'),`“${t.name||'This transfer'}” will be removed from your library. Downloaded files are kept unless you choose to delete them.`);
  $('rmFiles').checked=false;$('rmGo').disabled=false;
  openDialog(rmDlg);$('rmCancel').focus();
}
async function removeGo(){
  const t=rmTarget,data=$('rmFiles').checked;$('rmGo').disabled=true;
  try{await post(`/torrent/delete?id=${t.id}&data=${data?1:0}`);closeDialog(rmDlg);toast(data?'Transfer and files removed':'Transfer removed',t.name)}
  catch(e){$('rmGo').disabled=false;toast('Could not remove transfer',e.message,true)}
}

/* dialogs: native <dialog> with a fallback for older WebKit */
let modal=null,returnFocus=null;
function openDialog(d){
  if(modal)closeDialog(modal);
  returnFocus=document.activeElement;modal=d;
  if(d.showModal)d.showModal();else{d.classList.add('fb');d.setAttribute('role','dialog');d.setAttribute('aria-modal','true');d.setAttribute('open','')}
}
// Settle state synchronously: the native close event fires a task later, and
// keys pressed in between must already reach the page.
function closeDialog(d){
  if(!d.hasAttribute('open'))return;
  if(d.close)d.close();else d.removeAttribute('open');
  dialogClosed(d);
}
function dialogClosed(d){
  if(modal===d)modal=null;
  if(d===addDlg)resetAdd();
  if(returnFocus&&returnFocus.isConnected)returnFocus.focus();
  returnFocus=null;
}
for(const d of [addDlg,rmDlg]){
  d.addEventListener('close',()=>{if(modal===d)dialogClosed(d)});
  d.addEventListener('cancel',e=>{e.preventDefault();closeDialog(d)});
  d.addEventListener('click',e=>{if(e.target===d)closeDialog(d)});
}
function trapFocus(e){
  const items=[...modal.querySelectorAll('button,input,select,a[href]')].filter(n=>!n.disabled&&n.getClientRects().length),a=document.activeElement;
  if(!items.length)return;
  const first=items[0],last=items[items.length-1];
  if(e.shiftKey?a===first||!modal.contains(a):a===last||!modal.contains(a)){e.preventDefault();(e.shiftKey?last:first).focus()}
}

/* add torrent */
let draft=null,parseSeq=0;
function resetAdd(){draft=null;parseSeq++;$('tFile').value='';$('magnet').value='';$('addErr').hidden=true;renderReview()}
function openAdd(magnet){
  resetAdd();
  if(!$('dir').value)$('dir').value=G.download_dir||'';
  $('prealloc').checked=!!G.preallocate;$('start').checked=true;
  $('browse').hidden=!/Mac/.test(navigator.platform||navigator.userAgent);
  openDialog(addDlg);
  if(magnet){$('magnet').value=magnet;renderReview()}
  $('magnet').focus();
}
function validMagnet(m){
  try{const u=new URL(m);return u.protocol==='magnet:'&&u.searchParams.getAll('xt').some(v=>/^(urn:btih:([0-9a-f]{40}|[a-z2-7]{32})|urn:btmh:1220[0-9a-f]{64})$/i.test(v))}catch(e){return false}
}
function renderReview(){
  const rv=$('review'),m=$('magnet').value.trim();
  let msg='Choose a .torrent file or paste a magnet link.',ok=false;
  rv.hidden=true;
  txt($('dropName'),draft?draft.file:'Choose a .torrent file');txt($('dropHint'),draft?'Choose a different file':'or drop it here');
  if(draft){
    if(draft.parsing)msg='Reading torrent…';
    else if(draft.error)msg='Could not read this .torrent file: '+draft.error;
    else{
      const files=draft.files,n=files.filter(f=>f.sel).length;
      ok=n>0;
      msg=!ok?'Select at least one file to download.':`${plural(files.length,'file')} · ${bytes(draft.size)}`+(n<files.length?` · ${n} selected (${bytes(files.reduce((a,f)=>a+(f.sel?f.len:0),0))})`:'');
      if(rv.dataset.k!==draft.key){
        rv.dataset.k=draft.key;
        rv.replaceChildren(h('div.rv-h',h('input',{type:'checkbox','data-a':'rv-all','aria-label':'Select all files'}),h('b',{text:draft.name,title:draft.name})),
          h('div.rv-l',files.map((f,i)=>h('label',h('input.rv-f',{type:'checkbox','data-i':i}),h('span',{text:f.path,title:f.path}),h('span.muted.num',{text:bytes(f.len)})))));
      }
      for(const c of rv.querySelectorAll('.rv-f'))c.checked=files[c.dataset.i].sel;
      const all=rv.querySelector('[data-a=rv-all]');all.checked=n===files.length;all.indeterminate=n>0&&n<files.length;
      rv.hidden=files.length<2;
    }
  }else if(m){ok=validMagnet(m);msg=ok?'Magnet link ready to add.':'Enter a valid magnet link with a BitTorrent info hash.'}
  txt($('addSummary'),msg);$('addGo').disabled=!ok;
}
async function setFile(file){
  const seq=++parseSeq;$('magnet').value='';$('addErr').hidden=true;
  draft={file:file.name,files:[],parsing:true};renderReview();
  try{
    if(file.size>2*1024*1024)throw new Error('torrent files must be smaller than 2 MiB');
    const b=new Uint8Array(await file.arrayBuffer()),p=preview(b,file.name);
    if(seq===parseSeq)draft={file:file.name,bytes:b,key:String(seq),...p};
  }catch(e){if(seq===parseSeq)draft={file:file.name,files:[],error:e.message}}
  if(seq===parseSeq)renderReview();
}
// Bounded bencode reader for the add preview: size, depth and node budgets, no duplicate keys.
const dec=new TextDecoder();
function bdecode(b){
  let nodes=0;
  const parse=(o,depth)=>{
    if(depth>64||++nodes>100000)throw new Error('metadata is too complex');
    const c=b[o];
    if(c===100||c===108){
      const dict=c===100,v=dict?Object.create(null):[];let i=o+1;
      while(i<b.length&&b[i]!==101){
        if(!dict){const val=parse(i,depth+1);v.push(val);i=val.end;continue}
        const key=parse(i,depth+1);if(!(key.v instanceof Uint8Array))throw new Error('invalid dictionary key');
        const k=dec.decode(key.v);if(k in v)throw new Error('duplicate dictionary key');
        const val=parse(key.end,depth+1);v[k]=val;i=val.end;
      }
      if(b[i]!==101)throw new Error('unexpected end of file');
      return {v,end:i+1};
    }
    if(c===105){const e=b.indexOf(101,o),raw=e<0?'':dec.decode(b.subarray(o+1,e));if(!/^(0|-?[1-9]\d*)$/.test(raw)||!Number.isSafeInteger(+raw))throw new Error('invalid integer');return {v:+raw,end:e+1}}
    const colon=b.indexOf(58,o),len=c>=48&&c<=57&&colon>o&&colon-o<=10?+dec.decode(b.subarray(o,colon)):NaN;
    if(!Number.isSafeInteger(len)||colon+1+len>b.length)throw new Error('invalid bencode');
    return {v:b.subarray(colon+1,colon+1+len),end:colon+1+len};
  };
  const root=parse(0,0);if(root.end!==b.length)throw new Error('trailing data');return root.v;
}
function preview(bytes,fallback){
  const root=bdecode(bytes),info=root&&root.info&&root.info.v;
  if(!info||info instanceof Uint8Array||Array.isArray(info))throw new Error('missing info dictionary');
  const str=n=>n&&n.v instanceof Uint8Array?dec.decode(n.v):'',int=n=>n&&typeof n.v==='number'?Math.max(0,n.v):0;
  const name=str(info['name.utf-8']||info.name)||fallback,files=[];
  if(info.files&&Array.isArray(info.files.v)){
    for(const e of info.files.v){const d=e.v||{},p=d['path.utf-8']||d.path;files.push({path:Array.isArray(p&&p.v)?p.v.map(str).join('/'):'',len:int(d.length),sel:true})}
  }else if(info['file tree']){
    const walk=(tree,segs)=>{for(const k of Object.keys(tree).sort()){const n=tree[k].v;if(k==='')files.push({path:segs.join('/'),len:int(n.length),sel:true});else if(n&&!(n instanceof Uint8Array))walk(n,[...segs,k])}};
    walk(info['file tree'].v,[]);
  }else files.push({path:name,len:int(info.length),sel:true});
  return {name,files,size:files.reduce((a,f)=>a+f.len,0)};
}
async function submitAdd(){
  const go=$('addGo'),start=$('start').checked,base={dir:$('dir').value.trim(),prealloc:$('prealloc').checked?1:0,paused:start?0:1};
  go.disabled=true;txt(go,'Adding…');$('addErr').hidden=true;
  try{
    if(draft&&draft.bytes){
      const skip=draft.files.map((f,i)=>f.sel?-1:i).filter(i=>i>=0).join(',');
      await post('/add-torrent?'+q({...base,skip}),draft.bytes,'application/x-bittorrent');
    }else await post('/add-magnet',q({...base,magnet:$('magnet').value.trim()}));
    const name=draft?draft.name:'Magnet link';
    closeDialog(addDlg);toast(start?'Torrent added':'Torrent added paused',name);
  }catch(e){txt($('addErr'),'Could not add torrent: '+e.message);$('addErr').hidden=false}
  txt(go,'Add');if(modal===addDlg)renderReview();
}
async function browseDir(){
  try{const d=await post('/select-download-dir');if(d.path)$('dir').value=d.path}
  catch(e){toast('Folder picker unavailable',e.message,true);$('dir').focus()}
}

/* search */
let S=null,sTimer=0,catalog=null,catLoading=false,sStarted=0,sSort={k:store.get('ssort','seeds'),d:store.get('sdir','desc')};
const added=new Set();
const trust=n=>confirm(`Search plugins run third-party Python code on this computer. Install ${n} only if you trust its source. Continue?`);
function enabledPlugins(){
  const healthy=(S&&S.plugins||[]).filter(p=>p.healthy).map(p=>p.module);
  let chosen=[];try{chosen=JSON.parse(store.get('search-plugins','[]')).filter(m=>healthy.includes(m))}catch(e){}
  return chosen.length?chosen:healthy;
}
async function loadSearch(){
  clearTimeout(sTimer);
  try{S=await getJSON('/search/status');renderSearch()}catch(e){txt($('sStatus'),'Search is unavailable: '+e.message)}
  if(S&&(S.busy||S.loading)&&view==='search')sTimer=setTimeout(loadSearch,900);
  if($('plugins').open&&!catalog)loadCatalog();
}
async function pluginsChanged(){await loadSearch();if(catalog)loadCatalog()}
function renderSearch(){
  const plugins=(S.plugins||[]).filter(p=>p.module!=='__init__'),ready=plugins.filter(p=>p.healthy).length,on=enabledPlugins(),res=S.results||[];
  if(S.last_started_at&&S.last_started_at!==sStarted){sStarted=S.last_started_at;added.clear()}
  $('sWarn').hidden=ready>0||!!S.loading;
  txt($('sStatus'),S.loading?'Loading search plugins…':S.busy?'Searching…':S.last_error||S.plugin_error||(res.length?`${plural(res.length,'result')} from ${plural(on.length,'plugin')}.`
    :ready?`Ready to search with ${on.length===ready?'all ':''}${plural(on.length,'plugin')}.`:'Install a plugin to start searching.'));
  $('sGo').disabled=!!S.busy;txt($('sGo'),S.busy?'Searching…':'Search');
  if(document.activeElement!==$('sq')&&!$('sq').value&&S.query)$('sq').value=S.query;
  $('scat').value=store.get('scat','all');
  renderResults();
  $('pList').replaceChildren(...(plugins.length?plugins.map(p=>li(
    h('input',{type:'checkbox','data-plugin':p.module,checked:p.healthy&&on.includes(p.module),disabled:!p.healthy,'aria-label':'Use '+(p.display_name||p.module)}),
    h('div.grow',h('b',{text:(p.display_name||p.module)+(p.version?' '+p.version:'')}),h('span.badge.'+(p.healthy?'ok':'bad'),{text:p.healthy?'Ready':'Broken'}),
      h('div.muted',{text:p.broken_reason||(p.categories||[]).join(', ')||'All categories'})),
    ibtn('trash','Remove plugin '+p.module,'punins','.danger',{'data-module':p.module}))):empty('No plugins installed yet.')));
}
function renderResults(){
  const res=S&&S.results||[],{k,d}=sSort,key={date:'pub_date'}[k]||k,m=d==='asc'?1:-1;
  if(!res.length)return $('sResults').replaceChildren();
  const sorted=res.slice().sort((a,b)=>(typeof a[key]==='number'?a[key]-b[key]:String(a[key]||'').localeCompare(String(b[key]||'')))*m||String(a.name).localeCompare(String(b.name)));
  const th=(k2,label,cls)=>h('th'+(cls||''),{'aria-sort':k===k2&&(d==='asc'?'ascending':'descending')},h('button.sort',{'data-a':'ssort','data-k':k2},label,k===k2&&icon(d==='asc'?'up':'down')));
  const cell=v=>h('td.n',{text:v});
  $('sResults').replaceChildren(h('table.tbl',h('thead',h('tr',th('name','Name'),th('plugin','Source'),th('size','Size','.n'),th('seeds','Seeds','.n'),th('leech','Peers','.n'),th('date','Date','.n'),h('th',h('span.vh',{text:'Actions'})))),
    h('tbody',sorted.map(x=>{
      let link=null;try{const u=new URL(x.desc_link);if(/^https?:$/.test(u.protocol))link=h('a.muted',{href:u.href,target:'_blank',rel:'noopener noreferrer',text:'Details'})}catch(e){}
      const done=added.has(String(x.index));
      return h('tr',h('td',h('div.t',{title:x.name,text:x.name||'Untitled'}),link),h('td',{text:x.plugin||x.site_url||''}),cell(x.size>0?bytes(x.size):'–'),cell(x.seeds>=0?x.seeds:'–'),cell(x.leech>=0?x.leech:'–'),
        cell(x.pub_date>0?new Date(x.pub_date*1000).toLocaleDateString():'–'),h('td.n',h('button.btn.sm'+(done?'':'.primary'),{'data-a':'sadd','data-index':x.index,'data-name':x.name,disabled:done,text:done?'Added':'Add'})));
    }))));
}
async function loadCatalog(refresh){
  if(catLoading)return;catLoading=true;txt($('cMeta'),'Loading the community plugin list…');
  try{const d=await getJSON('/search/catalog'+(refresh?'?refresh=1':''));catalog=d.entries||[];txt($('cMeta'),d.error||`${plural(catalog.length,'plugin')} from the qBittorrent unofficial plugin list.`)}
  catch(e){txt($('cMeta'),'Could not load the catalog: '+e.message)}
  catLoading=false;renderCatalog();
}
function renderCatalog(){
  if(!catalog)return;
  const f=$('cFilter').value.trim().toLowerCase();
  const items=catalog.filter(e=>!f||[e.name,e.author,e.comment,e.module].join(' ').toLowerCase().includes(f))
    .sort((a,b)=>(b.installed-a.installed)||String(a.name).localeCompare(String(b.name)));
  $('cList').replaceChildren(...(items.length?items.map(e=>li(h('div.grow',h('b',{text:e.name||e.module}),
      e.installed?h('span.badge.'+(e.installed_healthy?'ok':'bad'),{text:e.installed_healthy?'Installed':'Needs fix'}):null,
      h('div.muted',{text:[e.author,e.version&&'v'+e.version,e.updated].filter(Boolean).join(' · ')||e.comment||''})),
    h('button.btn.sm'+(e.installed?'':'.primary'),{'data-a':'pinstall','data-url':e.download_url||'',text:e.installed?'Update':'Install'})))
    :empty(f?'No plugins match that filter.':'The catalog is empty.')));
}

/* rss */
let R=null;
async function loadRss(){try{R=await getJSON('/rss/status');renderRss()}catch(e){toast('Could not load RSS feeds',e.message,true)}}
function renderRss(){
  const feeds=R.feeds||[],rules=R.rules||[],title=u=>(feeds.find(f=>f.url===u)||{}).title||u;
  $('rFeeds').replaceChildren(...(feeds.length?feeds.map(f=>li(h('div.grow',{title:f.url},h('b',{text:f.title||f.url}),
      h('div.muted',{text:`${plural(f.items,'item')} · every ${dur(f.interval)} · checked ${f.last_poll>0?dur(Date.now()/1000-f.last_poll)+' ago':'never'}`})),
    ibtn('trash','Remove feed '+(f.title||f.url),'rfeed-rm','.danger',{'data-url':f.url}))):empty('No feeds yet.')));
  $('rRules').replaceChildren(...(rules.length?rules.map(r=>li(h('div.grow',h('b',{text:r.name}),h('div.muted',{text:`Matches “${r.pattern}” · ${r.feed_url?title(r.feed_url):'all feeds'}`})),
    ibtn('trash','Remove rule '+r.name,'rrule-rm','.danger',{'data-name':r.name}))):empty('No rules yet.')));
}
const rssAct=(url,body,title)=>act(url,body,title).then(d=>{loadRss();return d});

/* reachability: whether other peers can connect to us, and what to do if not */
const sharedIp=ip=>/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip||'');
function reach(){
  const fw=G.firewall_status,n=G.inbound_public_peers||0,port=G.incoming_port,maps=[G.natpmp_status,G.upnp_status],rip=G.router_external_ip,tip=G.tracker_external_ip;
  if(fw==='block-all')return['err','Firewall blocks incoming connections','“Block all incoming connections” is on in System Settings › Network › Firewall, so peers cannot reach you. Turn it off to seed.','Blocked by firewall'];
  if(fw==='blocked'||fw==='unlisted')return['err','The macOS firewall is blocking Rustorrent','Peers cannot connect to you, so seeding waits. Allow Rustorrent to accept incoming connections.','Blocked by firewall',1];
  if(n)return['ok','Reachable',`${plural(n,'peer')} connected to you from the internet this session.`,'Reachable'];
  const ups=G.upstream_status||'',cgnat=/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(rip||'')||!sharedIp(rip)&&rip&&tip&&!tip.includes(':')&&tip!==rip;
  if(cgnat)return['warn','Behind your provider\'s shared address',`Your internet provider shares one public address between customers (carrier-grade NAT), so peers cannot connect in and no router setting can change that. Ask your provider for a public IPv4 address. Uploads still reach peers that Rustorrent connects to.`,'Not reachable'];
  if(sharedIp(rip)){
    if(ups.startsWith('mapped '))return['warn','Port open on both routers',`Your router sits behind another router or modem, and Rustorrent opened ${ups.match(/port \d+/)[0]} on both. Waiting for the first peer to connect in.`,'Waiting for peers'];
    return['warn','Behind a second router',`Your router's internet address (${rip}) is private, so another router or your provider's modem sits in front of it${ups?' and did not accept a request to open the port':''}. On that device (usually at ${rip.replace(/\.\d+$/,'.1')}): turn on bridge mode, or forward port ${port} (TCP and UDP) to ${rip}, or make ${rip} its DMZ host. Until then, uploads only reach peers that Rustorrent connects to.`,'Not reachable'];
  }
  const m=maps.find(m=>m&&m.startsWith('mapped '));
  if(m)return['warn','Port open on your router',`Your router forwards ${m.match(/port \d+/)[0]} to Rustorrent over ${m.includes('upnp')?'UPnP':'NAT-PMP'}. Waiting for the first peer to connect in.`,'Waiting for peers'];
  if(maps.some(m=>m==='pending'))return['warn','Checking your router…','','Checking…'];
  if(maps.every(m=>m&&m.startsWith('disabled')))return['warn','Automatic port forwarding is off',`Rustorrent is not asking your router to open a port. Forward port ${port} (TCP and UDP) to this computer so peers can connect in.`,'Not reachable'];
  return['warn','Incoming port not open',`Your router did not accept a UPnP or NAT-PMP request. Turn one of them on in the router settings, or forward port ${port} (TCP and UDP) to this computer. Until then only peers that Rustorrent connects to can download from you.`,'Not reachable'];
}
function renderReach(){
  const [k,title,detail,short,fix]=reach(),net=$('net');
  net.className='net '+k;txt($('netT'),short);attr(net,'title',title);
  if(view!=='settings')return;
  $('reach').className='reach '+k;txt($('reachT'),title);txt($('reachD'),detail);$('fwBtn').hidden=!fix;
}

/* settings */
function renderSettings(force){
  renderReach();
  const set=(id,v)=>{const e=$(id);if(force||document.activeElement!==e&&!e.dataset.dirty)e.value=v};
  set('limDown',Math.round((G.global_download_limit_bps||0)/1024));set('limUp',Math.round((G.global_upload_limit_bps||0)/1024));
  set('ratio',G.seed_ratio||0);set('profile',G.peer_profile||'balanced');
  txt($('profileNote'),G.peer_profile_global_limit?`Up to ${G.peer_profile_global_limit} peers in total, ${G.peer_profile_torrent_limit} per transfer.`:'');
  const maps=[G.natpmp_status,G.upnp_status].filter(Boolean),mapped=maps.filter(m=>m.startsWith('mapped ')),sum=k=>[...T.values()].reduce((a,t)=>a+t[k],0);
  const pairs=[['Version',G.version],['Default save location',G.download_dir],['Downloaded this session',bytes(G.session_downloaded_bytes)],['Uploaded this session',bytes(G.session_uploaded_bytes)],
    ['Peers',`${sum('active_peers')} connected · ${sum('tracker_peers')} known`],['Connections',`${G.peer_connected||0} opened · ${G.peer_disconnected||0} closed`],
    ['Incoming port',G.incoming_port||'–'],['Port mapping',(mapped.length?mapped:maps).join(' · ')||'–'],
    ['Disk latency',`read ${(G.disk_read_ms_avg||0).toFixed(1)} ms · write ${(G.disk_write_ms_avg||0).toFixed(1)} ms`],['Proxy',G.proxy_label]].filter(p=>p[1]!=null&&p[1]!=='');
  const dl=$('session'),key=JSON.stringify(pairs);
  if(dl.dataset.k!==key){dl.dataset.k=key;dl.replaceChildren(...pairs.flatMap(([k,v])=>[h('dt',{text:k}),h('dd',{text:v})]))}
}
function clampInput(e,max,round){const v=Math.max(0,Math.min(max,round(+e.value||0)));e.value=v;delete e.dataset.dirty;return v}

/* events */
const CLICK={
  net:()=>go('settings'),
  fw:el=>{el.disabled=true;act('/network/allow-firewall',null,'Firewall updated','Peers can now connect to Rustorrent.').finally(()=>{el.disabled=false})},
  add:()=>openAdd(),'submit-add':submitAdd,browse:browseDir,'rm-go':removeGo,pcat:()=>loadCatalog(true),
  close:el=>closeDialog(el.closest('dialog')),
  clear:()=>{findText='';store.set('find','');$('find').value='';go('library','all')},
  'rv-all':el=>{for(const f of draft.files)f.sel=el.checked;renderReview()},
  plugins:()=>{$('plugins').open=true;$('plugins').scrollIntoView({block:'start',behavior:'smooth'})},
  ssort:el=>{const k=el.dataset.k;sSort={k,d:sSort.k===k&&sSort.d==='desc'?'asc':'desc'};store.set('ssort',k);store.set('sdir',sSort.d);renderResults()},
  sadd:el=>{el.disabled=true;post('/search/add-result',q({index:el.dataset.index,dir:G.download_dir||'',prealloc:G.preallocate?1:0}))
    .then(()=>{added.add(el.dataset.index);txt(el,'Added');el.classList.remove('primary');toast('Torrent added',el.dataset.name)},e=>{el.disabled=false;toast('Could not add result',e.message,true)})},
  punins:el=>{if(confirm(`Remove search plugin ${el.dataset.module}?`))act('/search/remove-plugin',{module:el.dataset.module},'Plugin removed').then(pluginsChanged)},
  pinstall:el=>{if(!el.dataset.url||!trust('this plugin'))return;el.disabled=true;txt(el,'Installing…');act('/search/install-url',{url:el.dataset.url},'Plugin installed').then(pluginsChanged)},
  pupdate:async()=>{
    const urls=(catalog||[]).filter(x=>x.installed&&x.download_url).map(x=>x.download_url);
    if(!urls.length)return toast('Nothing to update','Open the community catalog to link installed plugins.');
    if(!trust('updates for all installed community plugins'))return;
    try{for(const url of urls)await post('/search/install-url',q({url}));toast('Plugins updated')}catch(e){toast('Update failed',e.message,true)}
    pluginsChanged();
  },
  'rfeed-rm':el=>rssAct('/rss/remove-feed',{url:el.dataset.url},'Feed removed'),
  'rrule-rm':el=>rssAct('/rss/remove-rule',{name:el.dataset.name},'Rule removed')
};
const on=(type,fn)=>document.addEventListener(type,fn);
const rowOf=el=>{const e=el.closest('.row');return e&&rows.get(+e.dataset.id)};
on('click',e=>{
  const el=e.target.closest('[data-a],.nav,.row');if(!el)return;
  const a=el.dataset.a,r=rowOf(el);
  if(r)select(r.id);
  if(el.classList.contains('nav'))return go(el.dataset.v||'library',el.dataset.f);
  if(!a)return;
  if(r&&r.t){
    if(a==='expand')return toggleExpand(r);
    if(a==='tab'){store.set('tab',lastTab=el.dataset.tab);return selectTab(r,lastTab)}
    if(a==='untrack')return act('/torrent/remove-tracker',{id:r.id,url:el.dataset.url},'Tracker removed');
    if(a==='rename')return startRename(r,+el.closest('.li').dataset.i);
    return torrentAction(a,r);
  }
  if(CLICK[a])CLICK[a](el);
});
const SUBMIT={
  label:(f,r)=>{const v=r.labelIn.value.trim();act('/torrent/set-label',{id:r.id,label:v},v?'Label saved':'Label cleared',v).then(()=>{delete r.labelIn.dataset.dirty})},
  tracker:(f,r)=>{const input=f.querySelector('input'),url=input.value.trim();if(url)act('/torrent/add-tracker',{id:r.id,url},'Tracker added').then(d=>{if(d)input.value=''})},
  search:()=>{
    const query=$('sq').value.trim();if(!query)return $('sq').focus();
    added.clear();$('sGo').disabled=true;txt($('sStatus'),'Searching…');
    act('/search/run',{query,category:$('scat').value,engines:enabledPlugins().join(',')}).then(loadSearch);
  },
  purl:()=>{const url=$('pUrl').value.trim();if(url&&trust(url))act('/search/install-url',{url},'Plugin installed').then(d=>{if(d)$('pUrl').value='';pluginsChanged()})},
  rfeed:()=>{const url=$('rUrl').value.trim();if(url)rssAct('/rss/add-feed',{url,interval:$('rInt').value},'Feed added').then(d=>{if(d)$('rUrl').value=''})},
  rrule:()=>{const name=$('rName').value.trim(),pattern=$('rPat').value.trim();if(name&&pattern)rssAct('/rss/add-rule',{name,pattern},'Rule added').then(d=>{if(d)$('rName').value=$('rPat').value=''})}
};
on('submit',e=>{e.preventDefault();const f=e.target,r=rowOf(f),fn=SUBMIT[f.dataset.f];if(fn&&(r||!f.closest('.row')))fn(f,r)});
on('input',e=>{
  const t=e.target;
  if(t.id==='find'){findText=t.value;store.set('find',findText);applyFilter()}
  else if(t.id==='magnet'){if(t.value.trim()){draft=null;parseSeq++;$('tFile').value=''}renderReview()}
  else if(t.id==='cFilter')renderCatalog();
  else if(t.classList.contains('in'))t.dataset.dirty='1';
});
on('change',e=>{
  const t=e.target,r=rowOf(t),id=t.id;
  if(id==='tFile'){if(t.files[0])setFile(t.files[0])}
  else if(t.classList.contains('rv-f')){draft.files[t.dataset.i].sel=t.checked;renderReview()}
  else if(t.classList.contains('prio')&&r)act('/file-priority',{id:r.id,index:t.dataset.i,priority:t.value});
  else if(id==='limDown'||id==='limUp')act('/rate-limits',{download_kbps:clampInput($('limDown'),102400,Math.round),upload_kbps:clampInput($('limUp'),102400,Math.round)},'Bandwidth limits saved');
  else if(id==='ratio')act('/settings/seed-ratio',{ratio:clampInput(t,10,v=>Math.round(v*100)/100)},'Seeding limit saved');
  else if(id==='profile'){delete t.dataset.dirty;act('/settings/peer-profile',{profile:t.value},'Peer profile saved')}
  else if(id==='appearance'){const v=t.value==='system'?'':t.value;store.set('theme',v||null);applyTheme(v)}
  else if(id==='scat')store.set('scat',t.value);
  else if(t.dataset.plugin)store.set('search-plugins',JSON.stringify([...document.querySelectorAll('[data-plugin]')].filter(c=>c.checked&&!c.disabled).map(c=>c.dataset.plugin)));
  else if(id==='pFile'){const file=t.files[0];t.value='';if(file&&trust(file.name))file.arrayBuffer().then(b=>post('/search/install-plugin?filename='+encodeURIComponent(file.name),b,'text/x-python'))
    .then(()=>toast('Plugin installed',file.name),err=>toast('Action failed',err.message,true)).then(pluginsChanged)}
});
on('focusin',e=>{const r=e.target.closest&&rowOf(e.target);if(r)select(r.id)});
$('plugins').addEventListener('toggle',()=>{if($('plugins').open&&!catalog)loadCatalog()});
$('theme').addEventListener('click',()=>{const t=document.documentElement.dataset.theme==='dark'?'light':'dark';store.set('theme',t);applyTheme(t)});
on('keydown',e=>{
  const t=e.target,key=e.key;
  if(modal){if(key==='Escape'){e.preventDefault();closeDialog(modal)}else if(key==='Tab')trapFocus(e);return}
  if((e.metaKey||e.ctrlKey)&&key.toLowerCase()==='o'){e.preventDefault();return openAdd()}
  if(e.metaKey||e.ctrlKey||e.altKey)return;
  if(t.getAttribute('role')==='tab'&&/^Arrow(Left|Right)$/.test(key)){
    const r=rowOf(t),i=TABS.findIndex(x=>x[0]===r.tab);
    e.preventDefault();store.set('tab',lastTab=TABS[(i+(key==='ArrowRight'?1:3))%4][0]);return selectTab(r,lastTab,true);
  }
  if(/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)){if(key==='Escape'&&t.id==='find'&&t.value){t.value=findText='';store.set('find','');applyFilter()}return}
  if(key==='/'){e.preventDefault();if(view!=='library')go('library');return $('find').focus()}
  if(key==='a'||key==='A'){e.preventDefault();return openAdd()}
  if(view!=='library')return;
  if(key==='ArrowDown'){e.preventDefault();return move(1)}
  if(key==='ArrowUp'){e.preventDefault();return move(-1)}
  const r=rows.get(selected);if(!r||!r.t||r.el.hidden)return;
  if(key===' '&&(t===document.body||t.classList.contains('rn'))){e.preventDefault();if(!r.toggle.disabled)torrentAction('toggle',r)}
  else if(key==='Delete'||key==='Backspace'){e.preventDefault();confirmRemove(r.t)}
});
// Space on a focused transfer name pauses/resumes instead of activating the disclosure button.
on('keyup',e=>{if(e.key===' '&&e.target.classList.contains('rn'))e.preventDefault()});
on('paste',e=>{
  if(modal||/^(INPUT|TEXTAREA)$/.test(e.target.tagName))return;
  const s=(e.clipboardData&&e.clipboardData.getData('text')||'').trim();
  if(/^magnet:\?/i.test(s)){e.preventDefault();openAdd(s)}
});
let drag=0;
const isFiles=e=>e.dataTransfer&&[...e.dataTransfer.types].includes('Files');
const dragOff=()=>{drag=0;$('overlay').classList.remove('on');$('drop').classList.remove('over')};
on('dragenter',e=>{if(!isFiles(e))return;e.preventDefault();drag++;$('overlay').classList.toggle('on',modal!==addDlg);$('drop').classList.add('over')});
on('dragover',e=>{if(isFiles(e)){e.preventDefault();e.dataTransfer.dropEffect='copy'}});
on('dragleave',()=>{if(--drag<=0)dragOff()});
on('drop',e=>{
  if(!isFiles(e))return;e.preventDefault();dragOff();
  const file=[...e.dataTransfer.files].find(f=>/\.torrent$/i.test(f.name));
  if(!file)return toast('Not a torrent file','Drop a file ending in .torrent.',true);
  if(modal!==addDlg)openAdd();
  setFile(file);
});

$('find').value=findText;
applyTheme(themePref());
go(store.get('view','library'),filter);
renderReview();
connect();
