import{initializeApp}from"https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js";
import{getDatabase,ref,onValue,set,push,remove,get,off}from"https://www.gstatic.com/firebasejs/10.12.0/firebase-database.js";
import{getAuth,signInAnonymously,onAuthStateChanged}from"https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";
import{getFunctions,httpsCallable,connectFunctionsEmulator}from"https://www.gstatic.com/firebasejs/10.12.0/firebase-functions.js";
const _app=initializeApp({apiKey:"AIzaSyBuuSFWmjkDPiF-LNlZkjVcMDPK9sHyYEQ",authDomain:"unit-e-1d07b.firebaseapp.com",databaseURL:"https://unit-e-1d07b-default-rtdb.europe-west1.firebasedatabase.app",projectId:"unit-e-1d07b",storageBucket:"unit-e-1d07b.firebasestorage.app",messagingSenderId:"465930916258",appId:"1:465930916258:web:89210233e6ba1004d262fb"});
const db=getDatabase(_app);
const auth=getAuth(_app);
const fns=getFunctions(_app,"europe-west1");
const fnVerifyPin=httpsCallable(fns,"verifyPin");
const fnSetPin=httpsCallable(fns,"setPin");
const fnHasPins=httpsCallable(fns,"hasPins");
let _authReady=false,_authUid=null;
onAuthStateChanged(auth,u=>{_authUid=u?u.uid:null;_authReady=true;});
let _authFailed=false;
const _authP=signInAnonymously(auth).catch(e=>{console.warn("Auth failed",e);_authFailed=true;return null;});
let GK="";

// === Offline persistence with AES-GCM encryption ===
const _aesSalt=new TextEncoder().encode("mak_aes_unit-e-1d07b");
let _aesKey=null;
async function _getAesKey(){
  if(_aesKey)return _aesKey;
  const km=await crypto.subtle.importKey("raw",_aesSalt,"PBKDF2",false,["deriveKey"]);
  _aesKey=await crypto.subtle.deriveKey({name:"PBKDF2",salt:_aesSalt,iterations:100000,hash:"SHA-256"},km,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
  return _aesKey;
}
async function _aesEnc(s){
  const key=await _getAesKey(),iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,new TextEncoder().encode(s));
  const buf=new Uint8Array(12+ct.byteLength);buf.set(iv);buf.set(new Uint8Array(ct),12);
  return btoa(String.fromCharCode(...buf));
}
async function _aesDec(s){
  try{const raw=Uint8Array.from(atob(s),c=>c.charCodeAt(0));
  const iv=raw.slice(0,12),ct=raw.slice(12);
  const key=await _getAesKey();
  const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,ct);
  return new TextDecoder().decode(pt);}catch(e){return null;}
}
// Legacy XOR decode for migration
const _ek="mak_"+btoa(location.hostname).slice(0,8);
function _xorDec(s){try{const d=atob(s),k=_ek;let r="";for(let i=0;i<d.length;i++)r+=String.fromCharCode(d.charCodeAt(i)^k.charCodeAt(i%k.length));return r;}catch(e){return null;}}

const LS={
  async save(k,v){try{const enc=await _aesEnc(JSON.stringify(v));localStorage.setItem("mak_"+k,enc);}catch(e){}},
  async load(k){try{const v=localStorage.getItem("mak_"+k);if(!v)return null;
    // Try AES-GCM first
    let d=await _aesDec(v);if(d){try{return JSON.parse(d);}catch(e){}}
    // Fallback: legacy XOR migration
    d=_xorDec(v);if(d){try{const parsed=JSON.parse(d);LS.save(k,parsed);return parsed;}catch(e){}}
    // Last resort: unencrypted
    try{return JSON.parse(v);}catch(e2){return null;}
  }catch(e){return null;}},
  async queueOp(op){const q=await LS.load("queue")||[];q.push(op);await LS.save("queue",q);},
  async getQueue(){return await LS.load("queue")||[];},
  async clearQueue(){await LS.save("queue",[]);}
};

async function _offlineUpdate(uid,key,data){
  const cached=await LS.load("patients_"+uid)||{};cached[key]=data;LS.save("patients_"+uid,cached);
  S.patients=Object.entries(cached).map(([k,v])=>({...v,_k:k}));
  const all=await LS.load("allData")||{};if(!all[uid])all[uid]={};all[uid][key]=data;LS.save("allData",all);S.allData=all;
}
async function _offlineRemove(uid,key){
  const cached=await LS.load("patients_"+uid)||{};delete cached[key];LS.save("patients_"+uid,cached);
  S.patients=Object.entries(cached).map(([k,v])=>({...v,_k:k}));
  const all=await LS.load("allData")||{};if(all[uid])delete all[uid][key];LS.save("allData",all);S.allData=all;
}
async function syncQueue(){
  const q=await LS.getQueue();if(!q.length)return;
  const failed=[];
  for(const op of q){
    try{
      if(op.type==="set")await set(ref(db,op.path),op.data);
      else if(op.type==="remove")await remove(ref(db,op.path));
      else if(op.type==="push")await push(ref(db,op.path),op.data);
    }catch(e){failed.push(op);}
  }
  await LS.save("queue",failed);
  if(q.length>failed.length)toast("Synced "+(q.length-failed.length)+" changes");
}

const I={
back:'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="15 18 9 12 15 6"/></svg>',
plus:'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>',
save:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>',
trash:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6M9 6V4h6v2"/></svg>',
cam:'<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>',
cog:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
lock:'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
eye:'<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
eyeOff:'<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><line x1="1" y1="1" x2="23" y2="23"/></svg>',
user:'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="8" r="4"/><path d="M12 14c-5 0-8 2.5-8 5v2h16v-2c0-2.5-3-5-8-5z"/></svg>',
dl:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
chk:'<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>'
};

const CC={1:{label:"Green",cls:"green"},2:{label:"Yellow",cls:"yellow"},3:{label:"Red",cls:"red"},4:{label:"Critical",cls:"critical"}};
const cc=c=>CC[c]||CC[4];
const _testIOS=window.location.search.includes("testios");
const _isIOS=_testIOS||/iphone|ipad|ipod/i.test(navigator.userAgent);
const _isStandalone=!_testIOS&&(window.navigator.standalone||window.matchMedia("(display-mode:standalone)").matches);
const installSteps=_isIOS?[
  {title:"Step 1 · Tap the Share button",desc:"Tap the Share icon (square with up arrow) at the bottom of Safari."},
  {title:"Step 2 · Add to Home Screen",desc:"Scroll down and tap “Add to Home Screen”."},
  {title:"Step 3 · Confirm",desc:"Tap “Add” in the top right. MedEvac will appear on your home screen as a full-screen app."}
]:[
  {title:"Step 1 · Open browser menu",desc:"Tap the three-dot menu (⋮) in the top right of your browser."},
  {title:"Step 2 · Choose Install app",desc:"From the menu pick “Add to Home screen” or “Install app”."},
  {title:"Step 3 · Confirm and test",desc:"Tap Add/Install, then find the MedEvac icon on your home screen."}
];
const installGuideKey="mk_install_guide_shown";

function renderInstallGuide(){
  const el=document.getElementById("install-guide-steps");
  if(!el)return;
  el.innerHTML=installSteps.map((s,i)=>'<div class="install-guide__step active"><div class="install-guide__step-num">'+(i+1)+'</div><div class="install-guide__step-text"><div class="install-guide__step-title">'+s.title.replace(/^Step \d+ \u00b7 /,"")+'</div><div class="install-guide__step-desc">'+s.desc+'</div></div></div>').join("");
  const hint=document.getElementById("install-guide-hint");
  if(hint)hint.textContent=_isIOS?"No app store needed \u2014 it\u2019s a web app that works like a native app.":"One tap install \u2014 no app store needed.";
}

function showInstallGuide(force=false){
  const guide=document.getElementById("install-guide");
  if(!guide)return;
  if(!force&&!installSteps.length)return;
  if(!force&&localStorage.getItem(installGuideKey))return;
  renderInstallGuide();
  guide.classList.add("show");
  localStorage.setItem(installGuideKey,"1");
}

function hideInstallGuide(){
  const guide=document.getElementById("install-guide");
  if(guide)guide.classList.remove("show");
}

function openInstallPrompt(){
  if(_dp){
    _dp.prompt();
    _dp.userChoice.then(()=>dismissInstall()).catch(()=>{});
    hideInstallGuide();
    return;
  }
  const hint=document.getElementById("install-guide-hint");
  if(!hint)return;
  if(/iphone|ipad|ipod/i.test(navigator.userAgent))hint.textContent="Tap Share > Add to Home Screen > Add.";
  else hint.textContent="Open the browser menu (three dots) and choose Add to Home screen.";
}

let S={screen:"home",unit:null,patients:[],allData:{},pinStatus:{},filter:"all",search:"",online:navigator.onLine,editP:null,editCode:null,addCode:null,pinTarget:null,pinVal:"",pinError:false,pinFails:0,pinLockUntil:0,ocrImg:null,ocrB64:null,ocrResults:[],ocrSel:[],ocrLoading:false,adminTab:"overview",showCivil:{},_bp:false,adminPin:""};
async function listenUnit(uid){if(S.unit)off(ref(db,"patients/"+S.unit));S.unit=uid;
  // Load cached data immediately
  const cached=await LS.load("patients_"+uid);
  S.patients=cached?Object.entries(cached).map(([k,v])=>({...v,_k:k})):[];
  if(S.screen==="ward")render();
  onValue(ref(db,"patients/"+uid),snap=>{const raw=snap.val()||{};LS.save("patients_"+uid,raw);S.patients=Object.entries(raw).map(([k,v])=>({...v,_k:k}));if(S.screen==="ward")render();if(S._bp&&S.patients.length>0){S._bp=false;setTimeout(()=>{try{backupPNG();}catch(e){console.warn("Backup failed",e);}},500);}});}
let _listenAllDone=false;
async function listenAll(){
  if(_listenAllDone)return;_listenAllDone=true;
  // Load cached data immediately for instant offline render
  const cachedAll=await LS.load("allData");if(cachedAll){S.allData=cachedAll;}
  onValue(ref(db,"patients"),snap=>{S.allData=snap.val()||{};LS.save("allData",S.allData);if(S.screen==="admin"||S.screen==="home")render();});
  // Fetch which units have PINs configured (no PIN values exposed)
  try{const r=await fnHasPins();S.pinStatus=r.data||{};}catch(e){console.warn("hasPins failed",e);}
}

function esc(s){if(!s)return"";const d=document.createElement("div");d.textContent=s;return d.innerHTML;}
// PIN verification and hashing moved to Cloud Functions (server-side only)
function audit(action,unit,detail){try{push(ref(db,"audit"),{action,unit:unit||"",detail:detail||"",ts:Date.now(),uid:_authUid||"anon",ua:navigator.userAgent.slice(0,80)});}catch(e){}}
const $=id=>document.getElementById(id);
const app=$("app");
function toast(m,t="ok"){const e=$("toast");e.className="toast "+t;e.textContent=m;requestAnimationFrame(()=>requestAnimationFrame(()=>e.classList.add("show")));clearTimeout(window._tt);window._tt=setTimeout(()=>e.classList.remove("show"),2500);}
function mask(c){if(!c||c.length<6)return c||"";return c.slice(0,3)+"\u2022".repeat(c.length-6)+c.slice(-3);}
function filtered(){let l=[...S.patients];if(S.filter==="1")l=l.filter(p=>p.code==1);else if(S.filter==="2")l=l.filter(p=>p.code==2);else if(S.filter==="r")l=l.filter(p=>p.code>=3);if(S.search){const q=S.search.toLowerCase();l=l.filter(p=>(p.name||"").toLowerCase().includes(q)||(p.civil||"").includes(q)||(p.ward||"").toLowerCase().includes(q));}return l.sort((a,b)=>b.code-a.code);}
function confirm2(title,msg){return new Promise(res=>{const r=$("cr");r.innerHTML='<div class="c-overlay"><div class="modal"><div style="font-size:15px;font-weight:800;margin-bottom:6px">'+esc(title)+'</div><div style="font-size:12px;color:var(--muted);margin-bottom:20px">'+esc(msg)+'</div><div style="display:flex;gap:8px"><button class="btn2" id="cn" style="flex:1">Cancel</button><button class="btnd" id="cy" style="flex:1">'+I.trash+' Delete</button></div></div></div>';$("cy").addEventListener("click",()=>{r.innerHTML="";res(true);});$("cn").addEventListener("click",()=>{r.innerHTML="";res(false);});});}

const TO=5*60*1000;let _tmr;
function _ul(){$("tr").innerHTML="";S.screen="home";S.unit=null;S.patients=[];S.showCivil={};render();}
function resetT(){clearTimeout(_tmr);if(S.screen!=="home"&&S.screen!=="pin")_tmr=setTimeout(()=>{$("tr").innerHTML='<div class="t-overlay"><div class="modal"><div style="width:52px;height:52px;border-radius:16px;background:linear-gradient(135deg,var(--acc),#0891b2);display:flex;align-items:center;justify-content:center;margin:0 auto 18px;box-shadow:0 8px 32px rgba(6,182,212,.2)"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div><div style="font-size:16px;font-weight:800;margin-bottom:6px">Session Expired</div><div style="font-size:12px;color:var(--muted);margin-bottom:22px">Locked for privacy.</div><button class="btn" id="ul-btn">Return Home</button></div></div>';setTimeout(()=>{const b=$("ul-btn");if(b)b.addEventListener("click",_ul);},0);},TO);}
["click","touchstart","keydown","scroll"].forEach(e=>document.addEventListener(e,resetT,{passive:true}));

const _pb=$("pb");
document.addEventListener("visibilitychange",()=>{if(document.hidden&&S.screen!=="home")_pb.classList.add("show");else _pb.classList.remove("show");});
window.addEventListener("focus",()=>_pb.classList.remove("show"));
document.addEventListener("contextmenu",e=>{if(S.screen!=="home")e.preventDefault();});
window.addEventListener("beforeunload",()=>{S.patients=[];S.allData={};S.editP=null;});

function backupPNG(){
  if(!S.unit||!S.patients.length)return;const pts=[...S.patients].sort((a,b)=>b.code-a.code);
  const cols=["#","Name","Civil ID","Nat","Ward","Code","Notes"],rows=pts.map((p,i)=>[""+(i+1),p.name||"",p.civil||"",p.nat||"",p.ward||"",""+p.code,p.notes||""]);
  const cv=document.createElement("canvas"),ctx=cv.getContext("2d"),fs=14,pad=10,rh=fs+pad*2,hh=rh+4,cw=[40,160,130,70,70,50,140],tw=cw.reduce((a,b)=>a+b)+20,th=50+hh+rows.length*rh+20;
  cv.width=tw;cv.height=th;ctx.fillStyle="#0f172a";ctx.fillRect(0,0,tw,th);
  ctx.fillStyle="#38bdf8";ctx.font="bold 18px Inter,sans-serif";ctx.textAlign="right";ctx.textBaseline="middle";
  ctx.fillText("Unit "+S.unit[0]+" - "+(S.unit.endsWith("_F")?"F":"M"),tw-10,20);
  ctx.fillStyle="#94a3b8";ctx.font="12px Inter,sans-serif";ctx.fillText(new Date().toISOString().slice(0,16).replace("T"," "),tw-10,40);
  let y=50;ctx.fillStyle="#1e293b";ctx.fillRect(10,y,tw-20,hh);ctx.fillStyle="#93c5fd";ctx.font="bold "+fs+"px Inter,sans-serif";let x=tw-10;
  cols.forEach((c,i)=>{ctx.fillText(c,x-4,y+hh/2);x-=cw[i];});y+=hh;
  const clr={1:"#10b981",2:"#f59e0b",3:"#ef4444",4:"#ef4444"};
  rows.forEach((row,ri)=>{ctx.fillStyle=ri%2?"#141c2e":"#0f172a";ctx.fillRect(10,y,tw-20,rh);ctx.font=fs+"px Inter,sans-serif";x=tw-10;row.forEach((cell,ci)=>{ctx.fillStyle=ci===5?clr[+cell]||"#e2e8f0":"#e2e8f0";let t=cell;const mw=cw[ci]-8;if(ctx.measureText(t).width>mw){while(ctx.measureText(t+"\u2026").width>mw&&t.length>1)t=t.slice(0,-1);t+="\u2026";}ctx.fillText(t,x-4,y+rh/2);x-=cw[ci];});y+=rh;});
  const a=document.createElement("a");a.href=cv.toDataURL("image/png");a.download="MedEvac_"+S.unit+".png";document.body.appendChild(a);a.click();document.body.removeChild(a);audit("backup_export",S.unit,S.patients.length+" patients");toast("Backup saved");
}

function render(){
  try{let h="";const s=S.screen;
  if(s==="home")h=vHome();else if(s==="pin")h=vPin();else if(s==="ward")h=vWard();
  else if(s==="detail")h=vDetail();else if(s==="add")h=vAdd();else if(s==="admin")h=vAdmin();
  app.innerHTML=h;bindAll();resetT();}catch(e){console.error(e);}
}

function vHome(){
  const cnt={};["A","B","C","D","E"].forEach(u=>["M","F"].forEach(g=>{cnt[u+"_"+g]=Object.keys(S.allData[u+"_"+g]||{}).length;}));
  const total=Object.values(cnt).reduce((a,b)=>a+b,0);
  return'<div class="screen"><div class="hdr"><div class="hdr-c"><h1>MedEvac</h1><p>Mubarak Al-Kabeer Hospital</p></div><div class="badge '+(_authFailed?"badge-off":S.online?"badge-on":"badge-off")+'"><div class="ldot"></div>'+(_authFailed?"Auth Error":S.online?"Online":"Offline")+'</div><button class="hbtn" id="ba">'+I.cog+'</button></div><div class="sp" style="padding:14px 16px 100px"><div class="hero"><div style="display:flex;justify-content:space-between;margin-bottom:6px;position:relative;z-index:1"><span style="font-size:10px;opacity:.5;font-weight:700;text-transform:uppercase;letter-spacing:1px">Total Patients</span><span style="font-size:9px;opacity:.25;font-weight:500">'+new Date().toLocaleDateString("en",{month:"short",day:"numeric",year:"numeric"})+'</span></div><div style="font-size:44px;font-weight:900;letter-spacing:-2px;position:relative;z-index:1;background:linear-gradient(135deg,#fff 0%,rgba(255,255,255,.7) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent">'+total+'</div><div style="font-size:11px;opacity:.25;margin-top:4px;font-weight:500;position:relative;z-index:1">Across all units</div></div>'+["A","B","C","D","E"].map(u=>'<div class="uc"><div class="uh"><span>Unit '+u+'</span><span>'+(cnt[u+"_M"]+cnt[u+"_F"])+'</span></div><div class="ub"><div class="ubtn female" data-unit="'+u+'_F"><div class="ubtn-ico">'+I.user+'</div><div class="ubtn-name">Female</div><div class="ubtn-cnt">'+cnt[u+"_F"]+'</div></div><div class="ubtn male" data-unit="'+u+'_M"><div class="ubtn-ico">'+I.user+'</div><div class="ubtn-name">Male</div><div class="ubtn-cnt">'+cnt[u+"_M"]+'</div></div></div></div>').join("")+'</div></div>';
}

function vPin(){
  const isA=S.pinTarget==="ADMIN",u=["A","B","C","D","E"].find(u=>S.pinTarget===u+"_M"||S.pinTarget===u+"_F"),g=S.pinTarget?.endsWith("_M")?"Male":"Female";
  return'<div class="screen"><div class="hdr"><button class="hbtn" id="bb">'+I.back+'</button><div class="hdr-c" style="text-align:center"><h1>'+(isA?"Admin":"Unit "+u+" \u2014 "+g)+'</h1></div><div style="width:36px"></div></div><div class="pin-body"><div class="pin-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div><div style="font-size:13px;color:var(--muted);font-weight:600;margin-bottom:28px">Enter PIN</div><div class="pin-dots">'+[0,1,2,3].map(i=>'<div class="pdot'+(i<S.pinVal.length?" f":"")+'"></div>').join("")+'</div>'+(S.pinError?'<div class="pin-err">Wrong PIN</div>':'')+'<div class="pkeys">'+[[1,2,3],[4,5,6],[7,8,9],["",0,"\u232b"]].map(r=>r.map(k=>k===""?'<div></div>':'<button class="pkey'+(k==="\u232b"?" del":"")+'" data-pin="'+k+'">'+k+'</button>').join("")).join("")+'</div></div></div>';
}

function vWard(){
  const list=filtered(),t=S.patients.length,g=S.patients.filter(p=>p.code==1).length,y=S.patients.filter(p=>p.code==2).length,r=S.patients.filter(p=>p.code>=3).length,u=S.unit[0],isF=S.unit.endsWith("_F");
  return'<div class="screen"><div class="hdr"><button class="hbtn" id="bb">'+I.back+'</button><div class="hdr-c" style="text-align:center"><h1>Unit '+u+' \u2014 '+(isF?"Female":"Male")+'</h1><p>Mubarak Al-Kabeer</p></div><button class="hbtn" id="bdl">'+I.dl+'</button></div><div class="offbar'+(S.online?"":" show")+'">Offline</div><div class="stats-row"><div class="stat ca'+(S.filter==="all"?" act":"")+'" data-filt="all"><div class="n">'+t+'</div><div class="l">All</div></div><div class="stat cg'+(S.filter==="1"?" act":"")+'" data-filt="1"><div class="n">'+g+'</div><div class="l">Green</div></div><div class="stat cy'+(S.filter==="2"?" act":"")+'" data-filt="2"><div class="n">'+y+'</div><div class="l">Yellow</div></div><div class="stat cr'+(S.filter==="r"?" act":"")+'" data-filt="r"><div class="n">'+r+'</div><div class="l">Red</div></div></div><div class="sbar"><input class="sinp" id="si" placeholder="Search..." value="'+esc(S.search)+'"><button class="abtn" id="badd">'+I.plus+'</button></div><div class="plist" id="pl">'+(list.length?list.map(p=>{const c=cc(p.code),cv=S.showCivil[p._k]?p.civil:mask(p.civil);return'<div class="pc '+c.cls+'" data-key="'+p._k+'"><div class="ps"></div><div class="pb"><div class="bn">'+p.code+'</div><div class="bt">'+c.label+'</div></div><div class="pi"><div class="pn">'+esc(p.name)+'</div><div class="pm"><span class="ch">'+esc(cv)+'</span><span class="ch">'+esc(p.nat)+'</span>'+(p.notes?'<span class="ch">'+esc(p.notes)+'</span>':'')+'</div></div><div class="pw">'+esc(p.ward)+'</div></div>';}).join(""):'<div style="text-align:center;padding:60px 20px;color:var(--muted)">No patients</div>')+'</div></div>';
}

function vDetail(){
  const p=S.editP,cv=S.showCivil[p._k]?p.civil:mask(p.civil);
  return'<div class="screen"><div class="hdr"><button class="hbtn" id="bb">'+I.back+'</button><div class="hdr-c" style="margin:0 8px"><h1 style="font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(p.name)+'</h1><p>Details</p></div></div><div class="sp" style="padding:14px 16px 100px"><div style="background:var(--card);border:1px solid var(--glass-border);border-radius:var(--radius);padding:0 16px;margin-bottom:18px;box-shadow:var(--shadow);backdrop-filter:blur(16px)"><div class="ir"><span style="color:var(--muted);font-weight:600">Civil ID</span><span style="font-weight:700;display:flex;align-items:center;gap:6px">'+esc(cv)+'<button style="background:none;border:none;cursor:pointer;color:var(--muted);padding:2px" id="tc">'+(S.showCivil[p._k]?I.eyeOff:I.eye)+'</button></span></div><div class="ir"><span style="color:var(--muted);font-weight:600">Nationality</span><span style="font-weight:700">'+esc(p.nat||"\u2014")+'</span></div></div><div class="fg"><label class="fl">Ward / Bed</label><input class="fi" id="ew" value="'+esc(p.ward||"")+'"></div><div class="fg"><label class="fl">Severity Code</label><div class="cg2">'+[1,2,3,4].map(c=>'<div class="co'+(S.editCode==c?" s"+c:"")+'" data-cpick="e" data-code="'+c+'"><div class="cn">'+c+'</div><div class="ct">'+cc(c).label+'</div></div>').join("")+'</div></div><div class="fg"><label class="fl">Notes</label><input class="fi" id="en" placeholder="Notes..." value="'+esc(p.notes||"")+'"></div><div style="display:flex;gap:8px"><button class="btn" id="bs">'+I.save+' Save</button><button class="btnd" id="bd">'+I.trash+'</button></div></div></div>';
}

function vAdd(){
  return'<div class="screen"><div class="hdr"><button class="hbtn" id="bb">'+I.back+'</button><div class="hdr-c" style="text-align:center"><h1>Add Patient</h1></div><div style="width:36px"></div></div><div class="sp" style="padding:14px 14px 100px"><div class="fg"><label class="fl">Full Name *</label><input class="fi" id="an" placeholder="Name" autocomplete="off"></div><div class="fg"><label class="fl">Civil ID *</label><input class="fi" id="ac" placeholder="Civil ID" inputmode="numeric" autocomplete="off"></div><div class="fg"><label class="fl">Nationality</label><input class="fi" id="at" placeholder="Nationality" autocomplete="off"></div><div class="fg"><label class="fl">Ward / Bed *</label><input class="fi" id="aw" placeholder="e.g. W21R8" autocomplete="off"></div><div class="fg"><label class="fl">Severity Code *</label><div class="cg2">'+[1,2,3,4].map(c=>'<div class="co'+(S.addCode==c?" s"+c:"")+'" data-cpick="a" data-code="'+c+'"><div class="cn">'+c+'</div><div class="ct">'+cc(c).label+'</div></div>').join("")+'</div></div><div class="fg"><label class="fl">Notes</label><input class="fi" id="ao" placeholder="Notes..." autocomplete="off"></div><button class="btn" id="bsa">'+I.plus+' Add Patient</button></div></div>';
}

function vAdmin(){
  const tabs=[{id:"overview",l:"Overview"},{id:"ocr",l:"OCR"},{id:"pins",l:"Security"}];let c="";
  if(S.adminTab==="overview")c=["A","B","C","D","E"].map(u=>{const m=Object.values(S.allData[u+"_M"]||{}),f=Object.values(S.allData[u+"_F"]||{}),all=[...m,...f],g=all.filter(p=>p.code==1).length,y=all.filter(p=>p.code==2).length,r=all.filter(p=>p.code>=3).length;return'<div style="background:var(--card);border:1px solid var(--glass-border);border-radius:var(--radius);margin-bottom:10px;overflow:hidden;box-shadow:var(--shadow);backdrop-filter:blur(16px)"><div style="background:linear-gradient(135deg,rgba(15,23,42,.9),rgba(30,41,59,.8));padding:14px 18px;color:#fff;font-weight:800;font-size:13px;display:flex;justify-content:space-between;letter-spacing:-.2px"><span>Unit '+u+'</span><span style="opacity:.3;font-size:11px">'+all.length+'</span></div><div style="display:grid;grid-template-columns:repeat(4,1fr);padding:14px;text-align:center"><div><div style="font-size:20px;font-weight:900;color:var(--acc)">'+all.length+'</div><div style="font-size:7px;color:var(--muted);font-weight:700;text-transform:uppercase;margin-top:4px;letter-spacing:.8px">All</div></div><div><div style="font-size:20px;font-weight:900;color:var(--g)">'+g+'</div><div style="font-size:7px;color:var(--muted);font-weight:700;text-transform:uppercase;margin-top:4px;letter-spacing:.8px">Green</div></div><div><div style="font-size:20px;font-weight:900;color:var(--y)">'+y+'</div><div style="font-size:7px;color:var(--muted);font-weight:700;text-transform:uppercase;margin-top:4px;letter-spacing:.8px">Yellow</div></div><div><div style="font-size:20px;font-weight:900;color:var(--r)">'+r+'</div><div style="font-size:7px;color:var(--muted);font-weight:700;text-transform:uppercase;margin-top:4px;letter-spacing:.8px">Red</div></div></div></div>';}).join("");
  else if(S.adminTab==="ocr")c='<div class="ocr-drop" id="oz"><input type="file" id="of" accept="image/*" multiple style="display:none"><div style="margin-bottom:12px;opacity:.5">'+I.cam+'</div><div style="font-weight:800;font-size:14px;margin-bottom:4px">Capture / Upload</div><div style="font-size:12px;color:var(--muted)">Select one or more images</div></div>'+(S.ocrImg?'<img src="'+S.ocrImg+'" style="width:100%;border-radius:12px;margin:10px 0;max-height:160px;object-fit:cover">':'')+(S.ocrLoading?'<div style="text-align:center;padding:20px"><div class="loader"></div><p style="margin-top:10px;color:var(--muted);font-size:12px">Analyzing...</p></div>':'')+(S.ocrResults.length?'<div style="margin-top:10px"><div class="fg"><select class="fi" id="ou">'+["A","B","C","D","E"].flatMap(u=>['<option value="'+u+'_M">Unit '+u+' M</option>','<option value="'+u+'_F">Unit '+u+' F</option>']).join("")+'</select></div>'+S.ocrResults.map((p,i)=>'<div class="ocr-row"><div class="ocr-chk'+(S.ocrSel.includes(i)?" on":"")+'" data-ocr="'+i+'">'+(S.ocrSel.includes(i)?I.chk:"")+'</div><div style="flex:1;min-width:0"><div style="font-weight:700;font-size:13px">'+esc(p.name||"-")+'</div><div style="font-size:11px;color:var(--muted)">'+esc(p.civil||"")+'</div></div></div>').join("")+'<div style="display:flex;gap:8px;margin-top:10px"><button class="btn2" id="osa">All</button><button class="btn" id="oi"'+(S.ocrSel.length?"":" disabled")+'>Import '+S.ocrSel.length+'</button></div></div>':'');
  else if(S.adminTab==="pins"){const labels={A_M:"A Male",A_F:"A Female",B_M:"B Male",B_F:"B Female",C_M:"C Male",C_F:"C Female",D_M:"D Male",D_F:"D Female",E_M:"E Male",E_F:"E Female",ADMIN:"Admin"};c='<div style="background:var(--rbg);border:1px solid var(--rbd);border-radius:var(--radius-xs);padding:12px;margin-bottom:14px;font-size:11px;color:var(--r);font-weight:600;display:flex;gap:8px;letter-spacing:.2px">'+I.lock+' Keep PINs secret</div>'+Object.entries(labels).map(([uid,l])=>'<div style="background:var(--card);border:1px solid var(--glass-border);border-radius:var(--radius-xs);padding:12px;margin-bottom:8px;display:flex;align-items:center;gap:10px;box-shadow:var(--shadow);backdrop-filter:blur(12px)"><div style="flex:1;font-weight:700;font-size:13px">'+l+'</div><input class="fi" id="p-'+uid+'" placeholder="'+(S.pinStatus[uid]?"\u2022\u2022\u2022\u2022":"New")+'" maxlength="6" type="password" style="width:70px;text-align:center;font-size:16px;font-weight:900;letter-spacing:3px;padding:8px" autocomplete="off"><button class="btn" style="width:auto;padding:8px 12px" data-sp="'+uid+'">'+I.save+'</button></div>').join("");}
  return'<div class="screen"><div class="hdr"><button class="hbtn" id="bb">'+I.back+'</button><div class="hdr-c" style="text-align:center"><h1>Admin</h1></div><div style="width:36px"></div></div><div class="tabs">'+tabs.map(t=>'<div class="tab'+(S.adminTab===t.id?" act":"")+'" data-tab="'+t.id+'">'+t.l+'</div>').join("")+'</div><div class="sp" style="padding:10px 12px 80px">'+c+'</div></div>';
}

function bindAll(){
  document.querySelectorAll("[data-unit]").forEach(b=>b.addEventListener("click",()=>{S.pinTarget=b.dataset.unit;S.pinVal="";S.pinError=false;S.screen="pin";render();}));
  const ba=$("ba");if(ba)ba.addEventListener("click",()=>{S.pinTarget="ADMIN";S.pinVal="";S.pinError=false;S.screen="pin";render();});
  const bb=$("bb");if(bb)bb.addEventListener("click",()=>{if(S.screen==="ward"||S.screen==="admin"){S.screen="home";S.showCivil={};render();}else if(S.screen==="detail"||S.screen==="add"){S.screen="ward";render();}else if(S.screen==="pin"){S.screen="home";render();}});
  const bdl=$("bdl");if(bdl)bdl.addEventListener("click",()=>backupPNG());
  const tc=$("tc");if(tc&&S.editP)tc.addEventListener("click",e=>{e.stopPropagation();const show=!S.showCivil[S.editP._k];S.showCivil[S.editP._k]=show;if(show)audit("view_civil",S.unit,S.editP.name);render();});
  document.querySelectorAll("[data-pin]").forEach(k=>k.addEventListener("click",()=>{const v=k.dataset.pin;if(v==="\u232b")S.pinVal=S.pinVal.slice(0,-1);else if(S.pinVal.length<6)S.pinVal+=v;S.pinError=false;if(S.pinVal.length===4||S.pinVal.length===6)checkPin();else render();}));
  document.querySelectorAll("[data-filt]").forEach(f=>f.addEventListener("click",()=>{S.filter=f.dataset.filt;render();}));
  const si=$("si");if(si)si.addEventListener("input",e=>{S.search=e.target.value;render();});
  document.querySelectorAll(".pc").forEach(c=>c.addEventListener("click",()=>{const p=S.patients.find(x=>x._k===c.dataset.key);if(p){S.editP=p;S.editCode=p.code;S.screen="detail";render();}}));
  document.querySelectorAll("[data-cpick='e']").forEach(c=>c.addEventListener("click",()=>{S.editCode=+c.dataset.code;render();}));
  document.querySelectorAll("[data-cpick='a']").forEach(c=>c.addEventListener("click",()=>{S.addCode=+c.dataset.code;render();}));
  const bs=$("bs");if(bs)bs.addEventListener("click",async()=>{const ward=$("ew").value.trim(),notes=$("en").value.trim();if(ward.length>30){toast("Ward too long","err");return;}if(notes.length>500){toast("Notes too long","err");return;}bs.disabled=true;const data={...S.editP,ward,code:S.editCode,notes,ts:Date.now()};delete data._k;try{await set(ref(db,"patients/"+S.unit+"/"+S.editP._k),data);audit("edit",S.unit,data.name);toast("Saved");}catch(e){await LS.queueOp({type:"set",path:"patients/"+S.unit+"/"+S.editP._k,data});await _offlineUpdate(S.unit,S.editP._k,data);toast("Saved offline","ok");}S.screen="ward";render();});
  const bd=$("bd");if(bd)bd.addEventListener("click",async()=>{if(!await confirm2("Delete?","Remove \""+esc(S.editP.name)+"\"?"))return;try{await remove(ref(db,"patients/"+S.unit+"/"+S.editP._k));audit("delete",S.unit,S.editP.name);toast("Deleted");}catch(e){await LS.queueOp({type:"remove",path:"patients/"+S.unit+"/"+S.editP._k});await _offlineRemove(S.unit,S.editP._k);toast("Deleted offline","ok");}S.screen="ward";render();});
  const badd=$("badd");if(badd)badd.addEventListener("click",()=>{S.addCode=null;S.screen="add";render();});
  const bsa=$("bsa");if(bsa)bsa.addEventListener("click",async()=>{const n=$("an").value.trim(),c=$("ac").value.trim(),w=$("aw").value.trim(),nat=$("at").value.trim(),notes=$("ao").value.trim();if(!n||!c||!w||!S.addCode){toast("Fill required","err");return;}
    if(n.length>200){toast("Name too long (max 200)","err");return;}
    if(c.length>20){toast("Civil ID too long","err");return;}
    if(!/^\d+$/.test(c)){toast("Civil ID must be numeric","err");return;}
    if(w.length>30){toast("Ward too long","err");return;}
    if(nat.length>50){toast("Nationality too long","err");return;}
    if(notes.length>500){toast("Notes too long (max 500)","err");return;}
    // Duplicate detection by Civil ID
    const dup=S.patients.find(p=>p.civil&&p.civil===c);if(dup&&!confirm("Patient with Civil ID "+c+" already exists ("+dup.name+"). Add anyway?")){return;}bsa.disabled=true;const data={name:n,civil:c,nat,ward:w,code:S.addCode,notes,ts:Date.now()};try{await push(ref(db,"patients/"+S.unit),data);audit("add",S.unit,data.name);toast("Added");}catch(e){const offKey="off_"+Date.now();await LS.queueOp({type:"push",path:"patients/"+S.unit,data});await _offlineUpdate(S.unit,offKey,data);toast("Added offline","ok");}S.screen="ward";render();});
  document.querySelectorAll("[data-tab]").forEach(t=>t.addEventListener("click",()=>{S.adminTab=t.dataset.tab;render();}));
  const oz=$("oz");if(oz)oz.addEventListener("click",()=>{const f=$("of");if(f)f.click();});
  const of_=$("of");if(of_)of_.addEventListener("change",handleOCR);
  document.querySelectorAll("[data-ocr]").forEach(c=>c.addEventListener("click",()=>{const i=+c.dataset.ocr;if(S.ocrSel.includes(i))S.ocrSel=S.ocrSel.filter(x=>x!==i);else S.ocrSel.push(i);render();}));
  const osa=$("osa");if(osa)osa.addEventListener("click",()=>{S.ocrSel=S.ocrSel.length===S.ocrResults.length?[]:S.ocrResults.map((_,i)=>i);render();});
  const oi=$("oi");if(oi)oi.addEventListener("click",importOCR);
  document.querySelectorAll("[data-sp]").forEach(b=>b.addEventListener("click",async()=>{const uid=b.dataset.sp,v=$("p-"+uid);const pv=v?v.value.trim():"";if(!pv||pv.length<4){toast("Min 4 digits","err");return;}if(!S.adminPin){toast("Admin session invalid","err");return;}try{await fnSetPin({adminPin:S.adminPin,unit:uid,newPin:pv});S.pinStatus[uid]=true;toast("Saved");}catch(e){toast(e.message||"Failed","err");}}));
}

async function checkPin(){
  // Client-side lockout (server also rate-limits)
  if(S.pinLockUntil>Date.now()){const secs=Math.ceil((S.pinLockUntil-Date.now())/1000);toast("Locked for "+secs+"s","err");S.pinVal="";render();return;}
  try{
    await fnVerifyPin({unit:S.pinTarget,pin:S.pinVal});
    // Success — server already logged audit
    S.pinFails=0;S.pinLockUntil=0;
    if(S.pinTarget==="ADMIN"){S.adminPin=S.pinVal;S.screen="admin";S.adminTab="overview";audit("admin_access","ADMIN","");await listenAll();}
    else{S.screen="ward";S.filter="all";S.search="";S._bp=true;await listenUnit(S.pinTarget);}
    render();
  }catch(e){
    const code=e.code||"";
    if(code==="functions/resource-exhausted"){S.pinLockUntil=Date.now()+60000;toast("Too many attempts. Locked.","err");}
    else if(code==="functions/permission-denied"||code==="functions/not-found"){
      S.pinFails++;if(S.pinFails>=5){S.pinLockUntil=Date.now()+60000*Math.min(S.pinFails-4,5);toast("Too many attempts. Locked.","err");}
    }else{toast("Error: "+(e.message||"offline"),"err");}
    S.pinError=true;S.pinVal="";render();
  }
}

function handleOCR(e){const files=Array.from(e.target.files);if(!files.length)return;S.ocrResults=[];S.ocrSel=[];S.ocrLoading=true;S.ocrImg=null;render();
const readFile=f=>new Promise((ok,no)=>{const r=new FileReader();r.onload=ev=>ok({data:ev.target.result.split(",")[1],mime:f.type,url:ev.target.result});r.onerror=no;r.readAsDataURL(f);});
(async()=>{try{const imgs=await Promise.all(files.map(readFile));S.ocrImg=imgs[0].url;render();
const content=[];imgs.forEach(im=>content.push({type:"image",source:{type:"base64",media_type:im.mime,data:im.data}}));
content.push({type:"text",text:'Extract ALL patients from these images. Return ONLY a JSON array: [{"name":"Full Name","civil":"Civil ID number","nat":"Nationality","ward":"Ward/bed info","code":1,"notes":"any notes"}]. code: 1=green,2=yellow,3=red,4=critical. If no patients found return [].'});
if(!GK){toast("API key missing","err");S.ocrLoading=false;render();return;}
const res=await fetch("https://api.anthropic.com/v1/messages",{method:"POST",headers:{"x-api-key":GK,"anthropic-version":"2023-06-01","content-type":"application/json","anthropic-dangerous-direct-browser-access":"true"},body:JSON.stringify({model:"claude-sonnet-4-20250514",max_tokens:4096,messages:[{role:"user",content}]})});
if(!res.ok){const errText=await res.text();console.error("Claude API error:",res.status,errText);toast("API error "+res.status+": check console","err");S.ocrLoading=false;render();return;}
const data=await res.json();console.log("Claude response:",JSON.stringify(data).slice(0,500));
const raw=data.content?.[0]?.text||"[]";const cleaned=raw.replace(/```json|```/g,"").trim();
S.ocrResults=JSON.parse(cleaned);if(!Array.isArray(S.ocrResults))S.ocrResults=[];
S.ocrSel=S.ocrResults.map((_,i)=>i);if(!S.ocrResults.length)toast("No patients found","err");
}catch(err){console.error("OCR error:",err);toast("OCR failed: "+err.message,"err");S.ocrResults=[];}
S.ocrLoading=false;render();e.target.value="";})();}

async function importOCR(){const uid=$("ou")?.value;if(!uid||!S.ocrSel.length)return;const b=$("oi");b.disabled=true;try{for(const i of S.ocrSel){const p=S.ocrResults[i];await push(ref(db,"patients/"+uid),{name:p.name||"",civil:p.civil||"",nat:p.nat||"",ward:p.ward||"",code:+p.code||2,notes:p.notes||"",ts:Date.now()});}audit("ocr_import",uid,S.ocrSel.length+" patients");toast("Imported "+S.ocrSel.length);S.ocrResults=[];S.ocrSel=[];S.ocrImg=null;render();}catch(e){toast("Failed","err");b.disabled=false;}}

let _dp=null;
window.addEventListener("beforeinstallprompt",e=>{
  e.preventDefault();
  _dp=e;
  if(!localStorage.getItem(installGuideKey))setTimeout(showInstallGuide,1500);
  if(!localStorage.getItem("mi"))setTimeout(()=>{
    const b=$("ibanner");
    if(b)b.classList.add("show");
  },3000);
});
// iOS Safari: animated walkthrough with Safari bar detection
function showIOSPrompt(){
  const p=$("pwa-wt");if(!p)return;
  const anim=$("wt-anim"),au=$("wt-arrow-up"),ad=$("wt-arrow-down");
  // Detect Safari bar position
  const vv=window.visualViewport;
  const barTop=vv&&vv.offsetTop>10;
  // Position overlay
  p.classList.remove("safari-top","safari-bottom");
  p.classList.add(barTop?"safari-top":"safari-bottom");
  if(au)au.style.display=barTop?"block":"none";
  if(ad)ad.style.display=barTop?"none":"block";
  // Build animated Safari mockup
  if(anim){
    const shareIcon='<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#007AFF" stroke-width="2" stroke-linecap="round"><path d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8"/><polyline points="16 6 12 2 8 6"/><line x1="12" y1="2" x2="12" y2="15"/></svg>';
    const addIcon='<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#007AFF" stroke-width="2" stroke-linecap="round"><rect x="3" y="3" width="18" height="18" rx="4"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>';
    const fingerSvg='<svg viewBox="0 0 24 24" fill="rgba(0,0,0,.6)" width="100%" height="100%"><path d="M12 2C9.8 2 8 3.8 8 6v6.5l-1.3-1.3c-.8-.8-2-.8-2.8 0s-.8 2 0 2.8l5.7 5.7c.4.4 1 .6 1.6.6H17c1.7 0 3-1.3 3-3v-5.5c0-1.1-.9-2-2-2s-2 .9-2 2V10c0-1.1-.9-2-2-2s-2 .9-2 2V6c0-2.2-1.8-4-4-4z"/></svg>';
    const barPos=barTop?"top":"bottom";
    const menuPos=barTop?"from-top":"from-bottom";
    anim.innerHTML='<div class="pwa-wt__safari'+(barTop?" top":"")+'">'
      +'<div style="width:140px;height:28px;background:rgba(0,0,0,.04);border-radius:8px"></div>'
      +'<div class="pwa-wt__share-btn" id="wt-share">'+shareIcon
      +'<div class="pwa-wt__finger" style="'+(barTop?"top":"bottom")+':0;right:-8px">'+fingerSvg+'</div></div>'
      +'</div>'
      +'<div class="pwa-wt__menu '+menuPos+'">'
      +'<div class="pwa-wt__mitem"><svg viewBox="0 0 24 24" fill="none" stroke="#8e8e93" stroke-width="2" width="16" height="16"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>Copy</div>'
      +'<div class="pwa-wt__mitem hl" style="position:relative">'+addIcon+'Add to Home Screen'
      +'<div class="pwa-wt__finger2" style="right:10px;top:50%;transform:translateY(-50%)">'+fingerSvg+'</div></div>'
      +'<div class="pwa-wt__mitem"><svg viewBox="0 0 24 24" fill="none" stroke="#8e8e93" stroke-width="2" width="16" height="16"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>Find on Page</div>'
      +'</div>';
  }
  p.style.display="block";
}
function hideIOSPrompt(){const p=$("pwa-wt");if(p)p.style.display="none";localStorage.setItem(installGuideKey,"1");}
const wtClose=$("wt-close");if(wtClose)wtClose.addEventListener("click",hideIOSPrompt);

if(_isIOS&&!_isStandalone&&(_testIOS||!localStorage.getItem(installGuideKey))){
  setTimeout(showIOSPrompt,2000);
}
const ib=$("ib-btn");if(ib)ib.addEventListener("click",()=>{if(_isIOS){showIOSPrompt();}else{showInstallGuide(true);}});
function dismissInstall(){const b=$("ibanner");if(b)b.classList.remove("show");localStorage.setItem("mi","1");}
const ibDismiss=$("ib-dismiss");if(ibDismiss)ibDismiss.addEventListener("click",dismissInstall);
window.addEventListener("online",()=>{S.online=true;render();syncQueue();});
window.addEventListener("offline",()=>{S.online=false;render();});
const installGuideNow=$("install-guide-now");
if(installGuideNow)installGuideNow.addEventListener("click",openInstallPrompt);
const installGuideClose=$("install-guide-close");
if(installGuideClose)installGuideClose.addEventListener("click",hideInstallGuide);
const installGuideEl=$("install-guide");
if(installGuideEl)installGuideEl.addEventListener("click",e=>{if(e.target===installGuideEl)hideInstallGuide();});

async function boot(){try{
  // Wait for anonymous auth before attaching Firebase listeners
  await _authP;
  // Fetch Gemini key after auth
  get(ref(db,"config/claudeKey")).then(s=>{if(s.exists())GK=s.val();}).catch(()=>{});
  await listenAll();S.screen="home";render();if(navigator.onLine)await syncQueue();
}catch(e){showFatal("Boot Error: "+e.message);}}
boot();

// Service Worker registration
if("serviceWorker" in navigator){
  navigator.serviceWorker.getRegistrations()
    .then(rs=>Promise.all(rs.map(r=>r.unregister())))
    .catch(()=>{})
    .finally(()=>{
      navigator.serviceWorker.register("/sw.js",{updateViaCache:"none"})
        .then(r=>r.update())
        .catch(err=>console.warn("Service worker registration failed",err));
    });
}