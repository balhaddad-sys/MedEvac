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
const fnOcrExtract=httpsCallable(fns,"ocrExtract");
const fnGetAuditLog=httpsCallable(fns,"getAuditLog");
let _authReady=false,_authUid=null;
onAuthStateChanged(auth,u=>{_authUid=u?u.uid:null;_authReady=true;});
let _authFailed=false;
const _authP=signInAnonymously(auth).catch(e=>{console.warn("Auth failed",e);_authFailed=true;return null;});

// One-time migration: split "ward" field into ward + room
async function migrateWardRoom(){
  await _authP;
  if(!_authUid){try{await signInAnonymously(auth);}catch(e){toast("Auth failed","err");return;}}
  const snap=await get(ref(db,"patients"));
  const data=snap.val();if(!data){toast("No data to migrate","err");return;}
  let count=0;
  const updates={};
  ["A","B","C","D","E"].forEach(u=>["M","F"].forEach(g=>{
    const uid=u+"_"+g;
    const patients=data[uid];if(!patients)return;
    Object.entries(patients).forEach(([key,p])=>{
      const raw=(p.ward||"").trim();
      if(!raw)return;
      // Already cleanly split? Skip if ward has no room info embedded
      if(p.room && !/\s/.test(raw) && !/R\d/i.test(raw))return;
      // Try to find W-number and R-number parts anywhere in the string
      const wMatch=raw.match(/(W\d+)/i);
      const rMatch=raw.match(/(R\d[\w\-]*)/i);
      if(wMatch){
        const newWard=wMatch[1].toUpperCase();
        const newRoom=rMatch?rMatch[1].toUpperCase():"";
        if(newWard!==p.ward||newRoom!==(p.room||"")){
          updates["patients/"+uid+"/"+key+"/ward"]=newWard;
          updates["patients/"+uid+"/"+key+"/room"]=newRoom;
          count++;
          console.log("Migrate:",raw,"->",newWard,"/",newRoom);
        }
      }
    });
  }));
  if(!count){toast("All records already migrated");return;}
  // Write each patient as a full object to respect Firebase rules
  const patientUpdates={};
  for(const [path,val] of Object.entries(updates)){
    // path is "patients/A_M/key/ward" or "patients/A_M/key/room"
    const parts=path.split("/");
    const pPath=parts[0]+"/"+parts[1]+"/"+parts[2]; // patients/uid/key
    const field=parts[3];
    if(!patientUpdates[pPath])patientUpdates[pPath]={uid:parts[1],key:parts[2],fields:{}};
    patientUpdates[pPath].fields[field]=val;
  }
  let ok=0,fail=0;
  for(const p of Object.values(patientUpdates)){
    const existing=data[p.uid]?.[p.key];
    if(!existing)continue;
    const updated={...existing,...p.fields};
    try{await set(ref(db,"patients/"+p.uid+"/"+p.key),updated);ok++;console.log("OK:",p.uid,p.key,p.fields);}catch(e){console.warn("Failed:",p.uid,p.key,e.message);fail++;}
  }
  toast("Migrated "+ok+" patients"+(fail?" ("+fail+" failed)":""));
  const newSnap=await get(ref(db,"patients"));
  S.allData=newSnap.val()||{};
  render();
}

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

let S={screen:"home",unit:null,patients:[],allData:{},pinStatus:{},filter:"all",search:"",online:navigator.onLine,editP:null,editCode:null,addCode:null,pinTarget:null,pinVal:"",pinError:false,pinOk:false,pinFails:0,pinLockUntil:0,ocrImg:null,ocrB64:null,ocrResults:[],ocrSel:[],ocrLoading:false,adminTab:"overview",showCivil:{},_bp:false,adminPin:"",expandedUnits:{},adminSearch:"",adminFilter:"all",_pinNeedsLayout:true};
async function listenUnit(uid){if(S.unit)off(ref(db,"patients/"+S.unit));S.unit=uid;
  // Load cached data immediately
  const cached=await LS.load("patients_"+uid);
  S.patients=cached?Object.entries(cached).map(([k,v])=>({...v,_k:k})):[];
  if(S.screen==="ward")render();
  let _unitDebounce;onValue(ref(db,"patients/"+uid),snap=>{const raw=snap.val()||{};LS.save("patients_"+uid,raw);S.patients=Object.entries(raw).map(([k,v])=>({...v,_k:k}));if(S.screen==="ward"){clearTimeout(_unitDebounce);_unitDebounce=setTimeout(()=>render(),100);}if(S._bp&&S.patients.length>0){S._bp=false;const hash=JSON.stringify(raw);const prev=localStorage.getItem("_bkHash_"+uid);if(hash!==prev){localStorage.setItem("_bkHash_"+uid,hash);setTimeout(()=>{try{backupPNG();}catch(e){console.warn("Backup failed",e);}},500);}}});}
let _listenAllDone=false;
async function listenAll(){
  if(_listenAllDone)return;_listenAllDone=true;
  // Load cached data immediately for instant offline render
  const cachedAll=await LS.load("allData");if(cachedAll){S.allData=cachedAll;}
  let _allDebounce;onValue(ref(db,"patients"),snap=>{S.allData=snap.val()||{};LS.save("allData",S.allData);if(S.screen==="admin"||S.screen==="home"){clearTimeout(_allDebounce);_allDebounce=setTimeout(()=>render(),100);}});
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
function filtered(){let l=[...S.patients];if(S.filter==="1")l=l.filter(p=>p.code==1);else if(S.filter==="2")l=l.filter(p=>p.code==2);else if(S.filter==="r")l=l.filter(p=>p.code>=3);if(S.search){const q=S.search.toLowerCase();l=l.filter(p=>(p.name||"").toLowerCase().includes(q)||(p.civil||"").includes(q)||(p.ward||"").toLowerCase().includes(q)||(p.room||"").toLowerCase().includes(q));}return l.sort((a,b)=>b.code-a.code);}
function confirm2(title,msg){return new Promise(res=>{const r=$("cr");r.innerHTML='<div class="c-overlay"><div class="modal"><div style="font-size:15px;font-weight:800;margin-bottom:6px">'+esc(title)+'</div><div style="font-size:12px;color:var(--muted);margin-bottom:20px">'+esc(msg)+'</div><div style="display:flex;gap:8px"><button class="btn2" id="cn" style="flex:1">Cancel</button><button class="btnd" id="cy" style="flex:1">'+I.trash+' Delete</button></div></div></div>';$("cy").addEventListener("click",()=>{r.innerHTML="";res(true);});$("cn").addEventListener("click",()=>{r.innerHTML="";res(false);});});}

const TO=5*60*1000;let _tmr;
function _wipeMemory(){S.patients=[];S.allData={};S.editP=null;S.adminPin=null;S.showCivil={};S.ocrResults=[];S.ocrSel=[];S.ocrImg=null;S._auditLog=null;}
function _ul(){$("tr").innerHTML="";_wipeMemory();S.screen="home";S.unit=null;render();}
function resetT(){clearTimeout(_tmr);if(S.screen!=="home"&&S.screen!=="pin")_tmr=setTimeout(()=>{_wipeMemory();$("tr").innerHTML='<div class="t-overlay"><div class="modal"><div style="width:52px;height:52px;border-radius:16px;background:linear-gradient(135deg,#3b82f6,#1d4ed8);display:flex;align-items:center;justify-content:center;margin:0 auto 18px;box-shadow:0 8px 32px rgba(37,99,235,.2)"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div><div style="font-size:16px;font-weight:800;margin-bottom:6px">Session Expired</div><div style="font-size:12px;color:var(--muted);margin-bottom:22px">Locked for privacy.</div><button class="btn" id="ul-btn">Return Home</button></div></div>';setTimeout(()=>{const b=$("ul-btn");if(b)b.addEventListener("click",_ul);},0);},TO);}
["click","touchstart","keydown","scroll"].forEach(e=>document.addEventListener(e,resetT,{passive:true}));

const _pb=$("pb");
let _hideTimer;
document.addEventListener("visibilitychange",()=>{if(document.hidden&&S.screen!=="home"){_pb.classList.add("show");clearTimeout(_hideTimer);_hideTimer=setTimeout(()=>{_wipeMemory();S.screen="home";S.unit=null;render();},120000);}else{clearTimeout(_hideTimer);_pb.classList.remove("show");}});
window.addEventListener("focus",()=>_pb.classList.remove("show"));
document.addEventListener("contextmenu",e=>{if(S.screen!=="home")e.preventDefault();});
window.addEventListener("beforeunload",()=>{_wipeMemory();});

function exportFullList(showDoctors){
  const allPats=[];
  ["A","B","C","D","E"].forEach(u=>["M","F"].forEach(g=>{
    const uid=u+"_"+g;
    Object.entries(S.allData[uid]||{}).forEach(([k,v])=>allPats.push({...v,_unit:u,_gender:g==="M"?"M":"F",_uid:uid}));
  }));
  if(!allPats.length){toast("No patients","err");return;}

  // Group by ward
  const wardMap={};
  allPats.forEach(p=>{const w=_wardLabel(p);if(!wardMap[w])wardMap[w]=[];wardMap[w].push(p);});
  const wardKeys=Object.keys(wardMap).sort();

  const fs=14,pad=10,rh=fs+pad*2,hh=rh+8;
  const cols=showDoctors?["#","Name","Civil ID","Unit","Room","Code","Doctor"]:["#","Name","Civil ID","Unit","Room","Code"];
  const cw=showDoctors?[30,180,120,65,65,45,140]:[35,220,140,80,80,45];
  const tw=cw.reduce((a,b)=>a+b)+50;
  const clr={1:"#059669",2:"#d97706",3:"#dc2626",4:"#dc2626"};
  const MAX_PAGE_H=1400;
  const dateStr=new Date().toLocaleString("en",{year:"numeric",month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"});

  // Build flat list of draw commands, then paginate
  const items=[];
  wardKeys.forEach(w=>{
    const pts=wardMap[w].sort((a,b)=>{if(a._unit!==b._unit)return a._unit.localeCompare(b._unit);return(b.code||0)-(a.code||0);});
    items.push({type:"wardHdr",ward:w,count:pts.length,h:36});
    items.push({type:"colHdr",h:hh});
    pts.forEach((p,ri)=>{
      const unitLabel=p._unit+" "+(p._gender==="F"?"\u2640":"\u2642");
      const cells=[""+(ri+1),p.name||"",p.civil||"",unitLabel,p.room||"-",""+p.code];
      if(showDoctors)cells.push(p.doctor||"-");
      items.push({type:"row",cells,ri,h:rh});
    });
    items.push({type:"gap",h:14});
  });

  // Paginate
  const pages=[];
  let page=[],pageH=70; // banner height
  items.forEach(item=>{
    // If adding this item exceeds max, start new page (but keep ward header + col header together)
    if(pageH+item.h>MAX_PAGE_H&&page.length>0&&item.type!=="colHdr"){
      pages.push(page);page=[];pageH=70;
      // If last item in prev page was wardHdr, move it to new page
    }
    page.push(item);pageH+=item.h;
  });
  if(page.length)pages.push(page);

  // Ensure ward headers aren't orphaned at end of page
  for(let pi=0;pi<pages.length-1;pi++){
    const pg=pages[pi];
    if(pg.length>0&&pg[pg.length-1].type==="wardHdr"){
      const moved=pg.pop();
      pages[pi+1].unshift(moved);
    }
  }

  const rr=function(ctx2,x2,y2,w2,h2,r){ctx2.beginPath();ctx2.moveTo(x2+r,y2);ctx2.lineTo(x2+w2-r,y2);ctx2.quadraticCurveTo(x2+w2,y2,x2+w2,y2+r);ctx2.lineTo(x2+w2,y2+h2-r);ctx2.quadraticCurveTo(x2+w2,y2+h2,x2+w2-r,y2+h2);ctx2.lineTo(x2+r,y2+h2);ctx2.quadraticCurveTo(x2,y2+h2,x2,y2+h2-r);ctx2.lineTo(x2,y2+r);ctx2.quadraticCurveTo(x2,y2,x2+r,y2);ctx2.closePath();ctx2.fill();};

  const codeLbl={1:"Green",2:"Yellow",3:"Red",4:"Critical"};

  function renderPage(pgItems,pgNum,totalPages){
    const cv=document.createElement("canvas"),ctx=cv.getContext("2d");
    let totalH=80;
    pgItems.forEach(it=>totalH+=it.h);
    totalH+=40; // footer
    cv.width=tw;cv.height=totalH;

    // White background
    ctx.fillStyle="#ffffff";ctx.fillRect(0,0,tw,totalH);
    // Top blue banner
    ctx.fillStyle="#1e3a5f";ctx.fillRect(0,0,tw,70);
    ctx.textAlign="right";ctx.textBaseline="middle";
    ctx.fillStyle="#ffffff";ctx.font="bold 20px Inter,sans-serif";
    ctx.fillText("MedEvac — Patient Registry by Ward",tw-20,24);
    ctx.fillStyle="rgba(255,255,255,.6)";ctx.font="13px Inter,sans-serif";
    ctx.fillText("Mubarak Al-Kabeer Hospital  |  "+dateStr,tw-20,48);
    ctx.fillStyle="rgba(255,255,255,.35)";ctx.font="11px Inter,sans-serif";
    ctx.fillText("Page "+pgNum+" of "+totalPages+"  |  "+allPats.length+" patients total",tw-20,64);

    let y=80;
    pgItems.forEach(item=>{
      if(item.type==="wardHdr"){
        ctx.fillStyle="#ffffff";ctx.fillRect(16,y,tw-32,32);
        ctx.fillStyle="#1e40af";rr(ctx,16,y,tw-32,32,10);
        ctx.fillStyle="#ffffff";ctx.font="bold 15px Inter,sans-serif";
        ctx.fillText("Ward "+item.ward+"   —   "+item.count+" patient"+(item.count!==1?"s":""),tw-28,y+16);
        y+=item.h;
      }else if(item.type==="colHdr"){
        ctx.fillStyle="#e8eef6";ctx.fillRect(16,y,tw-32,hh);
        // Bottom border on header
        ctx.fillStyle="#c7d2e0";ctx.fillRect(16,y+hh-1,tw-32,1);
        ctx.fillStyle="#1e3a5f";ctx.font="bold "+fs+"px Inter,sans-serif";
        let x=tw-20;
        cols.forEach((c,i)=>{ctx.fillText(c,x-6,y+hh/2);x-=cw[i];});
        y+=item.h;
      }else if(item.type==="row"){
        ctx.fillStyle=item.ri%2?"#f8fafc":"#ffffff";ctx.fillRect(16,y,tw-32,rh);
        // Bottom border
        ctx.fillStyle="#e8eef6";ctx.fillRect(16,y+rh-1,tw-32,1);
        let x=tw-20;
        const codeNum=+item.cells[5];
        // Draw each cell
        item.cells.forEach((cell,ci)=>{
          if(ci===5){
            // Code column: colored label
            ctx.fillStyle=clr[codeNum]||"#334155";
            ctx.font="bold "+fs+"px Inter,sans-serif";
            ctx.fillText(codeLbl[codeNum]||cell,x-6,y+rh/2);
          }else if(ci===3){
            // Unit column: bold blue
            ctx.fillStyle="#1e40af";
            ctx.font="bold "+fs+"px Inter,sans-serif";
            ctx.fillText(cell,x-6,y+rh/2);
          }else if(ci===0){
            // Row number: muted
            ctx.fillStyle="#94a3b8";
            ctx.font=fs+"px Inter,sans-serif";
            ctx.fillText(cell,x-6,y+rh/2);
          }else{
            ctx.fillStyle="#1e293b";
            ctx.font=fs+"px Inter,sans-serif";
            let t=cell;const mw=cw[ci]-14;
            if(ctx.measureText(t).width>mw){while(ctx.measureText(t+"\u2026").width>mw&&t.length>1)t=t.slice(0,-1);t+="\u2026";}
            ctx.fillText(t,x-6,y+rh/2);
          }
          x-=cw[ci];
        });
        y+=item.h;
      }else if(item.type==="gap"){
        y+=item.h;
      }
    });

    // Footer line + text
    ctx.fillStyle="#e2e8f0";ctx.fillRect(20,y+6,tw-40,1);
    ctx.fillStyle="#94a3b8";ctx.font="11px Inter,sans-serif";
    ctx.fillText("MedEvac  \u2022  Mubarak Al-Kabeer Hospital  \u2022  Page "+pgNum+"/"+totalPages,tw-20,y+24);

    return cv;
  }

  // Render all pages to canvases, then build PDF
  const canvases=pages.map((pg,i)=>renderPage(pg,i+1,pages.length));

  // Build PDF with embedded JPEG images
  function buildPDF(cvs){
    const imgs=cvs.map(cv=>{
      const jpeg=cv.toDataURL("image/jpeg",0.92);
      const raw=atob(jpeg.split(",")[1]);
      const bytes=new Uint8Array(raw.length);
      for(let i=0;i<raw.length;i++)bytes[i]=raw.charCodeAt(i);
      return{w:cv.width,h:cv.height,data:bytes};
    });

    const parts=[];
    let pos=0;
    function writeStr(s){const b=new TextEncoder().encode(s);parts.push(b);pos+=b.length;}
    function writeBytes(b){parts.push(b);pos+=b.length;}
    function getPos(){return pos;}

    const objOffsets=[];
    let oNum=1;
    function startObj(){objOffsets.push(getPos());writeStr(oNum+" 0 obj\n");return oNum++;}
    function endObj(){writeStr("endobj\n");}

    // Reset
    parts.length=0;pos=0;

    writeStr("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    // 1: Catalog
    startObj();writeStr("<< /Type /Catalog /Pages 2 0 R >>\n");endObj();

    // 2: Pages
    startObj();
    // We'll write a long enough placeholder
    const kidsList=[];
    // First pass: figure out object numbers for pages
    // Each page needs: Image obj, Content stream obj, Page obj = 3 objs per page
    // Pages obj is #2, so first page starts at obj 3
    // page i: imgObj=3+i*3, contentObj=4+i*3, pageObj=5+i*3
    for(let i=0;i<imgs.length;i++) kidsList.push((5+i*3)+" 0 R");
    writeStr("<< /Type /Pages /Kids ["+kidsList.join(" ")+"] /Count "+imgs.length+" >>\n");
    endObj();

    // For each page: Image, Content stream, Page
    imgs.forEach(img=>{
      const pdfW=595.28;
      const scale=pdfW/img.w;
      const pdfH=img.h*scale;

      // Image XObject
      const imgObjN=startObj();
      writeStr("<< /Type /XObject /Subtype /Image /Width "+img.w+" /Height "+img.h+" /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length "+img.data.length+" >>\nstream\n");
      writeBytes(img.data);
      writeStr("\nendstream\n");endObj();

      // Content stream
      const contentData="q "+pdfW.toFixed(2)+" 0 0 "+pdfH.toFixed(2)+" 0 0 cm /Img Do Q\n";
      const contentObjN=startObj();
      writeStr("<< /Length "+contentData.length+" >>\nstream\n"+contentData+"endstream\n");endObj();

      // Page
      startObj();
      writeStr("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 "+pdfW.toFixed(2)+" "+pdfH.toFixed(2)+"] /Contents "+contentObjN+" 0 R /Resources << /XObject << /Img "+imgObjN+" 0 R >> >> >>\n");endObj();
    });

    // xref
    const xrefPos=getPos();
    writeStr("xref\n0 "+oNum+"\n");
    writeStr("0000000000 65535 f \n");
    for(let i=0;i<objOffsets.length;i++){
      writeStr(String(objOffsets[i]).padStart(10,"0")+" 00000 n \n");
    }
    writeStr("trailer\n<< /Size "+oNum+" /Root 1 0 R >>\nstartxref\n"+xrefPos+"\n%%EOF\n");

    // Merge all parts
    const totalLen=parts.reduce((a,b)=>a+b.length,0);
    const result=new Uint8Array(totalLen);
    let off=0;
    for(const p of parts){result.set(p,off);off+=p.length;}
    return result;
  }

  const pdfBytes=buildPDF(canvases);
  const blob=new Blob([pdfBytes],{type:"application/pdf"});
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");a.href=url;
  a.download="MedEvac_ByWard_"+new Date().toISOString().slice(0,10)+".pdf";
  document.body.appendChild(a);a.click();document.body.removeChild(a);
  setTimeout(()=>URL.revokeObjectURL(url),5000);
  audit("full_export","ALL",allPats.length+" patients");
  toast("PDF exported — "+pages.length+" page"+(pages.length>1?"s":""));
}

function backupPNG(showDoctors){
  if(!S.unit||!S.patients.length)return;
  const cols=showDoctors?["#","Name","Civil ID","Nat","Room","Code","Doctor"]:["#","Name","Civil ID","Nat","Room","Code","Notes"];
  const cw=showDoctors?[32,150,110,60,50,40,140]:[32,150,110,60,50,40,130];
  const fs=13,pad=9,rh=fs+pad*2,hh=rh+4,whh=30;
  const tw=cw.reduce((a,b)=>a+b)+24;
  const clr={1:"#059669",2:"#d97706",3:"#dc2626",4:"#dc2626"};

  // Group by ward
  const wardMap={};
  S.patients.forEach(p=>{const w=p.ward||"Unknown";if(!wardMap[w])wardMap[w]=[];wardMap[w].push(p);});
  const wardKeys=Object.keys(wardMap).sort();

  // Calculate total height
  let totalH=60; // banner
  wardKeys.forEach(w=>{totalH+=whh+hh;totalH+=wardMap[w].length*rh;totalH+=10;});
  totalH+=20; // bottom padding

  const cv=document.createElement("canvas"),ctx=cv.getContext("2d");
  cv.width=tw;cv.height=totalH;
  // White bg + blue banner
  ctx.fillStyle="#ffffff";ctx.fillRect(0,0,tw,totalH);
  ctx.fillStyle="#1e3a5f";ctx.fillRect(0,0,tw,54);
  ctx.textAlign="right";ctx.textBaseline="middle";
  ctx.fillStyle="#ffffff";ctx.font="bold 16px Inter,sans-serif";
  ctx.fillText("Unit "+S.unit[0]+" \u2014 "+(S.unit.endsWith("_F")?"Female":"Male")+" \u2014 "+S.patients.length+" patients",tw-14,20);
  ctx.fillStyle="rgba(255,255,255,.5)";ctx.font="11px Inter,sans-serif";
  ctx.fillText(new Date().toLocaleString("en",{year:"numeric",month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"}),tw-14,38);
  let y=60;

  wardKeys.forEach(w=>{
    const pts=wardMap[w].sort((a,b)=>(b.code||0)-(a.code||0));
    // Ward header
    ctx.fillStyle="#1e3a5f";
    const rr=function(x2,y2,w2,h2,r){ctx.beginPath();ctx.moveTo(x2+r,y2);ctx.lineTo(x2+w2-r,y2);ctx.quadraticCurveTo(x2+w2,y2,x2+w2,y2+r);ctx.lineTo(x2+w2,y2+h2-r);ctx.quadraticCurveTo(x2+w2,y2+h2,x2+w2-r,y2+h2);ctx.lineTo(x2+r,y2+h2);ctx.quadraticCurveTo(x2,y2+h2,x2,y2+h2-r);ctx.lineTo(x2,y2+r);ctx.quadraticCurveTo(x2,y2,x2+r,y2);ctx.closePath();ctx.fill();};
    rr(12,y,tw-24,whh,6);
    ctx.fillStyle="#ffffff";ctx.font="bold 13px Inter,sans-serif";
    ctx.fillText("Ward "+w+" \u2014 "+pts.length+" patient"+(pts.length!==1?"s":""),tw-20,y+whh/2);
    y+=whh;

    // Column headers
    ctx.fillStyle="#f0f4f8";ctx.fillRect(12,y,tw-24,hh);
    ctx.fillStyle="#1e3a5f";ctx.font="bold "+fs+"px Inter,sans-serif";
    let x=tw-14;
    cols.forEach((c,i)=>{ctx.fillText(c,x-4,y+hh/2);x-=cw[i];});
    y+=hh;

    // Rows
    pts.forEach((p,ri)=>{
      const row=[""+(ri+1),p.name||"",p.civil||"",p.nat||"",p.room||"-",""+p.code];
      row.push(showDoctors?(p.doctor||"-"):(p.notes||""));
      ctx.fillStyle=ri%2?"#f8fafc":"#ffffff";ctx.fillRect(12,y,tw-24,rh);
      ctx.fillStyle="#e2e8f0";ctx.fillRect(12,y+rh-0.5,tw-24,0.5);
      ctx.font=fs+"px Inter,sans-serif";x=tw-14;
      row.forEach((cell,ci)=>{
        ctx.fillStyle=ci===5?clr[+cell]||"#334155":"#334155";
        if(ci===5)ctx.font="bold "+fs+"px Inter,sans-serif";else ctx.font=fs+"px Inter,sans-serif";
        let t=cell;const mw=cw[ci]-8;
        if(ctx.measureText(t).width>mw){while(ctx.measureText(t+"\u2026").width>mw&&t.length>1)t=t.slice(0,-1);t+="\u2026";}
        ctx.fillText(t,x-4,y+rh/2);x-=cw[ci];
      });y+=rh;
    });
    y+=10; // gap between wards
  });
  const a=document.createElement("a");a.href=cv.toDataURL("image/png");a.download="MedEvac_"+S.unit+".png";document.body.appendChild(a);a.click();document.body.removeChild(a);audit("backup_export",S.unit,S.patients.length+" patients");toast("Backup saved");
}

function render(force=false){
  if(!force&&S.screen==="pin"&&!S.pinOk&&!S.pinError&&S.pinVal.length<4&&!S._pinNeedsLayout){
    updatePinDisplay();
    return;
  }
  S._pinNeedsLayout=false;
  try{let h="";const s=S.screen;
  if(s==="home")h=vHome();else if(s==="pin")h=vPin();else if(s==="wardview")h=vWardView();else if(s==="ward")h=vWard();
  else if(s==="detail")h=vDetail();else if(s==="add")h=vAdd();else if(s==="admin")h=vAdmin();
  app.innerHTML=h;bindAll();updatePinDisplay();resetT();}catch(e){console.error(e);}
}

function hideLaunchSplash(){
  const splash=$("launch-splash");
  if(!splash)return;
  splash.classList.add("hide");
  splash.addEventListener("transitionend",()=>{if(splash.parentElement)splash.parentElement.removeChild(splash);},{once:true});
}

function vHome(){
  const cnt={};["A","B","C","D","E"].forEach(u=>["M","F"].forEach(g=>{cnt[u+"_"+g]=Object.keys(S.allData[u+"_"+g]||{}).length;}));
  const total=Object.values(cnt).reduce((a,b)=>a+b,0);
  return'<div class="screen"><div class="hdr"><div class="hdr-c"><h1>MedEvac</h1><p>Mubarak Al-Kabeer Hospital</p></div><div class="badge '+(_authFailed?"badge-off":S.online?"badge-on":"badge-off")+'"><div class="ldot"></div>'+(_authFailed?"Auth Error":S.online?"Online":"Offline")+'</div><button class="hbtn" id="bfl">'+I.dl+'</button><button class="hbtn" id="ba">'+I.cog+'</button></div><div class="sp" style="padding:14px 16px 100px"><div class="hero"><div style="display:flex;justify-content:space-between;margin-bottom:6px;position:relative;z-index:1"><span style="font-size:10px;opacity:.5;font-weight:700;text-transform:uppercase;letter-spacing:1px">Total Patients</span><span style="font-size:9px;opacity:.25;font-weight:500">'+new Date().toLocaleDateString("en",{month:"short",day:"numeric",year:"numeric"})+'</span></div><div style="font-size:44px;font-weight:900;letter-spacing:-2px;position:relative;z-index:1;color:#fff">'+total+'</div><div style="font-size:11px;opacity:.25;margin-top:4px;font-weight:500;position:relative;z-index:1">Across all units</div></div><button class="btn2" id="bwv" style="margin-bottom:14px;justify-content:center;gap:8px;font-size:13px;padding:12px"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg> View by Ward</button>'+["A","B","C","D","E"].map(u=>'<div class="uc"><div class="uh"><span>Unit '+u+'</span><span>'+(cnt[u+"_M"]+cnt[u+"_F"])+'</span></div><div class="ub"><div class="ubtn female" data-unit="'+u+'_F"><div class="ubtn-ico">'+I.user+'</div><div class="ubtn-name">Female</div><div class="ubtn-cnt">'+cnt[u+"_F"]+'</div></div><div class="ubtn male" data-unit="'+u+'_M"><div class="ubtn-ico">'+I.user+'</div><div class="ubtn-name">Male</div><div class="ubtn-cnt">'+cnt[u+"_M"]+'</div></div></div></div>').join("")+'</div></div>';
}

function _getAllPats(){
  const all=[];
  ["A","B","C","D","E"].forEach(u=>["M","F"].forEach(g=>{
    const uid=u+"_"+g;
    Object.entries(S.allData[uid]||{}).forEach(([k,v])=>all.push({...v,_k:k,_uid:uid,_unit:u,_gender:g==="M"?"M":"F"}));
  }));
  return all;
}
function _wardLabel(p){
  const raw=(p.ward||"").trim().toUpperCase();
  if(!raw)return"UNKNOWN";
  // Extract just the ward part (e.g. "W21" from "W21 R8" or "W 26 R 3" or "W28R14-2")
  const m=raw.match(/^(W\s*\d+)/i);
  if(m)return m[1].replace(/\s+/g,""); // "W 26" -> "W26"
  return raw; // ER, ICU, etc - keep as-is
}

function vWardView(){
  const allPats=_getAllPats();
  const wardMap={};
  allPats.forEach(p=>{const w=_wardLabel(p);if(!wardMap[w])wardMap[w]=[];wardMap[w].push(p);});
  const wardKeys=Object.keys(wardMap).sort();
  const q=(S.wardSearch||"").toLowerCase();
  const filtered=q?wardKeys.filter(w=>w.toLowerCase().includes(q)):wardKeys;
  const selWard=S.wardSelected;
  const totalPats=allPats.length;

  let body='';
  if(selWard&&wardMap[selWard]){
    const pts=wardMap[selWard].sort((a,b)=>{if(a._unit!==b._unit)return a._unit.localeCompare(b._unit);return(b.code||0)-(a.code||0);});
    // Group by unit+gender
    const groups=[];const seen={};
    pts.forEach(p=>{
      const key=p._unit+"_"+p._gender;
      if(!seen[key]){seen[key]={label:"Unit "+p._unit+" — "+(p._gender==="M"?"Male":"Female"),patients:[]};groups.push(seen[key]);}
      seen[key].patients.push(p);
    });
    body='<div class="ward-sel-hdr"><div><div class="ward-sel-title">Ward '+esc(selWard)+'</div><div class="ward-sel-cnt">'+pts.length+' patient'+(pts.length!==1?"s":"")+'</div></div><button class="btn2" id="bwback" style="width:auto;padding:8px 14px;font-size:12px;background:#fff;color:var(--pri)">All Wards</button></div>';
    groups.forEach(g=>{
      const isMale=g.label.includes("Male") && !g.label.includes("Female");
      body+='<div class="ward-unit-hdr"><span class="ward-unit-dot" style="background:'+(isMale?"#2563eb":"#d946ef")+'"></span>'+esc(g.label)+' <span style="opacity:.4;font-weight:600">('+g.patients.length+')</span></div>';
      g.patients.forEach(p=>{
        const c2=cc(p.code);const rm=p.room?' <span style="color:var(--muted);font-weight:500">/ '+esc(p.room)+'</span>':'';
        body+='<div class="acc-row acc-row-click" data-auid="'+p._uid+'" data-akey="'+p._k+'" style="margin:0 0 4px"><div class="acc-strip '+c2.cls+'"></div><div class="acc-row-body"><div class="acc-row-main"><div class="acc-pname">'+esc(p.name)+'</div><div class="acc-pmeta"><span>'+c2.label+'</span>'+(p.room?'<span>Room '+esc(p.room)+'</span>':'')+'<span>'+esc(p.nat||"-")+'</span></div></div><div class="acc-row-code '+c2.cls+'">'+p.code+'</div></div></div>';
      });
    });
  }else{
    body='<div class="ward-view-summary"><span class="ward-view-total">'+totalPats+'</span> patients across <span style="font-weight:800">'+wardKeys.length+'</span> wards</div>';
    body+='<div class="adm-search-wrap"><input class="sinp" id="ward-search" placeholder="Search wards..." value="'+esc(S.wardSearch||"")+'"><div class="adm-search-ico"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></div></div>';
    if(filtered.length){
      filtered.forEach(w=>{
        const pts=wardMap[w];const cnt=pts.length;
        const unitSet=[...new Set(pts.map(p=>p._unit))].sort();
        const gC=pts.filter(p=>p.code==1).length,yC=pts.filter(p=>p.code==2).length,rC=pts.filter(p=>p.code>=3).length;
        body+='<div class="ward-card" data-ward="'+esc(w)+'"><div class="ward-card-left"><div class="ward-card-badge">'+esc(w)+'</div></div><div class="ward-card-main"><div class="ward-card-name">Ward '+esc(w)+'</div><div class="ward-card-meta">'+unitSet.map(u=>'<span class="ward-unit-tag">'+u+'</span>').join("")+' &middot; '+cnt+' patient'+(cnt!==1?"s":"")+'</div></div><div class="ward-card-right"><span class="acc-badge bg">'+gC+'</span><span class="acc-badge by">'+yC+'</span><span class="acc-badge br">'+rC+'</span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--muted2)" stroke-width="2.5" stroke-linecap="round"><polyline points="15 18 9 12 15 6"/></svg></div></div>';
      });
    }else{body+='<div style="text-align:center;padding:40px 20px;color:var(--muted)">No wards found</div>';}
  }
  return'<div class="screen"><div class="hdr"><button class="hbtn" id="bb">'+I.back+'</button><div class="hdr-c" style="text-align:center"><h1>Ward View</h1><p>Patients by Ward</p></div><div style="width:36px"></div></div><div class="sp" style="padding:10px 14px 100px">'+body+'</div></div>';
}

function vPin(){
  const isA=S.pinTarget==="ADMIN",u=["A","B","C","D","E"].find(u=>S.pinTarget===u+"_M"||S.pinTarget===u+"_F"),g=S.pinTarget?.endsWith("_M")?"Male":"Female";
  const dotCls=S.pinError?"err":S.pinOk?"ok":"f";
  const titleCls=S.pinError?" t-err":"";
  const titleTxt=S.pinError?"Wrong PIN":S.pinOk?"Verified":"Enter PIN";
  return'<div class="screen"><div class="hdr"><button class="hbtn" id="bb">'+I.back+'</button><div class="hdr-c" style="text-align:center"><h1>'+(isA?"Admin":"Unit "+u+" \u2014 "+g)+'</h1></div><div style="width:36px"></div></div><div class="pin-body'+(S.pinError?" pin-shake":"")+'" id="pin-body"><div class="pin-icon"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div><div class="pin-title'+titleCls+'" id="pin-title">'+titleTxt+'</div><div class="pin-dots" id="pin-dots">'+[0,1,2,3].map(i=>'<div class="pdot'+(i<S.pinVal.length?" "+dotCls:"")+'" data-idx="'+i+'"></div>').join("")+'</div>'+'<div class="pkeys">'+[[1,2,3],[4,5,6],[7,8,9],["",0,"\u232b"]].map(r=>r.map(k=>k===""?'<div></div>':'<button class="pkey'+(k==="\u232b"?" del":"")+'" data-pin="'+k+'">'+k+'</button>').join("")).join("")+'</div></div></div>';
}

function vWard(){
  const list=filtered(),t=S.patients.length,g=S.patients.filter(p=>p.code==1).length,y=S.patients.filter(p=>p.code==2).length,r=S.patients.filter(p=>p.code>=3).length,u=S.unit[0],isF=S.unit.endsWith("_F");
  return'<div class="screen"><div class="hdr"><button class="hbtn" id="bb">'+I.back+'</button><div class="hdr-c" style="text-align:center"><h1>Unit '+u+' \u2014 '+(isF?"Female":"Male")+'</h1><p>Mubarak Al-Kabeer</p></div><button class="hbtn" id="bdl">'+I.dl+'</button></div><div class="offbar'+(S.online?"":" show")+'">Offline</div><div class="stats-row"><div class="stat ca'+(S.filter==="all"?" act":"")+'" data-filt="all"><div class="n">'+t+'</div><div class="l">All</div></div><div class="stat cg'+(S.filter==="1"?" act":"")+'" data-filt="1"><div class="n">'+g+'</div><div class="l">Green</div></div><div class="stat cy'+(S.filter==="2"?" act":"")+'" data-filt="2"><div class="n">'+y+'</div><div class="l">Yellow</div></div><div class="stat cr'+(S.filter==="r"?" act":"")+'" data-filt="r"><div class="n">'+r+'</div><div class="l">Red</div></div></div><div class="sbar"><input class="sinp" id="si" placeholder="Search..." value="'+esc(S.search)+'"><button class="abtn" id="badd">'+I.plus+'</button></div><div class="plist" id="pl">'+(list.length?list.map(p=>{const c=cc(p.code),cv=S.showCivil[p._k]?p.civil:mask(p.civil);const wardRoom=p.room?(p.ward||"")+' / '+(p.room||""):(p.ward||"");return'<div class="pc '+c.cls+'" data-key="'+p._k+'"><div class="ps"></div><div class="pb"><div class="bn">'+p.code+'</div><div class="bt">'+c.label+'</div></div><div class="pi"><div class="pn">'+esc(p.name)+'</div><div class="pm"><span class="ch">'+esc(cv)+'</span><span class="ch">'+esc(p.nat)+'</span>'+(p.notes?'<span class="ch">'+esc(p.notes)+'</span>':'')+'</div></div><div class="pw">'+esc(wardRoom)+'</div></div>';}).join(""):'<div style="text-align:center;padding:60px 20px;color:var(--muted)">No patients</div>')+'</div></div>';
}

function vDetail(){
  const p=S.editP,cv=S.showCivil[p._k]?p.civil:mask(p.civil);
  return'<div class="screen"><div class="hdr"><button class="hbtn" id="bb">'+I.back+'</button><div class="hdr-c" style="margin:0 8px"><h1 style="font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(p.name)+'</h1><p>Details</p></div></div><div class="sp" style="padding:14px 16px 100px"><div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:0 16px;margin-bottom:18px;box-shadow:var(--shadow)"><div class="ir"><span style="color:var(--muted);font-weight:600">Civil ID</span><span style="font-weight:700;display:flex;align-items:center;gap:6px">'+esc(cv)+'<button style="background:none;border:none;cursor:pointer;color:var(--muted);padding:2px" id="tc">'+(S.showCivil[p._k]?I.eyeOff:I.eye)+'</button></span></div><div class="ir"><span style="color:var(--muted);font-weight:600">Nationality</span><span style="font-weight:700">'+esc(p.nat||"\u2014")+'</span></div></div><div style="display:flex;gap:8px"><div class="fg" style="flex:1"><label class="fl">Ward *</label><input class="fi" id="ew" placeholder="e.g. W21" value="'+esc(p.ward||"")+'"></div><div class="fg" style="flex:1"><label class="fl">Room / Bed</label><input class="fi" id="erm" placeholder="e.g. R8" value="'+esc(p.room||"")+'"></div></div><div class="fg"><label class="fl">Severity Code</label><div class="cg2">'+[1,2,3,4].map(c=>'<div class="co'+(S.editCode==c?" s"+c:"")+'" data-cpick="e" data-code="'+c+'"><div class="cn">'+c+'</div><div class="ct">'+cc(c).label+'</div></div>').join("")+'</div></div><div class="fg"><label class="fl">Notes</label><input class="fi" id="en" placeholder="Notes..." value="'+esc(p.notes||"")+'"></div><div class="fg"><label class="fl">Doctor</label><input class="fi" id="edr" placeholder="Attending doctor..." value="'+esc(p.doctor||"")+'"></div><div style="display:flex;gap:8px"><button class="btn" id="bs">'+I.save+' Save</button><button class="btnd" id="bd">'+I.trash+'</button></div></div></div>';
}

function vAdd(){
  return'<div class="screen"><div class="hdr"><button class="hbtn" id="bb">'+I.back+'</button><div class="hdr-c" style="text-align:center"><h1>Add Patient</h1></div><div style="width:36px"></div></div><div class="sp" style="padding:14px 14px 100px"><div class="fg"><label class="fl">Full Name *</label><input class="fi" id="an" placeholder="Name" autocomplete="off" value="'+esc(S._addName||"")+'"></div><div class="fg"><label class="fl">Civil ID *</label><input class="fi" id="ac" placeholder="Civil ID" inputmode="numeric" autocomplete="off" value="'+esc(S._addCivil||"")+'"></div><div class="fg"><label class="fl">Nationality</label><input class="fi" id="at" placeholder="Nationality" autocomplete="off" value="'+esc(S._addNat||"")+'"></div><div style="display:flex;gap:8px"><div class="fg" style="flex:1"><label class="fl">Ward *</label><input class="fi" id="aw" placeholder="e.g. W21" autocomplete="off" value="'+esc(S._addWard||"")+'"></div><div class="fg" style="flex:1"><label class="fl">Room / Bed</label><input class="fi" id="arm" placeholder="e.g. R8" autocomplete="off" value="'+esc(S._addRoom||"")+'"></div></div><div class="fg"><label class="fl">Severity Code *</label><div class="cg2">'+[1,2,3,4].map(c=>'<div class="co'+(S.addCode==c?" s"+c:"")+'" data-cpick="a" data-code="'+c+'"><div class="cn">'+c+'</div><div class="ct">'+cc(c).label+'</div></div>').join("")+'</div></div><div class="fg"><label class="fl">Notes</label><input class="fi" id="ao" placeholder="Notes..." autocomplete="off" value="'+esc(S._addNotes||"")+'"></div><div class="fg"><label class="fl">Doctor</label><input class="fi" id="adr" placeholder="Attending doctor..." autocomplete="off" value="'+esc(S._addDoctor||"")+'"></div><button class="btn" id="bsa">'+I.plus+' Add Patient</button></div></div>';
}

function vAdmin(){
  const tabs=[{id:"overview",l:"Overview"},{id:"ocr",l:"OCR"},{id:"audit",l:"Audit"},{id:"pins",l:"Security"}];let c="";
  if(S.adminTab==="overview"){
    const allPatients=[];
    ["A","B","C","D","E"].forEach(u=>["M","F"].forEach(g=>{const uid=u+"_"+g;Object.entries(S.allData[uid]||{}).forEach(([k,v])=>allPatients.push({...v,_k:k,_uid:uid,_unit:u,_gender:g}));}));
    const totalAll=allPatients.length,totalG=allPatients.filter(p=>p.code==1).length,totalY=allPatients.filter(p=>p.code==2).length,totalR=allPatients.filter(p=>p.code>=3).length;
    const q=S.adminSearch?S.adminSearch.toLowerCase():"";
    c='<div class="adm-hero"><div class="adm-hero-title">Hospital Overview</div><div class="adm-summary"><div class="adm-stat"><div class="adm-n">'+totalAll+'</div><div class="adm-l">Total</div></div><div class="adm-stat"><div class="adm-n" style="color:#86efac">'+totalG+'</div><div class="adm-l">Green</div></div><div class="adm-stat"><div class="adm-n" style="color:#fde68a">'+totalY+'</div><div class="adm-l">Yellow</div></div><div class="adm-stat"><div class="adm-n" style="color:#fca5a5">'+totalR+'</div><div class="adm-l">Red</div></div></div></div>'
    +'<div class="adm-search-wrap"><input class="sinp" id="adm-search" placeholder="Search patients by name, ID, or ward..." value="'+esc(S.adminSearch)+'"><div class="adm-search-ico"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></div></div>'
    +'<div class="adm-filters"><div class="adm-flt'+(S.adminFilter==="all"?" act":"")+'" data-af="all"><div class="adm-flt-n">'+totalAll+'</div><div class="adm-flt-l">All</div></div><div class="adm-flt'+(S.adminFilter==="r"?" act":"")+'" data-af="r"'+(S.adminFilter!=="r"?' style="color:var(--r)"':'')+'><div class="adm-flt-n">'+totalR+'</div><div class="adm-flt-l">Critical</div></div><div class="adm-flt'+(S.adminFilter==="2"?" act":"")+'" data-af="2"'+(S.adminFilter!=="2"?' style="color:var(--y)"':'')+'><div class="adm-flt-n">'+totalY+'</div><div class="adm-flt-l">Yellow</div></div><div class="adm-flt'+(S.adminFilter==="1"?" act":"")+'" data-af="1"'+(S.adminFilter!=="1"?' style="color:var(--g)"':'')+'><div class="adm-flt-n">'+totalG+'</div><div class="adm-flt-l">Green</div></div></div>';
    const _filterPats=list=>{
      let r=list.sort((a,b)=>(b.code||0)-(a.code||0));
      if(S.adminFilter==="1")r=r.filter(p=>p.code==1);
      else if(S.adminFilter==="2")r=r.filter(p=>p.code==2);
      else if(S.adminFilter==="r")r=r.filter(p=>p.code>=3);
      if(q)r=r.filter(p=>(p.name||"").toLowerCase().includes(q)||(p.civil||"").includes(q)||(p.ward||"").toLowerCase().includes(q));
      return r;
    };
    const _renderRows=list=>list.length?list.map(p=>{const c2=cc(p.code);return'<div class="acc-row acc-row-click" data-auid="'+p._uid+'" data-akey="'+p._k+'"><div class="acc-strip '+c2.cls+'"></div><div class="acc-row-body"><div class="acc-row-main"><div class="acc-pname">'+esc(p.name)+'</div><div class="acc-pmeta"><span>'+esc(p.ward||"-")+'</span><span>'+c2.label+'</span></div></div><div class="acc-row-code '+c2.cls+'">'+p.code+'</div></div></div>';}).join(""):'<div class="acc-empty">No patients match</div>';
    c+=["A","B","C","D","E"].map(u=>{
      const mAll=Object.entries(S.allData[u+"_M"]||{}).map(([k,v])=>({...v,_k:k,_uid:u+"_M",_g:"M"}));
      const fAll=Object.entries(S.allData[u+"_F"]||{}).map(([k,v])=>({...v,_k:k,_uid:u+"_F",_g:"F"}));
      const mFiltered=_filterPats([...mAll]),fFiltered=_filterPats([...fAll]);
      const total=mFiltered.length+fFiltered.length;
      const gC=[...mFiltered,...fFiltered].filter(p=>p.code==1).length,yC=[...mFiltered,...fFiltered].filter(p=>p.code==2).length,rC=[...mFiltered,...fFiltered].filter(p=>p.code>=3).length;
      const isOpen=S.expandedUnits[u];
      const chevron='<div class="acc-chev"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" style="transition:transform .2s;transform:rotate('+(isOpen?"180":"0")+'deg)"><polyline points="6 9 12 15 18 9"/></svg></div>';
      return'<div class="acc-unit'+(isOpen?" open":"")+'"><div class="acc-hdr" data-toggle="'+u+'"><div class="acc-hdr-l"><div class="acc-unit-badge">'+u+'</div><div><div class="acc-name">Unit '+u+'</div><div class="acc-subtitle">'+mFiltered.length+' male &middot; '+fFiltered.length+' female</div></div></div><div class="acc-hdr-r"><span class="acc-badge bg">'+gC+'</span><span class="acc-badge by">'+yC+'</span><span class="acc-badge br">'+rC+'</span>'+chevron+'</div></div>'
      +(isOpen?'<div class="acc-body">'+(total?'<div class="acc-gender-section"><div class="acc-gender-hdr male"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07"/><path d="M15 6l3-3"/><path d="M18 3h-3"/><path d="M18 3v3"/></svg> Male <span class="acc-gender-cnt">'+mFiltered.length+'</span></div>'+(mFiltered.length?_renderRows(mFiltered):'<div class="acc-empty">No male patients</div>')+'</div><div class="acc-gender-section"><div class="acc-gender-hdr female"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="8" r="5"/><path d="M12 13v8"/><path d="M9 18h6"/></svg> Female <span class="acc-gender-cnt">'+fFiltered.length+'</span></div>'+(fFiltered.length?_renderRows(fFiltered):'<div class="acc-empty">No female patients</div>')+'</div>':'<div class="acc-empty">No patients match current filters</div>')+'</div>':'')
      +'</div>';
    }).join("");
  }
  else if(S.adminTab==="ocr"){
    c='<div class="ocr-drop" id="oz"><input type="file" id="of" accept="image/*" multiple style="display:none"><div style="margin-bottom:12px;opacity:.5">'+I.cam+'</div><div style="font-weight:800;font-size:14px;margin-bottom:4px">Capture / Upload</div><div style="font-size:12px;color:var(--muted)">Any image — handwritten, printed, screenshot</div></div>';
    if(S.ocrImg)c+='<img src="'+S.ocrImg+'" style="width:100%;border-radius:12px;margin:10px 0;max-height:160px;object-fit:cover">';
    if(S.ocrLoading)c+='<div style="text-align:center;padding:20px"><div class="loader"></div><p style="margin-top:10px;color:var(--muted);font-size:12px">Analyzing image...</p></div>';
    if(S.ocrResults.length){
      c+='<div style="margin-top:10px"><div style="display:flex;gap:8px;align-items:center;margin-bottom:12px"><div class="fg" style="flex:1;margin:0"><select class="fi" id="ou" style="padding:10px">'+["A","B","C","D","E"].flatMap(u=>['<option value="'+u+'_M">Unit '+u+' — Male</option>','<option value="'+u+'_F">Unit '+u+' — Female</option>']).join("")+'</select></div><button class="btn2" id="osa" style="width:auto;padding:10px 14px;font-size:11px">Select All</button></div>';
      c+='<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:8px">'+S.ocrResults.length+' patient'+(S.ocrResults.length!==1?'s':'')+' found</div>';
      S.ocrResults.forEach((p,i)=>{
        const sel=S.ocrSel.includes(i);
        const missingName=!p.name||!p.name.trim();
        const missingCivil=!p.civil||!p.civil.trim();
        const missingWard=!p.ward||!p.ward.trim();
        const hasMissing=missingName||missingCivil||missingWard;
        c+='<div class="ocr-card'+(sel?" ocr-sel":"")+(hasMissing?" ocr-warn":"")+'">'
          +'<div class="ocr-card-top"><div class="ocr-chk'+(sel?" on":"")+'" data-ocr="'+i+'">'+(sel?I.chk:'')+'</div><div style="flex:1;font-weight:800;font-size:12px;color:var(--pri)">Patient '+(i+1)+'</div>'+(hasMissing?'<span class="ocr-miss-tag">Missing data</span>':'<span class="ocr-ok-tag">Ready</span>')+'</div>'
          +'<div class="ocr-fields">'
          +'<div class="ocr-field'+(missingName?" ocr-miss":"")+'"><label>Name *</label><input class="fi ocr-fi" data-ocr-f="'+i+'" data-ocr-k="name" value="'+esc(p.name||"")+'"></div>'
          +'<div class="ocr-field'+(missingCivil?" ocr-miss":"")+'"><label>Civil ID *</label><input class="fi ocr-fi" data-ocr-f="'+i+'" data-ocr-k="civil" value="'+esc(p.civil||"")+'" inputmode="numeric"></div>'
          +'<div class="ocr-row2"><div class="ocr-field'+(missingWard?" ocr-miss":"")+'"><label>Ward *</label><input class="fi ocr-fi" data-ocr-f="'+i+'" data-ocr-k="ward" value="'+esc(p.ward||"")+'"></div>'
          +'<div class="ocr-field"><label>Room</label><input class="fi ocr-fi" data-ocr-f="'+i+'" data-ocr-k="room" value="'+esc(p.room||"")+'"></div></div>'
          +'<div class="ocr-row2"><div class="ocr-field"><label>Nationality</label><input class="fi ocr-fi" data-ocr-f="'+i+'" data-ocr-k="nat" value="'+esc(p.nat||"")+'"></div>'
          +'<div class="ocr-field"><label>Code</label><select class="fi ocr-fi" data-ocr-f="'+i+'" data-ocr-k="code"><option value="1"'+(p.code==1?' selected':'')+'>1 Green</option><option value="2"'+(p.code==2||!p.code?' selected':'')+'>2 Yellow</option><option value="3"'+(p.code==3?' selected':'')+'>3 Red</option><option value="4"'+(p.code==4?' selected':'')+'>4 Critical</option></select></div></div>'
          +'<div class="ocr-field"><label>Notes</label><input class="fi ocr-fi" data-ocr-f="'+i+'" data-ocr-k="notes" value="'+esc(p.notes||"")+'"></div>'
          +'</div></div>';
      });
      const validCount=S.ocrSel.filter(i=>{const p=S.ocrResults[i];return p.name&&p.name.trim()&&p.civil&&p.civil.trim()&&p.ward&&p.ward.trim();}).length;
      c+='<button class="btn" id="oi"'+(validCount?'':' disabled')+' style="margin-top:12px">Import '+validCount+' Patient'+(validCount!==1?'s':'')+'</button>';
      if(validCount<S.ocrSel.length&&S.ocrSel.length)c+='<div style="font-size:10px;color:var(--r);font-weight:600;margin-top:6px;text-align:center">'+(S.ocrSel.length-validCount)+' selected patient'+(S.ocrSel.length-validCount!==1?'s have':' has')+' missing required fields</div>';
      c+='</div>';
    }
  }
  else if(S.adminTab==="audit"){
    if(!S._auditLog){
      c='<div style="text-align:center;padding:40px"><button class="btn" id="bloadaudit">'+I.lock+' Load Audit Log</button><div style="font-size:11px;color:var(--muted);margin-top:8px">Requires admin PIN verification</div></div>';
    }else if(S._auditLoading){
      c='<div style="text-align:center;padding:40px"><div class="loader"></div><p style="margin-top:10px;color:var(--muted);font-size:12px">Loading audit log...</p></div>';
    }else{
      const entries=S._auditLog;
      const actionIcons={login:"\u2705",login_fail:"\u274C",admin_access:"\uD83D\uDD12",pin_change:"\uD83D\uDD11",backup_export:"\uD83D\uDCBE",full_export:"\uD83D\uDCC4",ocr_import:"\uD83D\uDCF7",ocr_extract:"\uD83D\uDCF7",patient_add:"\u2795",patient_edit:"\u270F\uFE0F",patient_delete:"\uD83D\uDDD1\uFE0F"};
      const actionLabels={login:"Login",login_fail:"Failed Login",admin_access:"Admin Access",pin_change:"PIN Changed",backup_export:"Backup Export",full_export:"Full Export",ocr_import:"OCR Import",ocr_extract:"OCR Extract",patient_add:"Patient Added",patient_edit:"Patient Edited",patient_delete:"Patient Deleted"};
      c='<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:10px">'+entries.length+' recent events</div>';
      if(!entries.length)c+='<div class="acc-empty">No audit entries</div>';
      else c+=entries.map(e=>{
        const d=new Date(e.ts);
        const timeStr=d.toLocaleDateString("en",{month:"short",day:"numeric"})+' '+d.toLocaleTimeString("en",{hour:"2-digit",minute:"2-digit"});
        const icon=actionIcons[e.action]||"\u2022";
        const label=actionLabels[e.action]||e.action;
        const isFail=e.action==="login_fail";
        return'<div style="background:var(--card);border:1px solid '+(isFail?"var(--rbd)":"var(--border)")+';border-radius:var(--radius-xs);padding:10px 12px;margin-bottom:6px;display:flex;align-items:center;gap:10px;box-shadow:var(--shadow)"><div style="font-size:18px;flex-shrink:0">'+icon+'</div><div style="flex:1;min-width:0"><div style="font-size:12px;font-weight:700;color:'+(isFail?"var(--r)":"var(--txt)")+'">'+esc(label)+'</div><div style="font-size:10px;color:var(--muted);margin-top:2px">'+esc(e.unit||"-")+(e.detail?" &middot; "+esc(e.detail):"")+'</div></div><div style="font-size:10px;color:var(--muted2);white-space:nowrap">'+timeStr+'</div></div>';
      }).join("");
      c+='<button class="btn2" id="bloadaudit" style="margin-top:12px;font-size:12px">Refresh</button>';
    }
  }
  else if(S.adminTab==="pins"){const labels={A_M:"A Male",A_F:"A Female",B_M:"B Male",B_F:"B Female",C_M:"C Male",C_F:"C Female",D_M:"D Male",D_F:"D Female",E_M:"E Male",E_F:"E Female",ADMIN:"Admin"};c='<div style="background:var(--rbg);border:1px solid var(--rbd);border-radius:var(--radius-xs);padding:12px;margin-bottom:14px;font-size:11px;color:var(--r);font-weight:600;display:flex;gap:8px;letter-spacing:.2px">'+I.lock+' Keep PINs secret</div>'+Object.entries(labels).map(([uid,l])=>'<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius-xs);padding:12px;margin-bottom:8px;display:flex;align-items:center;gap:10px;box-shadow:var(--shadow);"><div style="flex:1;font-weight:700;font-size:13px">'+l+'</div><input class="fi" id="p-'+uid+'" placeholder="'+(S.pinStatus[uid]?"\u2022\u2022\u2022\u2022":"New")+'" maxlength="6" type="password" style="width:70px;text-align:center;font-size:16px;font-weight:900;letter-spacing:3px;padding:8px" autocomplete="off"><button class="btn" style="width:auto;padding:8px 12px" data-sp="'+uid+'">'+I.save+'</button></div>').join("")+'<div style="margin-top:20px;padding-top:16px;border-top:1.5px solid var(--border)"><div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:10px">Data Tools</div><button class="btn2" id="bmigrate" style="font-size:12px;padding:10px">Migrate Ward/Room Data</button></div>';}
  return'<div class="screen"><div class="hdr"><button class="hbtn" id="bb">'+I.back+'</button><div class="hdr-c" style="text-align:center"><h1>Admin</h1></div><div style="width:36px"></div></div><div class="tabs">'+tabs.map(t=>'<div class="tab'+(S.adminTab===t.id?" act":"")+'" data-tab="'+t.id+'">'+t.l+'</div>').join("")+'</div><div class="sp" style="padding:10px 12px 80px">'+c+'</div></div>';
}

function updatePinDisplay(){
  if(S.screen!=="pin")return;
  const body=$("pin-body");
  if(body){
    body.classList.toggle("pin-shake",S.pinError);
    body.classList.toggle("pin-checking",S._pinChecking);
  }
  const titleEl=$("pin-title");
  if(titleEl){
    const titleText=S.pinError?"Wrong PIN":S.pinOk?"Verified":S._pinChecking?"Verifying...":"Enter PIN";
    titleEl.textContent=titleText;
    titleEl.classList.toggle("t-err",S.pinError);
  }
  const dots=document.querySelectorAll("#pin-dots .pdot");
  const len=S.pinVal.length;
  dots.forEach((dot,idx)=>{dot.classList.remove("f","ok","err");
    if(S.pinOk&&idx<len)dot.classList.add("ok");
    else if(S.pinError&&idx<len)dot.classList.add("err");
    else if(idx<len)dot.classList.add("f");
  });
}

function bindAll(){
  document.querySelectorAll("[data-unit]").forEach(b=>b.addEventListener("click",()=>{S.pinTarget=b.dataset.unit;S.pinVal="";S.pinError=false;S.pinOk=false;S._pinChecking=false;S._pinNeedsLayout=true;S.screen="pin";render();}));
  const bfl=$("bfl");if(bfl)bfl.addEventListener("click",()=>{
    const r=$("cr");r.innerHTML='<div class="c-overlay"><div class="modal"><div style="font-size:15px;font-weight:800;margin-bottom:6px">Export PDF</div><div style="font-size:12px;color:var(--muted);margin-bottom:20px">Include attending doctor names in the export?</div><div style="display:flex;gap:8px"><button class="btn2" id="ex-no" style="flex:1">Without Doctors</button><button class="btn" id="ex-yes" style="flex:1">With Doctors</button></div></div></div>';
    $("ex-yes").addEventListener("click",()=>{r.innerHTML="";exportFullList(true);});
    $("ex-no").addEventListener("click",()=>{r.innerHTML="";exportFullList(false);});
  });
  const bwv=$("bwv");if(bwv)bwv.addEventListener("click",()=>{S.wardSearch="";S.wardSelected=null;S.screen="wardview";render();});
  const ba=$("ba");if(ba)ba.addEventListener("click",()=>{S.pinTarget="ADMIN";S.pinVal="";S.pinError=false;S.pinOk=false;S._pinChecking=false;S._pinNeedsLayout=true;S.screen="pin";render();});
  const bb=$("bb");if(bb)bb.addEventListener("click",()=>{if(S.screen==="ward"||S.screen==="admin"){S.screen="home";S.showCivil={};S._fromAdmin=false;render();}else if(S.screen==="wardview"){S.screen="home";render();}else if(S.screen==="detail"||S.screen==="add"){if(S._fromAdmin){S._fromAdmin=false;S.screen="admin";render();}else if(S._fromWardView){S._fromWardView=false;S.screen="wardview";render();}else{S.screen="ward";render();}}else if(S.screen==="pin"){S.screen="home";render();}});
  const bdl=$("bdl");if(bdl)bdl.addEventListener("click",()=>{
    const r=$("cr");r.innerHTML='<div class="c-overlay"><div class="modal"><div style="font-size:15px;font-weight:800;margin-bottom:6px">Export PNG</div><div style="font-size:12px;color:var(--muted);margin-bottom:20px">Include attending doctor names?</div><div style="display:flex;gap:8px"><button class="btn2" id="ex-no" style="flex:1">Without Doctors</button><button class="btn" id="ex-yes" style="flex:1">With Doctors</button></div></div></div>';
    $("ex-yes").addEventListener("click",()=>{r.innerHTML="";backupPNG(true);});
    $("ex-no").addEventListener("click",()=>{r.innerHTML="";backupPNG(false);});
  });
  const tc=$("tc");if(tc&&S.editP)tc.addEventListener("click",e=>{e.stopPropagation();const show=!S.showCivil[S.editP._k];S.showCivil[S.editP._k]=show;if(show)audit("view_civil",S.unit,S.editP.name);render();});
  document.querySelectorAll("[data-pin]").forEach(k=>k.addEventListener("click",()=>{const v=k.dataset.pin;if(v==="\u232b"){if(S.pinVal.length){S.pinVal=S.pinVal.slice(0,-1);try{navigator.vibrate(40);}catch(e){}}S.pinError=false;S.pinOk=false;S._pinChecking=false;updatePinDisplay();return;}if(S.pinOk||S._pinChecking)return;if(S.pinVal.length<4){S.pinVal+=v;try{navigator.vibrate(25);}catch(e){}k.classList.add("pkey-tap");setTimeout(()=>k.classList.remove("pkey-tap"),200);}S.pinError=false;S.pinOk=false;updatePinDisplay();if(S.pinVal.length===4)checkPin();}));
  document.querySelectorAll("[data-filt]").forEach(f=>f.addEventListener("click",()=>{S.filter=f.dataset.filt;render();}));
  const si=$("si");if(si)si.addEventListener("input",e=>{S.search=e.target.value;render();});
  document.querySelectorAll(".pc").forEach(c=>c.addEventListener("click",()=>{const p=S.patients.find(x=>x._k===c.dataset.key);if(p){S.editP=p;S.editCode=p.code;S.screen="detail";render();}}));
  document.querySelectorAll("[data-cpick='e']").forEach(c=>c.addEventListener("click",()=>{S.editCode=+c.dataset.code;render();}));
  document.querySelectorAll("[data-cpick='a']").forEach(c=>c.addEventListener("click",()=>{const an=$("an"),ac=$("ac"),at=$("at"),aw=$("aw"),arm=$("arm"),ao=$("ao"),adr=$("adr");if(an)S._addName=an.value;if(ac)S._addCivil=ac.value;if(at)S._addNat=at.value;if(aw)S._addWard=aw.value;if(arm)S._addRoom=arm.value;if(ao)S._addNotes=ao.value;if(adr)S._addDoctor=adr.value;S.addCode=+c.dataset.code;render();}));
  const bs=$("bs");if(bs)bs.addEventListener("click",async()=>{const ward=$("ew").value.trim(),room=$("erm")?$("erm").value.trim():"",notes=$("en").value.trim(),doctor=$("edr")?$("edr").value.trim():"";if(ward.length>30){toast("Ward too long","err");return;}if(room.length>30){toast("Room too long","err");return;}if(notes.length>500){toast("Notes too long","err");return;}if(doctor.length>100){toast("Doctor name too long","err");return;}bs.disabled=true;const data={...S.editP,ward,room,code:S.editCode,notes,doctor,ts:Date.now()};delete data._k;try{await set(ref(db,"patients/"+S.unit+"/"+S.editP._k),data);audit("edit",S.unit,data.name);toast("Saved");}catch(e){await LS.queueOp({type:"set",path:"patients/"+S.unit+"/"+S.editP._k,data});await _offlineUpdate(S.unit,S.editP._k,data);toast("Saved offline","ok");}if(S._fromWardView){S._fromWardView=false;S.screen="wardview";}else if(S._fromAdmin){S._fromAdmin=false;S.screen="admin";await listenAll();}else{S.screen="ward";}render();});
  const bd=$("bd");if(bd)bd.addEventListener("click",async()=>{if(!await confirm2("Delete?","Remove \""+esc(S.editP.name)+"\"?"))return;try{await remove(ref(db,"patients/"+S.unit+"/"+S.editP._k));audit("delete",S.unit,S.editP.name);toast("Deleted");}catch(e){await LS.queueOp({type:"remove",path:"patients/"+S.unit+"/"+S.editP._k});await _offlineRemove(S.unit,S.editP._k);toast("Deleted offline","ok");}if(S._fromWardView){S._fromWardView=false;S.screen="wardview";}else if(S._fromAdmin){S._fromAdmin=false;S.screen="admin";await listenAll();}else{S.screen="ward";}render();});
  const badd=$("badd");if(badd)badd.addEventListener("click",()=>{S.addCode=null;S._addName="";S._addCivil="";S._addNat="";S._addWard="";S._addRoom="";S._addNotes="";S._addDoctor="";S.screen="add";render();});
  const bsa=$("bsa");if(bsa)bsa.addEventListener("click",async()=>{const n=$("an").value.trim(),c=$("ac").value.trim(),w=$("aw").value.trim(),rm=$("arm")?$("arm").value.trim():"",nat=$("at").value.trim(),notes=$("ao").value.trim(),doctor=$("adr")?$("adr").value.trim():"";if(!n||!c||!w||!S.addCode){toast("Fill required","err");return;}
    if(n.length>200){toast("Name too long (max 200)","err");return;}
    if(c.length>20){toast("Civil ID too long","err");return;}
    if(!/^\d+$/.test(c)){toast("Civil ID must be numeric","err");return;}
    if(w.length>30){toast("Ward too long","err");return;}
    if(rm.length>30){toast("Room too long","err");return;}
    if(nat.length>50){toast("Nationality too long","err");return;}
    if(notes.length>500){toast("Notes too long (max 500)","err");return;}
    // Duplicate detection by Civil ID
    const dup=S.patients.find(p=>p.civil&&p.civil===c);if(dup&&!confirm("Patient with Civil ID "+c+" already exists ("+dup.name+"). Add anyway?")){return;}if(doctor.length>100){toast("Doctor name too long","err");return;}bsa.disabled=true;const data={name:n,civil:c,nat,ward:w,room:rm,code:S.addCode,notes,doctor,ts:Date.now()};try{await push(ref(db,"patients/"+S.unit),data);audit("add",S.unit,data.name);toast("Added");}catch(e){const offKey="off_"+Date.now();await LS.queueOp({type:"push",path:"patients/"+S.unit,data});await _offlineUpdate(S.unit,offKey,data);toast("Added offline","ok");}S.screen="ward";render();});
  document.querySelectorAll("[data-tab]").forEach(t=>t.addEventListener("click",()=>{S.adminTab=t.dataset.tab;render();}));
  // Admin accordion toggles
  document.querySelectorAll("[data-toggle]").forEach(h=>h.addEventListener("click",()=>{const u=h.dataset.toggle;S.expandedUnits[u]=!S.expandedUnits[u];render();}));
  const admS=$("adm-search");if(admS){admS.addEventListener("input",e=>{S.adminSearch=e.target.value;render();const el=$("adm-search");if(el){el.focus();el.selectionStart=el.selectionEnd=el.value.length;}});}
  document.querySelectorAll("[data-af]").forEach(f=>f.addEventListener("click",()=>{S.adminFilter=f.dataset.af;render();}));
  document.querySelectorAll(".acc-row-click").forEach(r=>{r.style.cursor="pointer";r.addEventListener("click",async e=>{e.stopPropagation();const uid=r.dataset.auid,key=r.dataset.akey;if(!uid||!key)return;const pData=(S.allData[uid]||{})[key];if(!pData)return;S._fromAdmin=true;S.unit=uid;S.patients=Object.entries(S.allData[uid]||{}).map(([k,v])=>({...v,_k:k}));S.editP={...pData,_k:key};S.editCode=pData.code;S.screen="detail";render();});});
  // Ward view bindings
  document.querySelectorAll("[data-ward]").forEach(c=>c.addEventListener("click",()=>{S.wardSelected=c.dataset.ward;render();}));
  const ws=$("ward-search");if(ws){ws.addEventListener("input",e=>{S.wardSearch=e.target.value;render();const el=$("ward-search");if(el){el.focus();el.selectionStart=el.selectionEnd=el.value.length;}});}
  const bwback=$("bwback");if(bwback)bwback.addEventListener("click",()=>{S.wardSelected=null;render();});
  // Ward view patient clicks (reuse acc-row-click but set _fromWardView)
  if(S.screen==="wardview"){document.querySelectorAll(".acc-row-click").forEach(r=>{r.style.cursor="pointer";r.addEventListener("click",async e=>{e.stopPropagation();const uid=r.dataset.auid,key=r.dataset.akey;if(!uid||!key)return;const pData=(S.allData[uid]||{})[key];if(!pData)return;S._fromWardView=true;S.unit=uid;S.patients=Object.entries(S.allData[uid]||{}).map(([k,v])=>({...v,_k:k}));S.editP={...pData,_k:key};S.editCode=pData.code;S.screen="detail";render();});});}
  const oz=$("oz");if(oz)oz.addEventListener("click",()=>{const f=$("of");if(f)f.click();});
  const of_=$("of");if(of_)of_.addEventListener("change",handleOCR);
  document.querySelectorAll("[data-ocr]").forEach(c=>c.addEventListener("click",()=>{const i=+c.dataset.ocr;if(S.ocrSel.includes(i))S.ocrSel=S.ocrSel.filter(x=>x!==i);else S.ocrSel.push(i);render();}));
  // OCR editable fields — save edits to ocrResults without full re-render
  document.querySelectorAll(".ocr-fi").forEach(el=>{
    const idx=+el.dataset.ocrF,key=el.dataset.ocrK;
    if(isNaN(idx)||!key||!S.ocrResults[idx])return;
    el.addEventListener("input",()=>{
      if(key==="code")S.ocrResults[idx][key]=+el.value;
      else S.ocrResults[idx][key]=el.value;
    });
    // On blur, update missing-data indicators
    el.addEventListener("blur",()=>{
      const p=S.ocrResults[idx];
      const card=el.closest(".ocr-card");if(!card)return;
      const missingName=!p.name||!p.name.trim(),missingCivil=!p.civil||!p.civil.trim(),missingWard=!p.ward||!p.ward.trim();
      card.classList.toggle("ocr-warn",missingName||missingCivil||missingWard);
      // Update import button count
      const validCount=S.ocrSel.filter(i=>{const q=S.ocrResults[i];return q.name&&q.name.trim()&&q.civil&&q.civil.trim()&&q.ward&&q.ward.trim();}).length;
      const btn=$("oi");if(btn){btn.disabled=!validCount;btn.textContent="Import "+validCount+" Patient"+(validCount!==1?"s":"");}
    });
    if(el.tagName==="SELECT")el.addEventListener("change",()=>{S.ocrResults[idx][key]=+el.value;});
  });
  const osa=$("osa");if(osa)osa.addEventListener("click",()=>{S.ocrSel=S.ocrSel.length===S.ocrResults.length?[]:S.ocrResults.map((_,i)=>i);render();});
  const oi=$("oi");if(oi)oi.addEventListener("click",importOCR);
  document.querySelectorAll("[data-sp]").forEach(b=>b.addEventListener("click",async()=>{const uid=b.dataset.sp,v=$("p-"+uid);const pv=v?v.value.trim():"";if(!pv||pv.length<4){toast("Min 4 digits","err");return;}if(!S.adminPin){toast("Admin session invalid","err");return;}try{await fnSetPin({adminPin:S.adminPin,unit:uid,newPin:pv});S.pinStatus[uid]=true;toast("Saved");}catch(e){toast(e.message||"Failed","err");}}));
  const baudit=$("bloadaudit");if(baudit)baudit.addEventListener("click",async()=>{
    if(!S.adminPin){toast("Admin session invalid","err");return;}
    S._auditLoading=true;S._auditLog=[];render();
    try{const res=await fnGetAuditLog({adminPin:S.adminPin,limit:200});S._auditLog=res.data.entries||[];}
    catch(e){toast("Failed: "+(e.message||"error"),"err");S._auditLog=null;}
    S._auditLoading=false;render();
  });
  const bmig=$("bmigrate");if(bmig)bmig.addEventListener("click",async()=>{bmig.disabled=true;bmig.textContent="Migrating...";try{await migrateWardRoom();}catch(e){toast("Migration error: "+e.message,"err");}bmig.disabled=false;bmig.textContent="Migrate Ward/Room Data";});
}

async function checkPin(){
  if(S._pinChecking)return;
  // Client-side lockout (server also rate-limits)
  if(S.pinLockUntil>Date.now()){const secs=Math.ceil((S.pinLockUntil-Date.now())/1000);toast("Locked for "+secs+"s","err");S.pinVal="";render();return;}
  S._pinChecking=true;
  updatePinDisplay();
  // Ensure auth is ready before calling Cloud Functions
  await _authP;
  if(!_authUid){try{await signInAnonymously(auth);}catch(e){toast("Auth failed — check connection","err");S.pinVal="";S._pinChecking=false;render();return;}}
  try{
    await fnVerifyPin({unit:S.pinTarget,pin:S.pinVal});
    try{navigator.vibrate(100);}catch(e){}
    S.pinFails=0;S.pinLockUntil=0;S.pinOk=true;render();
    await new Promise(r=>setTimeout(r,500));
    S.pinOk=false;S._pinChecking=false;
    if(S.pinTarget==="ADMIN"){S.adminPin=S.pinVal;S.screen="admin";S.adminTab="overview";audit("admin_access","ADMIN","");await listenAll();}
    else{S.screen="ward";S.filter="all";S.search="";S._bp=true;await listenUnit(S.pinTarget);}
    render();
  }catch(e){
    try{navigator.vibrate([50,30,50]);}catch(x){}
    const code=e.code||"";
    if(code==="functions/resource-exhausted"){S.pinLockUntil=Date.now()+60000;toast("Too many attempts. Locked.","err");}
    else if(code==="functions/permission-denied"||code==="functions/not-found"){
      S.pinFails++;if(S.pinFails>=5){S.pinLockUntil=Date.now()+60000*Math.min(S.pinFails-4,5);toast("Too many attempts. Locked.","err");}
    }else{toast("Error: "+(e.message||"offline"),"err");}
    S.pinError=true;render();
    await new Promise(r=>setTimeout(r,450));
    S.pinError=false;S.pinVal="";S._pinChecking=false;render();
  }
}

function handleOCR(e){const files=Array.from(e.target.files);if(!files.length)return;S.ocrResults=[];S.ocrSel=[];S.ocrLoading=true;S.ocrImg=null;render();
const readFile=f=>new Promise((ok,no)=>{const r=new FileReader();r.onload=ev=>ok({data:ev.target.result.split(",")[1],mime:f.type,url:ev.target.result});r.onerror=no;r.readAsDataURL(f);});
(async()=>{try{const imgs=await Promise.all(files.map(readFile));S.ocrImg=imgs[0].url;render();
const images=imgs.map(im=>({data:im.data,mime:im.mime}));
const result=await fnOcrExtract({images});
S.ocrResults=result.data.patients||[];
S.ocrSel=S.ocrResults.map((_,i)=>i);if(!S.ocrResults.length)toast("No patients found","err");
}catch(err){console.error("OCR error:",err);const msg=err.message||"OCR failed";toast(msg.length>60?msg.slice(0,60)+"…":msg,"err");S.ocrResults=[];}
S.ocrLoading=false;render();e.target.value="";})();}

async function importOCR(){const uid=$("ou")?.value;if(!uid||!S.ocrSel.length)return;const b=$("oi");b.disabled=true;try{for(const i of S.ocrSel){const p=S.ocrResults[i];await push(ref(db,"patients/"+uid),{name:p.name||"",civil:p.civil||"",nat:p.nat||"",ward:p.ward||"",room:p.room||"",code:+p.code||2,notes:p.notes||"",ts:Date.now()});}audit("ocr_import",uid,S.ocrSel.length+" patients");toast("Imported "+S.ocrSel.length);S.ocrResults=[];S.ocrSel=[];S.ocrImg=null;render();}catch(e){toast("Failed","err");b.disabled=false;}}

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
  await listenAll();S.screen="home";render();hideLaunchSplash();if(navigator.onLine)await syncQueue();
}catch(e){showFatal("Boot Error: "+e.message);}}
boot();

// Service Worker registration — only update if new version available
if("serviceWorker" in navigator){
  navigator.serviceWorker.register("/sw.js",{updateViaCache:"none"})
    .then(r=>{
      r.update().catch(()=>{});
      r.addEventListener("updatefound",()=>{
        const nw=r.installing;
        if(nw)nw.addEventListener("statechange",()=>{
          if(nw.state==="activated"){window.location.reload();}
        });
      });
    })
    .catch(err=>console.warn("SW registration failed",err));
}
