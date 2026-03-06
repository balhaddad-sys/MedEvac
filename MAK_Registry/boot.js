function showFatal(msg){
  var div=document.createElement("div");
  div.style.cssText="padding:40px;color:#dc2626;font-size:13px;word-break:break-all;font-family:Inter,system-ui,sans-serif;background:#f0f4f8";
  div.textContent=msg;
  var app=document.getElementById("app");
  if(app){app.textContent="";app.appendChild(div);}
  else document.body.prepend(div);
}
window.onerror=function(m,s,l){showFatal("Error: "+m+" (Line: "+l+")");};
window.onunhandledrejection=function(e){showFatal("Promise Error: "+(e.reason&&e.reason.message||e.reason));};
