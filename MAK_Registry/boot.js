function showFatal(msg){
  var div=document.createElement("div");
  div.style.cssText="padding:40px;color:red;font-size:13px;word-break:break-all";
  div.textContent=msg;
  var app=document.getElementById("app");
  if(app){app.textContent="";app.appendChild(div);}
  else document.body.prepend(div);
}
window.onerror=function(m,s,l){showFatal("Error: "+m+" (Line: "+l+")");};
window.onunhandledrejection=function(e){showFatal("Promise Error: "+(e.reason&&e.reason.message||e.reason));};
