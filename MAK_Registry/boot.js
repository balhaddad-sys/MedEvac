function showFatal(html){
  const app=document.getElementById("app");
  if(app)app.innerHTML=html;
  else document.body.insertAdjacentHTML("afterbegin",html);
}
window.onerror=function(m,s,l,c,e){showFatal('<div style="padding:40px;color:red;font-size:13px;word-break:break-all"><b>Error:</b> '+m+'<br>Line: '+l+'</div>');};
window.onunhandledrejection=function(e){showFatal('<div style="padding:40px;color:red;font-size:13px;word-break:break-all"><b>Promise Error:</b> '+(e.reason?.message||e.reason)+'</div>');};
