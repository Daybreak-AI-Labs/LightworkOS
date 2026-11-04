(function(){
  "use strict";
  // Users > Workspace members: who holds a role inside one workspace.
  // People are chosen from a list and shown by name; the exact sign-in
  // identity only ever travels in the request, never on screen.
  const root=document.getElementById("wm-root");if(!root||!root.dataset.tenant)return;
  const el=id=>document.getElementById("wm-"+id),picker=el("tenant");let busy=false,denied=false,labels={},roleNames={},rolePermissions={},roleOptions={};
  try{labels=JSON.parse(root.dataset.labels||"{}")||{};}catch(_){labels={};}
  try{roleNames=JSON.parse(root.dataset.roleLabels||"{}")||{};}catch(_){roleNames={};}
  try{rolePermissions=JSON.parse(root.dataset.rolePermissions||"{}")||{};}catch(_){rolePermissions={};}
  try{roleOptions=JSON.parse(root.dataset.roleOptions||"{}")||{};}catch(_){roleOptions={};}
  const globalAdmin=root.dataset.globalAdmin==="true",you=root.dataset.you||"";
  // The workspace being edited comes from the picker when the page offers one;
  // the stale-tab header stays the workspace the page was RENDERED under.
  const tenant=()=>picker&&picker.value?picker.value:root.dataset.tenant,base=()=>"/api/v1/admin/tenants/"+encodeURIComponent(tenant())+"/roles";
  const expected=()=>root.dataset.expected!==undefined?root.dataset.expected:tenant();
  const label=principal=>labels[principal]||"A colleague";
  const roleLabel=role=>roleNames[role]||(window.mvHuman?window.mvHuman(role):String(role));
  const inviteTenant=document.getElementById("wi-tenant"),inviteRole=document.getElementById("wi-role");
  function syncInviteRoles(){
    if(!inviteTenant||!inviteRole||globalAdmin)return;
    const selected=inviteRole.value;inviteRole.replaceChildren();
    for(const role of roleOptions[inviteTenant.value]||[]){const option=node("option",roleLabel(role));option.value=role;inviteRole.append(option);}
    inviteRole.value=Array.from(inviteRole.options).some(option=>option.value===selected)?selected:"viewer";
  }
  if(inviteTenant){inviteTenant.addEventListener("change",syncInviteRoles);syncInviteRoles();}
  const workspaceName=()=>{if(picker&&picker.selectedIndex>=0&&picker.options[picker.selectedIndex])return picker.options[picker.selectedIndex].textContent.trim();return root.dataset.tenantName||"this workspace";};
  const ask=(message,okText)=>window.mvConfirm?window.mvConfirm(message,{okText}):Promise.resolve(false);
  const access=window.LightworkAccessState.create(()=>tenant()+":"+expected(),lock);
  function node(tag,text,cls){const item=document.createElement(tag);item.textContent=text;if(cls)item.className=cls;return item;}
  function lock(){denied=true;labels={};root.dataset.labels="{}";el("list").replaceChildren();el("principal").replaceChildren();el("principal").value="";el("role").selectedIndex=0;root.querySelectorAll("button,input,select").forEach(control=>control.disabled=true);const invite=document.getElementById("wi-root");if(invite)invite.replaceChildren(node("p","Your account, workspace or administrator access changed. Reload Users before continuing.","muted"));el("status").textContent="Your account, workspace or administrator access changed. Reload Users before continuing.";}
  function roleHasAdmin(role){return (rolePermissions[role]||[]).includes("admin");}
  function syncRoles(){
    if(globalAdmin||!Object.keys(roleOptions).length)return;
    const choice=el("role"),selected=choice.value;
    choice.replaceChildren();const blank=node("option","Choose a role");blank.value="";blank.disabled=true;choice.append(blank);
    for(const role of roleOptions[tenant()]||[]){const option=node("option",roleLabel(role));option.value=role;choice.append(option);}
    choice.value=Array.from(choice.options).some(option=>option.value===selected)?selected:"";
  }
  function syncMembers(members){
    const choice=el("principal");if(globalAdmin||choice.tagName!=="SELECT")return;
    const selected=choice.value;choice.replaceChildren();
    const blank=node("option","Choose a colleague…");blank.value="";blank.disabled=true;choice.append(blank);
    for(const principal of Object.keys(members).sort((a,b)=>label(a).localeCompare(label(b)))){
      const option=node("option",label(principal));option.value=principal;choice.append(option);
    }
    choice.value=Object.hasOwn(members,selected)?selected:"";
  }
  function problem(response,action){return window.mvErrorText?window.mvErrorText(response,action):"Could not "+action+". Try again.";}
  async function api(path,options={},action="load the workspace members"){
    const token=access.capture();
    const headers={"Content-Type":"application/json","X-Lightwork-Workspace-People-Context":root.dataset.context},exp=expected();if(exp)headers["X-Lightwork-Expected-Tenant"]=exp;
    const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),15000);
    let response,data;try{
    response=await fetch(base()+path,{...options,credentials:"same-origin",headers,signal:controller.signal});
    if(response.redirected){access.invalidate("session");throw new Error("Sign in again and reload Users.");}
    access.assertCurrent(token);
    if(["session","scope"].includes(access.observe(response,null,{forbiddenScope:true}).kind)){throw new Error("Your sign-in or administrator access changed. Sign in again and reload Users.");}
    if(response.status===204)return null;
    try{data=await response.json();}catch(_){throw new Error(problem(response.ok?{status:500}:response,action));}
    access.assertCurrent(token);
    if(access.observe(response,data,{forbiddenScope:true,contextMessage:/account or workspace changed|active workspace changed/i}).kind==="context")throw new Error("The account or workspace changed. Reload Users before continuing.");
    if(!response.ok)throw new Error(problem({status:response.status,detail:data&&data.detail},action));return data;
    }finally{clearTimeout(timeout);}
  }
  async function load(){
    const members=await api("");el("list").replaceChildren();syncMembers(members);
    const adminCount=Object.values(members).filter(roleHasAdmin).length;
    for(const [principal,role] of Object.entries(members)){
      const li=node("li","",""),name=node("span",label(principal),"wm-name"),badge=node("span",roleLabel(role),"badge");
      const edit=node("button","Change role","btn"),remove=node("button","Clear role","btn btn--danger");edit.type=remove.type="button";
      edit.setAttribute("aria-label","Change "+label(principal)+"'s role");remove.setAttribute("aria-label","Clear "+label(principal)+"'s role in "+workspaceName());
      if((!globalAdmin&&principal===you)||(adminCount<=1&&roleHasAdmin(role))){remove.disabled=true;remove.title="Keep a workspace administrator in place before clearing this role.";}
      edit.addEventListener("click",()=>{if(Array.from(el("principal").options||[]).some(o=>o.value===principal))el("principal").value=principal;el("role").value=role;el("role").focus();});
      remove.addEventListener("click",()=>action(async()=>{if(!await ask("Clear "+label(principal)+"'s workspace role in "+workspaceName()+"? This removes direct membership. Their standard access still applies elsewhere, and installation administrators may still enter. To keep them here with limited access, give them the Viewer role.","Clear role"))return;await api("/"+encodeURIComponent(principal),{method:"DELETE"},"clear this workspace role");await load();}));
      li.append(name," ",badge," ",edit," ",remove);el("list").append(li);
    }
    if(!Object.keys(members).length)el("list").append(node("li","No one has a role just for this workspace yet. Choose a colleague below to add one.","muted"));
    el("status").textContent="Showing members of "+workspaceName()+".";
  }
  async function action(work){if(busy||denied)return;busy=true;const controls=Array.from(root.querySelectorAll("button,input,select")).map(control=>[control,control.disabled]);controls.forEach(([control])=>control.disabled=true);try{await work();}catch(error){el("status").textContent=error&&error.message?error.message:problem(error,"update the workspace members");}finally{busy=false;if(!denied)controls.forEach(([control,wasDisabled])=>control.disabled=wasDisabled);}}
  el("refresh").addEventListener("click",()=>action(load));
  if(picker)picker.addEventListener("change",()=>{access.advance();root.dataset.tenant=picker.value;el("list").replaceChildren();syncRoles();el("status").textContent="Loading members of "+workspaceName()+"…";action(load);});
  el("form").addEventListener("submit",event=>{event.preventDefault();action(async()=>{
    const principal=el("principal").value.trim(),role=el("role").value;
    if(!principal.startsWith("user:")||principal.length<=5)throw new Error("Choose a colleague from the list.");
    if(!globalAdmin&&principal===you&&!roleHasAdmin(role))throw new Error("Keep your administrator role or ask another workspace administrator to make this change.");
    if(!await ask("Give "+label(principal)+" the "+roleLabel(role)+" role in "+workspaceName()+"?","Save"))return;
    await api("/"+encodeURIComponent(principal),{method:"PUT",body:JSON.stringify({role})},"save this workspace member");await load();
  });});
  if(root.dataset.autoload==="true")action(load);
  window.addEventListener("lightwork:context-changed",()=>access.invalidate("context"));
  window.addEventListener("storage",event=>{if(event.key==="lightwork-workspace-changed")access.invalidate("context");});
  window.LightworkWorkspacePeople={open:async context=>{
    if(denied||busy||context!==root.dataset.context)return false;
    const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),15000);
    try{const response=await fetch("/api/v1/users/workspace-context",{credentials:"same-origin",signal:controller.signal});
      if(response.redirected||[401,403].includes(response.status)){access.invalidate("scope");return false;}
      const current=await response.json();if(!response.ok)return false;
      if(current.context!==context){access.invalidate("context");return false;}
      const target=document.getElementById("wi-email")||picker||el("refresh");target.scrollIntoView({block:"center"});target.focus();requestAnimationFrame(()=>{if(!denied&&context===root.dataset.context&&target.isConnected){target.scrollIntoView({block:"center"});target.focus();}});return true;
    }catch(_){return false;}finally{clearTimeout(timeout);}
  }};
})();
