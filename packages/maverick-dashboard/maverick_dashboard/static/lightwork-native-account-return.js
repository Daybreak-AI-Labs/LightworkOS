/* Native commands require a backend ticket shared only by this shell's dashboard child. */
(() => {
  'use strict';
  const callback='http://127.0.0.1:8766/connections',profile='desktop-loopback-v1';
  const available=()=>location.href==='http://127.0.0.1:8765/connections'&&typeof window.__TAURI__?.core?.invoke==='function';
  const validTicket=value=>typeof value==='string'&&value.length>=100&&value.length<=8192&&/^(?:[a-f0-9]{2})+\.[a-f0-9]{64}$/.test(value);
  function create({onReturn,onFailure,getContext}){
    let attempt=null,timer=null;
    const invoke=(command,payload)=>window.__TAURI__.core.invoke(command,payload);
    const stopTimer=()=>{if(timer!==null)clearTimeout(timer);timer=null;};
    async function cancel(){
      const current=attempt;if(!current)return true;
      stopTimer();current.cancelling=true;
      try{await invoke('cancel_oauth_return',{handle:current.handle,context:current.context,ticket:current.launchTicket||current.prepareTicket});}
      catch(_){current.cancelling=false;if(attempt===current&&current.launched)timer=setTimeout(poll,500);throw new Error('The native account-return receiver could not be closed. Retry Cancel sign-in.');}
      if(attempt===current)attempt=null;
      return true;
    }
    async function fail(message,details={}){
      const current=attempt;
      try{await cancel();await Promise.resolve(onFailure(message,{...details,state:details.state||current?.state||'',context:current?.context||'',return_profile:profile,native_closed:true}));}
      catch(_){await Promise.resolve(onFailure(message+' The local receiver could not be closed; use Cancel sign-in to retry.',{...details,state:details.state||current?.state||'',context:current?.context||'',return_profile:profile,native_closed:false}));}
    }
    async function poll(){
      const current=attempt;if(!current||current.cancelling)return;
      if(getContext()!==current.context){await fail('The account or workspace changed. Refresh Connections before starting again.');return;}
      try{
        const result=await invoke('consume_oauth_return',{handle:current.handle,context:current.context,ticket:current.launchTicket});
        if(attempt!==current||current.cancelling)return;
        if(getContext()!==current.context){await fail('The account or workspace changed. Refresh Connections before starting again.');return;}
        if(!result||result.context!==current.context)throw new Error();
        if(result.outcome==='pending'){timer=setTimeout(poll,500);return;}
        if(result.outcome==='returned'&&result.state===current.state&&typeof result.code==='string'&&result.code.length>0&&result.code.length<=8192&&!/[\x00-\x1f\x7f]/.test(result.code)){
          attempt=null;stopTimer();onReturn({state:result.state,code:result.code,context:current.context,return_profile:profile});return;
        }
        if(['denied','expired','unavailable'].includes(result.outcome)){
          attempt=null;stopTimer();const message={denied:'The provider denied sign-in. Your original request and connection choices are kept.',expired:'Account sign-in expired. Your original request and connection choices are kept.',unavailable:'The account-return receiver became unavailable. Your original request and connection choices are kept.'}[result.outcome];
          await Promise.resolve(onFailure(message,{outcome:result.outcome,state:current.state,context:current.context,return_profile:profile,native_closed:true}));return;
        }
        await fail('The native account return could not be verified. Start a new sign-in.');
      }catch(_){if(attempt===current)await fail('The native account return could not be confirmed. Refresh Connections and start again.');}
    }
    async function prepare(context,ticket){
      if(!available()||attempt||!/^[a-f0-9]{64}$/.test(context)||!validTicket(ticket))throw new Error('Desktop account return is unavailable. Cancel any pending sign-in and retry.');
      let result;try{result=await invoke('prepare_oauth_return',{context,ticket});}catch(_){throw new Error('The registered account-return port is unavailable, or this dashboard’s desktop authorization could not be verified. Cancel other sign-in attempts, then retry.');}
      if(!result||!/^[a-f0-9]{64}$/.test(result.handle)||result.context!==context||result.return_profile!==profile||result.callback_uri!==callback||result.expires_in!==600){
        if(result&&typeof result.handle==='string'){try{await invoke('cancel_oauth_return',{handle:result.handle,context,ticket});}catch(_) {}}
        throw new Error('The native account-return address could not be verified. Refresh the page and try again.');
      }
      attempt={handle:result.handle,context,state:null,launched:false,cancelling:false,prepareTicket:ticket,launchTicket:null};
      return {callback_uri:callback,return_profile:profile,handle:result.handle};
    }
    async function launch(authorizeUrl,state,ticket){
      const current=attempt;if(!current||current.launched||current.cancelling||getContext()!==current.context||!/^[-_a-zA-Z0-9]{40,64}$/.test(state)||!validTicket(ticket))throw new Error('Refresh Connections and start a new sign-in.');
      current.state=state;current.launchTicket=ticket;current.launched=true;
      try{await invoke('launch_oauth_return',{handle:current.handle,context:current.context,authorizeUrl,state,ticket});}
      catch(_){throw new Error('The system browser could not open. Cancel this sign-in and try again.');}
      if(attempt===current)timer=setTimeout(poll,0);
    }
    window.addEventListener('pagehide',()=>{void cancel().catch(()=>{});});
    return Object.freeze({prepare,launch,cancel,hasAttempt:()=>attempt!==null});
  }
  window.LightworkNativeAccountReturn=Object.freeze({available,create,callback,profile});
})();
