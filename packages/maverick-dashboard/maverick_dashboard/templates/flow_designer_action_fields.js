// Ordinary typed action details; native saved definitions and approvals still bind execution.
var FDActionFields = (function () {
  'use strict';
  var cache = new Map(), pending = new Map(), counter = 0, MAX_ITEMS = 128;
  var kinds = ['string', 'integer', 'number', 'boolean', 'object', 'array', 'null'];
  var names = {string:'Text', integer:'Whole number', number:'Number', boolean:'Yes or no', object:'Details', array:'List', null:'No value'};
  var annotations = ['title', 'description', 'default', 'examples', '$schema', '$id', '$defs', 'definitions', 'deprecated', 'readOnly', 'writeOnly', 'enumNames'];
  var constraints = {object:['properties','required','additionalProperties','minProperties','maxProperties'],array:['items','minItems','maxItems','uniqueItems'],
    string:['minLength','maxLength','format'],integer:['minimum','maximum','exclusiveMinimum','exclusiveMaximum','multipleOf'],number:['minimum','maximum','exclusiveMinimum','exclusiveMaximum','multipleOf'],boolean:[],null:[]};
  function obj(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
  function human(s) { return String(s).replace(/([a-z0-9])([A-Z])/g,'$1 $2').replace(/[_-]+/g,' ').replace(/^./,function(c){return c.toUpperCase();}); }
  function bad() { throw new Error('This action has fields this form cannot display safely. Choose another action or ask the connection owner to update its field description. Your saved values are kept.'); }
  function protectedField(){throw new Error('This action requires protected connection information that this workflow form cannot pass safely. Use Connections to manage passwords and keys, then choose an action that uses a saved connection. Your saved details are kept.');}
  function compile(source) {
    var budget = 2048;
    function visit(s, depth, refs) {
      if (!obj(s) || depth > 10 || --budget < 0) bad();
      if(s.writeOnly!==undefined&&typeof s.writeOnly!=='boolean')bad();
      if(s.writeOnly===true)protectedField();
      if (s.$ref) {
        if (typeof s.$ref !== 'string' || !s.$ref.startsWith('#/') || refs.indexOf(s.$ref) >= 0) bad();
        var target = source;
        s.$ref.slice(2).split('/').forEach(function (key) { key=key.replace(/~1/g,'/').replace(/~0/g,'~');target = obj(target)&&Object.prototype.hasOwnProperty.call(target,key)?target[key]:undefined; });
        if (!obj(target)) bad();
        if(target.writeOnly===true)protectedField();
        var siblings = Object.assign(Object.create(null), s); delete siblings.$ref;
        if (Object.keys(siblings).some(function (key) { return annotations.indexOf(key) < 0; })) bad();
        return visit(Object.assign(Object.create(null), target, siblings), depth + 1, refs.concat(s.$ref));
      }
      var types = s.type;
      if (Array.isArray(types)) {
        if (!types.length || types.length > 7 || new Set(types).size !== types.length || types.some(function(t){return kinds.indexOf(t)<0;})) bad();
        return {type:'union', title:s.title, variants:types.map(function(t){var variant=Object.assign(Object.create(null),s,{type:t});delete variant.title;Object.keys(variant).forEach(function(k){if(Object.values(constraints).some(function(keys){return keys.indexOf(k)>=0;})&&constraints[t].indexOf(k)<0)delete variant[k];});return visit(variant,depth+1,refs);})};
      }
      var alternatives = s.oneOf || s.anyOf;
      if (alternatives) {
        if (s.oneOf && s.anyOf) bad();
        if (!Array.isArray(alternatives) || !alternatives.length || alternatives.length > 12 ||
            Object.keys(s).some(function(k){return annotations.indexOf(k)<0 && k!=='oneOf' && k!=='anyOf';})) bad();
        var variants = alternatives.map(function(a){return visit(a,depth+1,refs);});
        return {type:'union', variants:variants, title:s.title, exactly:!!s.oneOf};
      }
      var type = types || (s.properties ? 'object' : s.items ? 'array' : undefined);
      if (!type && (s.enum || Object.prototype.hasOwnProperty.call(s,'const'))) {
        var example = s.enum ? s.enum[0] : s.const; type = example === null ? 'null' : Array.isArray(example)?'array':typeof example;
      }
      if (!type && !Object.keys(s).some(function(k){return annotations.indexOf(k)<0;})) return {type:'any', title:s.title};
      if (kinds.indexOf(type) < 0) bad();
      if (Object.keys(s).some(function(k){return annotations.indexOf(k)<0 && ['type','enum','const'].concat(constraints[type]).indexOf(k)<0;})) bad();
      ['minimum','maximum','exclusiveMinimum','exclusiveMaximum','multipleOf','minLength','maxLength','minItems','maxItems','minProperties','maxProperties'].forEach(function(k){if(s[k]!==undefined&&(typeof s[k]!=='number'||!Number.isFinite(s[k])||/^min(?:Length|Items|Properties)$|^max(?:Length|Items|Properties)$/.test(k)&&(!Number.isSafeInteger(s[k])||s[k]<0)||k==='multipleOf'&&s[k]<=0))bad();});
      if(s.uniqueItems!==undefined&&typeof s.uniqueItems!=='boolean'||s.additionalProperties!==undefined&&typeof s.additionalProperties!=='boolean'&&!obj(s.additionalProperties))bad();
      var plan = {type:type, spec:s, title:s.title, props:[], choices:null};
      if (Object.prototype.hasOwnProperty.call(s,'const') && typeof s.const==='object' && s.const!==null && typeof s.title==='string') {
        var fixedBase=Object.assign(Object.create(null),s,{type:type});delete fixedBase.const;
        if(issue(visit(fixedBase,depth+1,refs),s.const,'Named choice'))bad();
        return {type:'fixed',value:s.const,title:s.title};
      }
      if (s.enum !== undefined || Object.prototype.hasOwnProperty.call(s,'const')) {
        var vals = s.enum !== undefined ? s.enum : [s.const];
        if (!Array.isArray(vals) || !vals.length || vals.length>128 || vals.some(function(v){return v!==null && typeof v==='object';})) bad();
        plan.choices = vals.map(function(v,i){return {value:v,label:Array.isArray(s.enumNames)&&typeof s.enumNames[i]==='string'?s.enumNames[i]:v===null?'No value':typeof v==='boolean'?(v?'Yes':'No'):human(v)};});
      }
      if (type === 'object') {
        var props = s.properties || {};
        if (!obj(props) || Object.keys(props).length>128 || s.required !== undefined && (!Array.isArray(s.required) || s.required.some(function(k){return typeof k!=='string' || !Object.prototype.hasOwnProperty.call(props,k);}))) bad();
        Object.keys(props).forEach(function(k){plan.props.push({key:k,required:(s.required||[]).indexOf(k)>=0,node:visit(props[k],depth+1,refs)});});
        plan.extra = s.additionalProperties === false ? null : visit(obj(s.additionalProperties)?s.additionalProperties:{},depth+1,refs);
      } else if (type === 'array') {
        if (s.items === false || Array.isArray(s.items)) bad();
        plan.item = visit(s.items || {},depth+1,refs);
      } else if (type==='string' && s.format && ['date','date-time','email','uri','url','uuid'].indexOf(s.format)<0) bad();
      return plan;
    }
    var tree = visit(source,0,[]); if (tree.type !== 'object') bad(); return tree;
  }
  function typeOf(v) { return v===null?'null':Array.isArray(v)?'array':obj(v)?'object':typeof v==='number'&&Number.isSafeInteger(v)?'integer':typeof v; }
  function stable(v) { return obj(v)?'{'+Object.keys(v).sort().map(function(k){return JSON.stringify(k)+':'+stable(v[k]);}).join(',')+'}':Array.isArray(v)?'['+v.map(stable).join(',')+']':JSON.stringify(v); }
  function day(v) { var d=new Date(v+'T00:00:00Z');return /^\d{4}-\d{2}-\d{2}$/.test(v)&&Number.isFinite(d.getTime())&&d.toISOString().slice(0,10)===v; }
  function issue(p,v,path,depth) {
    path = path || 'Action details';
    depth = depth || 0;
    if(depth>10)return path+': use fewer nested details.';
    if(p.type==='fixed')return stable(v)===stable(p.value)?undefined:path+': choose the named option.';
    if (p.type==='any') {
      var kind=typeOf(v);if(kinds.indexOf(kind)<0)return path+': enter a value.';
      if(kind==='object'||kind==='array'){
        var entries=Object.entries(v);if(entries.length>MAX_ITEMS)return path+': use no more than '+MAX_ITEMS+' items.';
        for(var entry of entries){var e=issue(p,entry[1],path+' › '+human(entry[0]),depth+1);if(e)return e;}
      }else if(kind==='string')return issue({type:'string',spec:{}},v,path,depth);
      else if(kind==='number'&&(!Number.isFinite(v)||Number.isInteger(v)&&!Number.isSafeInteger(v)))return path+': enter a number this form can preserve exactly.';
      return undefined;
    }
    if (p.type==='union') { var matched=p.variants.filter(function(a){return !issue(a,v,path,depth);}).length; return matched && (!p.exactly || matched===1)?undefined:path+': choose an allowed kind of value.'; }
    var t=typeOf(v), s=p.spec;
    if (t!==p.type && !(p.type==='number'&&t==='integer')) return path+': choose '+names[p.type].toLowerCase()+'.';
    if (p.choices && !p.choices.some(function(c){return Object.is(c.value,v);})) return path+': choose one of the listed values.';
    if (p.type==='object') {
      var keys=Object.keys(v);
      if (keys.length>MAX_ITEMS || s.minProperties!==undefined && keys.length<s.minProperties || s.maxProperties!==undefined && keys.length>s.maxProperties) return path+': check how many details are included.';
      for(var i=0;i<p.props.length;i++) { var field=p.props[i], has=Object.prototype.hasOwnProperty.call(v,field.key); if(field.required&&!has)return path+' › '+human(field.key)+': enter this required detail.'; if(has){var e=issue(field.node,v[field.key],path+' › '+human(field.key),depth+1);if(e)return e;} }
      for(var k of keys) if(!p.props.some(function(f){return f.key===k;})){if(!p.extra)return path+': remove the detail '+human(k)+'.';var extra=issue(p.extra,v[k],path+' › '+human(k),depth+1);if(extra)return extra;}
    } else if (p.type==='array') {
      if(v.length>MAX_ITEMS || s.minItems!==undefined&&v.length<s.minItems || s.maxItems!==undefined&&v.length>s.maxItems)return path+': check the number of items.';
      if(s.uniqueItems && new Set(v.map(stable)).size!==v.length)return path+': remove the repeated item.';
      for(var j=0;j<v.length;j++){var err=issue(p.item,v[j],path+' › Item '+(j+1),depth+1);if(err)return err;}
    } else if(p.type==='string') {
      var chars=Array.from(v); if(chars.some(function(c){var code=c.charCodeAt(0);return c.length===1&&code>=0xd800&&code<=0xdfff;}))return path+': replace the unreadable character.';
      if(depth===1&&/\{\{[\s\S]*\}\}/.test(v))return undefined;
      if(s.minLength!==undefined&&chars.length<s.minLength || s.maxLength!==undefined&&chars.length>s.maxLength)return path+': check the text length.';
      if(s.format==='date'&&!day(v) || s.format==='date-time'&&(!day(v.slice(0,10))||!/^\d{4}-\d\d-\d\d[Tt]\d\d:\d\d:\d\d(?:\.\d+)?(?:[Zz]|[+-]\d\d:\d\d)$/.test(v)||!Number.isFinite(Date.parse(v))))return path+': enter a valid date.';
      if(s.format==='email'&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v))return path+': enter an email address.';
      if((s.format==='uri'||s.format==='url')&&!/^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$/.test(v))return path+': enter a complete address.';
      if(s.format==='uuid'&&!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(v))return path+': choose a valid reference.';
      if(depth>1 && /\{\{[\s\S]*\}\}/.test(v))return path+': earlier-step values are not supported inside details or lists yet. Use a fixed value.';
    } else if(p.type==='integer'||p.type==='number') {
      if(!Number.isFinite(v)||Number.isInteger(v)&&!Number.isSafeInteger(v))return path+': enter a number this form can preserve exactly.';
      if(s.minimum!==undefined&&v<s.minimum || s.maximum!==undefined&&v>s.maximum || s.exclusiveMinimum!==undefined&&v<=s.exclusiveMinimum || s.exclusiveMaximum!==undefined&&v>=s.exclusiveMaximum)return path+': check the allowed number range.';
      if(s.multipleOf!==undefined && Math.abs(v/s.multipleOf-Math.round(v/s.multipleOf))>1e-9)return path+': use an allowed increment.';
    }
  }
  async function load(tool, refresh) {
    if(!refresh&&cache.has(tool))return cache.get(tool);
    if(pending.has(tool))return pending.get(tool);
    var task=(async function(){
      var controller=new AbortController(),deadline=setTimeout(function(){controller.abort();},20000);
      try {
        var response=await fetch('/api/v1/workflow-action-fields/'+encodeURIComponent(tool),{credentials:'same-origin',cache:'no-store',signal:controller.signal});
        var value;try{value=await response.json();}catch(_error){throw new Error('Action details could not be confirmed. Your values are kept; try again.');}
        if(response.status===401)throw new Error('Sign in again to load this action’s details. Your changes are kept.');
        if(response.status===403)throw new Error('You do not have permission to configure this action. Ask your workspace owner.');
        if(!response.ok)throw new Error(typeof value.detail==='string'?value.detail:'Action details could not be loaded. Your values are kept; try again.');
        if(value.tool!==tool||typeof value.revision!=='string')bad();
        var result={revision:value.revision,plan:compile(value.schema)};cache.set(tool,result);return result;
      } catch(error){throw new Error(error.name==='AbortError'?'Action details timed out. Your values are kept; try again.':error instanceof TypeError?'Action details could not be reached. Your values are kept; try again.':error.message);}
      finally{clearTimeout(deadline);pending.delete(tool);}
    })();pending.set(tool,task);return task;
  }
  function boundRecipeAction(flow,n) {
    // Recognize supplied arguments only for this enclosing recipe's generated
    // action. Native persistence still validates the complete exact graph,
    // evidence and current authority; a browser marker grants no permission.
    var recipe=flow.learned_recipe,index=n.recipe_step;
    if(!obj(recipe)||n.kind!=='action'||!Number.isSafeInteger(index)||index<0||
       n.params!==undefined&&(!obj(n.params)||Object.keys(n.params).length)||n._paramsRaw!==undefined||
       n.output!=='_recipe_step_'+index)return false;
    if(['lightwork.workflow-transducer.v1','lightwork.workflow-memory.v1'].includes(recipe.schema)) {
      var ordinal=Array.isArray(recipe.allowed_tools)?recipe.allowed_tools.indexOf(n.tool):-1;
      return Number.isSafeInteger(recipe.max_steps)&&index<recipe.max_steps&&ordinal>=0&&n.id==='action_'+index+'_'+ordinal;
    }
    if(!['lightwork.action-recipe.v1','lightwork.action-recipe.v2','lightwork.action-choice.v1'].includes(recipe.schema)||!Array.isArray(recipe.steps))return false;
    if(recipe.schema==='lightwork.action-choice.v1'&&index===1)return Array.isArray(recipe.branches)&&recipe.branches.some(function(branch){return obj(branch)&&branch.tool===n.tool&&n.id==='action_1_'+branch.route;});
    return obj(recipe.steps[index])&&recipe.steps[index].tool===n.tool&&n.id==='action_'+index;
  }
  function each(flow, fn) { (Array.isArray(flow.nodes)?flow.nodes:Object.values(flow.nodes||{})).forEach(function(n){if(n.kind==='action'&&n.tool&&!boundRecipeAction(flow,n))fn(n);if(n.body)each(n.body,fn);(n.branches||[]).forEach(function(b){each(b,fn);});}); }
  async function ready(flow,refresh) { var tools=new Set();each(flow,function(n){tools.add(n.tool);});await Promise.all(Array.from(tools,function(t){return load(t,refresh);})); }
  function valueCount(v){var stack=[v],count=0;while(stack.length){var item=stack.pop();if(++count>2048)return count;if(obj(item)||Array.isArray(item))Object.values(item).forEach(function(child){stack.push(child);});}return count;}
  function check(flow) { var errors=[];each(flow,function(n){var stored=cache.get(n.tool),size;try{size=JSON.stringify(n.params||{}).length;}catch(_error){size=Infinity;}var error=!stored?'Wait for this action’s details, then try again.':size>65536||valueCount(n.params||{})>2048?'These details are too large for this form. Remove unnecessary items before saving.':Object.values(n._actionErrors||{})[0]||issue(stored.plan,n.params||{},'Action details');if(error)errors.push((n.label||human(n.tool))+': '+error);});return errors; }
  function initial(p) { if(p.type==='fixed')return JSON.parse(JSON.stringify(p.value));if(p.spec&&p.spec.default!==undefined&&!issue(p,p.spec.default))return JSON.parse(JSON.stringify(p.spec.default));if(p.type==='object')return Object.create(null);if(p.type==='array')return [];if(p.type==='string'||p.type==='any')return '';if(p.type==='boolean')return false;if(p.type==='integer'||p.type==='number')return 0;return null; }
  function validDetails(n){var stored=cache.get(n.tool);return !!stored&&!issue(stored.plan,n.params||{},'Action details');}
  function mount(host, n, stored, changed, options) {
    var plan=stored.plan,renderBudget=2048;options=options||{}; n._actionRaw=n._actionRaw||Object.create(null);n._actionErrors=n._actionErrors||Object.create(null);n._actionKinds=n._actionKinds||Object.create(null);
    function node(tag,text,parent){var el=document.createElement(tag);if(text!==undefined)el.textContent=text;if(parent)parent.appendChild(el);return el;}
    function get(path){var v=n.params;for(var key of path){if(v==null||!Object.prototype.hasOwnProperty.call(v,key))return undefined;v=v[key];}return v;}
    function set(path,value,remove){if(!path.length){n.params=value;return;}var v=n.params;for(var i=0;i<path.length-1;i++){var k=path[i];if(!Object.prototype.hasOwnProperty.call(v,k)||!obj(v[k])&&!Array.isArray(v[k]))Object.defineProperty(v,k,{value:typeof path[i+1]==='number'?[]:Object.create(null),writable:true,enumerable:true,configurable:true});v=v[k];}if(remove)delete v[path[path.length-1]];else Object.defineProperty(v,path[path.length-1],{value:value,writable:true,enumerable:true,configurable:true});}
    function clear(path){function below(key){var candidate=JSON.parse(key);return candidate.length>=path.length&&path.every(function(part,i){return candidate[i]===part;});}[n._actionRaw,n._actionErrors,n._actionKinds].forEach(function(buffer){Object.keys(buffer).forEach(function(k){if(below(k))delete buffer[k];});});}
    function removeItemBuffers(path,index){['_actionRaw','_actionErrors','_actionKinds'].forEach(function(name){var next=Object.create(null);Object.keys(n[name]).forEach(function(key){var parts=JSON.parse(key),inside=parts.length>path.length&&path.every(function(part,i){return parts[i]===part;});if(inside&&typeof parts[path.length]==='number'){if(parts[path.length]===index)return;if(parts[path.length]>index)parts[path.length]--;}next[JSON.stringify(parts)]=n[name][key];});n[name]=next;});}
    function repaint(focus){host.replaceChildren();renderBudget=2048;render(plan,[],host,'Action details',0);if(focus){var target=Array.from(host.querySelectorAll('[data-action-path]')).find(function(el){return el.dataset.actionPath===JSON.stringify(focus);});if(target)target.focus();}changed();}
    function write(path,p,raw,control,error){var key=JSON.stringify(path), value=raw, problem;
      if((p.type==='integer'||p.type==='number')&&typeof raw==='string'){value=Number(raw);if(!raw.trim()||!/^[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[-+]?\d+)?$/i.test(raw))problem='Enter '+names[p.type].toLowerCase()+'.';}
      if(!problem)problem=issue(p,value,control.getAttribute('aria-label'),path.length);
      if(problem){n._actionRaw[key]=raw;n._actionErrors[key]=problem;control.setAttribute('aria-invalid','true');error.textContent=problem;error.hidden=false;}
      else{set(path,value);delete n._actionRaw[key];delete n._actionErrors[key];control.removeAttribute('aria-invalid');error.hidden=true;}changed();}
    function button(text,parent,fn){var b=node('button',text,parent);b.type='button';b.className='btn btn--ghost';b.addEventListener('click',fn);return b;}
    function render(p,path,parent,label,depth){
      if(depth>10||--renderBudget<0){if(renderBudget>=-1)node('p','These details are too complex for this form. Your values are kept; remove unnecessary details or choose a simpler action.',parent);return;}
      var value=get(path);
      if(p.type==='fixed'){node('p',p.title,parent);if(issue(p,value,label))button('Use '+p.title,parent,function(){clear(path);set(path,initial(p));repaint(path);});return;}
      if(p.type==='any'||p.type==='union'){
        var variants=p.type==='any'?kinds.map(function(t){return compile({type:'object',properties:{value:{type:t}},additionalProperties:false}).props[0].node;}):p.variants;
        var retainedKind=n._actionKinds[JSON.stringify(path)],chosen=Number.isInteger(retainedKind)&&variants[retainedKind]?retainedKind:variants.findIndex(function(a){return !issue(a,value,label,path.length);});if(chosen<0)chosen=0;
        var choose=node('select',undefined,parent);choose.className='input';choose.dataset.actionPath=JSON.stringify(path);choose.setAttribute('aria-label',label+' kind');
        variants.forEach(function(a,i){var o=node('option',a.title||names[a.type]||'Choice '+(i+1),choose);o.value=String(i);o.selected=i===chosen;});
        choose.addEventListener('change',function(){var selectedKind=Number(choose.value);clear(path);n._actionKinds[JSON.stringify(path)]=selectedKind;set(path,initial(variants[selectedKind]));repaint(path);});render(variants[chosen],path,parent,label,depth+1);return;
      }
      if(p.type==='object'||p.type==='array'){
        var group=node('fieldset',undefined,parent);group.className='fd-action-group';group.dataset.actionPath=JSON.stringify(path);group.tabIndex=-1;node('legend',label,group);
        if(value!==undefined&&typeOf(value)!==p.type){node('p','This saved value uses a different kind of detail. It is kept until you choose to replace it.',group);button('Use '+names[p.type].toLowerCase()+' fields',group,function(){clear(path);set(path,initial(p));repaint(path);});return;}
        if(value===undefined){set(path,initial(p));value=get(path);}
        if(p.type==='object'){
          p.props.forEach(function(f){var row=node('div',undefined,group), child=path.concat(f.key), included=Object.prototype.hasOwnProperty.call(value,f.key);
            if(!f.required){var lab=node('label',undefined,row),include=node('input',undefined,lab);include.type='checkbox';include.checked=included;lab.appendChild(document.createTextNode('Include '+(f.node.title||human(f.key))));include.addEventListener('change',function(){clear(child);set(child,initial(f.node),!include.checked);repaint(child);});}
            if(f.required||included)render(f.node,child,row,f.node.title||human(f.key),depth+1);
          });
          Object.keys(value).filter(function(k){return !p.props.some(function(f){return f.key===k;});}).slice(0,MAX_ITEMS).forEach(function(k){var row=node('div',undefined,group);if(p.extra)render(p.extra,path.concat(k),row,human(k),depth+1);else node('p',human(k)+' is no longer an allowed detail. Remove it before saving.',row);button('Remove '+human(k),row,function(){clear(path.concat(k));set(path.concat(k),undefined,true);repaint(path);});});
          if(Object.keys(value).length>MAX_ITEMS)node('p','This saved group has too many details. Remove details above to reveal the remaining ones; every saved value is kept.',group);
          if(p.extra&&Object.keys(value).length<Math.min(MAX_ITEMS,p.spec.maxProperties===undefined?MAX_ITEMS:p.spec.maxProperties)){var add=node('div',undefined,group),name=node('input',undefined,add),nameError=node('p',undefined,add);nameError.id='fd-action-name-error-'+(++counter);nameError.className='mv-form__err';nameError.hidden=true;name.className='input';name.maxLength=100;name.setAttribute('aria-label',label+' new detail name');name.setAttribute('aria-describedby',nameError.id);name.placeholder='Name this detail';button('Add detail',add,function(){var k=name.value.trim();if(!k||Object.prototype.hasOwnProperty.call(value,k)){nameError.textContent=k?'That detail is already included. Choose a different name.':'Give this detail a name.';nameError.hidden=false;name.setAttribute('aria-invalid','true');name.focus();return;}set(path.concat(k),initial(p.extra));repaint(path.concat(k));});}
        }else{
          value.slice(0,MAX_ITEMS).forEach(function(_item,i){var row=node('div',undefined,group);render(p.item,path.concat(i),row,'Item '+(i+1),depth+1);var remove=button('Remove item '+(i+1),row,function(){removeItemBuffers(path,i);value.splice(i,1);repaint(path);});remove.disabled=value.length<=(p.spec.minItems||0);});
          if(value.length>MAX_ITEMS)node('p','This saved list has '+value.length+' items. Remove items above to reveal the remaining ones; every saved value is kept.',group);
          var addItem=button('Add item',group,function(){value.push(initial(p.item));repaint(path.concat(value.length-1));});addItem.disabled=value.length>=Math.min(MAX_ITEMS,p.spec.maxItems===undefined?MAX_ITEMS:p.spec.maxItems);
          node('p','Up to '+Math.min(MAX_ITEMS,p.spec.maxItems===undefined?MAX_ITEMS:p.spec.maxItems)+' items in this form.'+(p.spec.minItems?' At least '+p.spec.minItems+' required.':''),group).className='muted';
        }return;
      }
      var wrap=node('div',undefined,parent);wrap.className='field';var id='fd-action-value-'+(++counter),lab=node('label',p.title||label,wrap);lab.htmlFor=id;
      if(p.type==='null'){
        if(value!==undefined&&value!==null){node('p','This saved detail uses a different kind of value. It is kept until you choose to replace it.',wrap);button('Use no value',wrap,function(){clear(path);set(path,null);repaint(path);});return;}
        node('p','No value.',wrap);if(value===undefined)set(path,null);return;
      }
      if(p.type==='string'&&!p.choices&&path.length===1&&(options.sources||[]).length){
        var source=node('select',undefined,wrap);source.className='input';source.setAttribute('aria-label',label+' source');
        node('option','Enter text',source).value='';var match=typeof value==='string'&&value.match(/^\{\{\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\}\}$/);
        (options.sources||[]).slice(0,128).forEach(function(s){var opt=node('option','Use '+s.label,source);opt.value=s.key;if(match&&match[1]===s.key)opt.selected=true;});
        var hasExpression=typeof value==='string'&&/\{\{[\s\S]*\}\}/.test(value);
        if(hasExpression&&!source.value){var retained=node('option','Keep saved earlier information',source);retained.value='__saved';retained.selected=true;}
        source.addEventListener('change',function(){if(source.value==='__saved')return;clear(path);set(path,source.value?'{'+ '{'+source.value+'}'+ '}':'');repaint(path);});
        if(hasExpression){node('p','This field uses earlier information when the workflow runs. Choose Enter text to replace it with a fixed value.',wrap).className='muted';return;}
      }
      var control=node(p.choices||p.type==='boolean'?'select':'input',undefined,wrap);control.id=id;control.className='input';control.dataset.actionPath=JSON.stringify(path);control.setAttribute('aria-label',label);
      var error=node('p',undefined,wrap);error.id=id+'-error';error.className='mv-form__err';error.hidden=true;control.setAttribute('aria-describedby',error.id);
      if(p.choices||p.type==='boolean'){
        var choices=p.choices||[{value:true,label:'Yes'},{value:false,label:'No'}],empty=node('option','Choose…',control);empty.value='';
        choices.forEach(function(c,i){var o=node('option',c.label,control);o.value=String(i);o.selected=Object.is(c.value,value);});
        control.addEventListener('change',function(){if(control.value===''){n._actionErrors[JSON.stringify(path)]=label+': choose a value.';changed();}else write(path,p,choices[Number(control.value)].value,control,error);});
      }else{
        control.type=p.spec.format==='date'?'date':p.spec.format==='date-time'?'datetime-local':p.spec.format==='email'?'email':'text';control.autocomplete='off';if(p.type==='number'||p.type==='integer')control.inputMode=p.type==='integer'?'numeric':'decimal';
        control.value=Object.prototype.hasOwnProperty.call(n._actionRaw,JSON.stringify(path))?n._actionRaw[JSON.stringify(path)]:value==null?'':String(value);
        if(p.spec.format==='date-time'){control.step='0.001';if(value&&Number.isFinite(Date.parse(value))&&!Object.prototype.hasOwnProperty.call(n._actionRaw,JSON.stringify(path))){var d=new Date(value);d.setMinutes(d.getMinutes()-d.getTimezoneOffset());control.value=d.toISOString().slice(0,23);}}
        control.addEventListener('input',function(){var raw=control.value;if(p.spec.format==='date-time'&&raw&&Number.isFinite(new Date(raw).getTime()))raw=new Date(raw).toISOString();write(path,p,raw,control,error);});
      }
      var problem=n._actionErrors[JSON.stringify(path)]||issue(p,value,label,path.length);if(problem){error.textContent=problem;error.hidden=false;control.setAttribute('aria-invalid','true');}
      var limits=[];if(p.spec.minimum!==undefined)limits.push('At least '+p.spec.minimum);if(p.spec.maximum!==undefined)limits.push('At most '+p.spec.maximum);if(p.spec.minLength)limits.push('At least '+p.spec.minLength+' characters');if(p.spec.maxLength!==undefined)limits.push('Up to '+p.spec.maxLength+' characters');if(limits.length)node('p',limits.join('. ')+'.',wrap).className='muted';
    }
    if(n._actionTool!==n.tool){n._actionRaw=Object.create(null);n._actionErrors=Object.create(null);n._actionKinds=Object.create(null);n._actionTool=n.tool;}
    repaint();
  }
  return {load:load,ready:ready,check:check,mount:mount,compile:compile,issue:issue,validDetails:validDetails,boundRecipeAction:boundRecipeAction};
}());
