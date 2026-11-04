const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {lua,lauxlib,lualib,to_luastring,to_jsstring} = require('fengari');

test('asynchronous Neovim controls require checked state and suppress cancelled or late results',()=>{
  const L=lauxlib.luaL_newstate();lualib.luaL_openlibs(L);
  const execute=text=>{
    const status=lauxlib.luaL_dostring(L,to_luastring(text));
    assert.equal(status,lua.LUA_OK,status===lua.LUA_OK?'':to_jsstring(lua.lua_tostring(L,-1)));
  };
  execute(`
    mode='halt'; notices={}; jobs={}; timers={}; stopped={}; sequence=0
    vim={log={levels={ERROR='error',INFO='info'}},
      ui={select=function(options,prompt,fn) fn('Yes') end},
      notify=function(message,level) notices[#notices+1]={message,level} end,
      fn={jobstart=function(args,callbacks)
        assert(args[3]=='--json')
        if mode=='missing' then return -1 end
        sequence=sequence+1; jobs[sequence]={args=args,callbacks=callbacks}; return sequence
      end,jobstop=function(id) stopped[id]=true end,
      timer_start=function(ms,callback) assert(ms==30000); timers[sequence]=callback; return sequence end,
      timer_stop=function(id) timers[id]=nil end,
      json_decode=function(command)
        if mode=='malformed' then error('malformed') end
        local present=command=='halt'
        if mode=='wrong-state' then present=false end
        return {command=command,acknowledged=true,scope='local',work_stopped=false,halt_file_present=present}
      end}}
  `);
  const source=fs.readFileSync(path.join(__dirname,'../nvim/lua/maverick/init.lua'),'utf8');
  execute(`maverick=(function()\n${source}\nend)()`);
  execute(`
    for _,value in ipairs({'missing','nonzero','signal','malformed','wrong-state','halt','unhalt','timeout','cancel'}) do
      mode=value
      if mode=='unhalt' then maverick.unhalt() else maverick.halt() end
      if mode~='missing' then
        local current=jobs[sequence]; local callbacks=current.callbacks
        assert(notices[#notices][2]=='info') -- Returned without waiting for process output.
        if mode=='timeout' then timers[sequence]()
        elseif mode=='cancel' then maverick.cancel_control()
        else callbacks.on_stdout(sequence,{current.args[2]}); callbacks.on_exit(sequence,mode=='nonzero' and 1 or mode=='signal' and 143 or 0) end
        local after=#notices
        callbacks.on_stdout(sequence,{'late'}); callbacks.on_exit(sequence,0)
        assert(#notices==after); assert(timers[sequence]==nil)
      end
      local notice=notices[#notices]
      if mode=='halt' or mode=='unhalt' then
        assert(notice[2]=='info')
        assert(string.find(notice[1],mode=='halt' and 'checkpoint' or 'not restarted'))
      else assert(notice[2]=='error') end
    end
    mode='halt'; maverick.halt(); local old=jobs[sequence].callbacks
    maverick.cancel_control(); mode='unhalt'; maverick.unhalt(); local before=#notices
    old.on_stdout(1,{'halt'}); old.on_exit(1,0); assert(#notices==before)
    maverick.cancel_control()
  `);
  lua.lua_close(L);
});
