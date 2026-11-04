/* Chromium rendering of native shell assets with fixed synthetic IPC only.
   These tests never invoke Tauri, Windows Installer, or installation recovery. */
const {test,expect}=require('@playwright/test');
const fs=require('node:fs');
const path=require('node:path');
const assets=path.resolve(__dirname,'../../../..','apps/desktop/ui');

async function openMaintenance(page,scenario){
  page.__errors=[];page.on('pageerror',error=>page.__errors.push(error.message));
  await page.context().route('**/*',route=>route.abort('blockedbyclient'));
  await page.route('**/__desktop_maintenance/*',route=>{
    const file=new URL(route.request().url()).pathname.split('/').pop();
    if(!['maintenance.html','maintenance.js'].includes(file))return route.abort('blockedbyclient');
    return route.fulfill({contentType:file.endsWith('.html')?'text/html':'application/javascript',body:fs.readFileSync(path.join(assets,file),'utf8')});
  });
  await page.addInitScript(config=>{
    window.__maintenanceCalls=[];
    window.__TAURI__={core:{invoke:async(command,args)=>{
      window.__maintenanceCalls.push({command,args});
      if(command==='maintenance_status')return config.status;
      if(command==='check_desktop_update')return {...config.review,repair:args.repair};
      if(command==='desktop_maintenance_logs')return {details:'Synthetic local installation log. <script>Never execute this text.</script>'};
      if(['install_desktop_update','resume_desktop_maintenance'].includes(command))return new Promise((resolve,reject)=>{
        window.__finishMaintenance=()=>reject(new Error('Synthetic verification failure; no installer was invoked.'));
      });
      throw new Error('Unexpected synthetic IPC command: '+command);
    }}};
  },scenario);
  await page.goto('/__desktop_maintenance/maintenance.html');
  await expect(page.locator('#installed-version')).toHaveText('1.0.0');
}
async function fits(page){
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth+1)).toBeTruthy();
}
test.afterEach(async({page},info)=>{
  await info.attach('desktop-maintenance-ui-only',{body:await page.screenshot({fullPage:true}),contentType:'image/png'});
  expect(page.__errors).toEqual([]);
});

test('desktop update review is keyboard reachable, authorization-bound and single-flight at phone width',async({page})=>{
  await page.setViewportSize({width:320,height:740});
  await openMaintenance(page,{status:{version:'1.0.0',updates_configured:true},review:{review:'synthetic-review',version:'1.0.1',notes:'<img src=x onerror=bad()> '+ 'long-release-note-'.repeat(15)}});
  await page.keyboard.press('Tab');await expect(page.locator('#back')).toBeFocused();
  await page.keyboard.press('Tab');await expect(page.locator('#check-update')).toBeFocused();await page.keyboard.press('Enter');
  await expect(page.locator('#update-review')).toBeVisible();await expect(page.locator('#update-notes img')).toHaveCount(0);
  await expect(page.locator('#install-update')).toBeDisabled();await fits(page);
  expect(await page.evaluate(()=>window.__maintenanceCalls.map(call=>call.command))).toEqual(['maintenance_status','check_desktop_update']);
  await page.locator('#maintenance-authorization').fill('not-an-authorization');await expect(page.locator('#install-update')).toBeDisabled();
  await page.locator('#maintenance-authorization').fill('a'.repeat(32)+':'+ 'b'.repeat(64));
  await page.locator('#install-update').focus();await page.keyboard.press('Enter');
  await expect(page.locator('#maintenance-authorization')).toHaveValue('');
  for(const id of ['install-update','repair-install','check-update','back','rollback-install'])await expect(page.locator('#'+id)).toBeDisabled();
  await page.locator('#install-update').dispatchEvent('click');
  expect(await page.evaluate(()=>window.__maintenanceCalls.filter(call=>call.command==='install_desktop_update').length)).toBe(1);
  await page.evaluate(()=>window.__finishMaintenance());
  await expect(page.locator('#update-review')).toBeHidden();await expect(page.locator('#check-update')).toBeEnabled();
  await page.getByText('Details for support',{exact:true}).click();await expect(page.locator('#maintenance-details')).toContainText('no installer was invoked');
  await fits(page);
});

test('desktop repair remains guided when recovery state is unavailable and needs no update authorization',async({page})=>{
  await page.setViewportSize({width:1280,height:800});
  await openMaintenance(page,{status:{version:'1.0.0',updates_configured:true,recovery:{unavailable:true,detail:'Synthetic unreadable recovery state'}},review:{review:'synthetic-repair',version:'1.0.0',notes:'Verified-copy fixture only'}});
  await expect(page.locator('#check-update')).toBeDisabled();await expect(page.locator('#repair-install')).toBeEnabled();
  await page.locator('#repair-install').focus();await page.keyboard.press('Enter');await expect(page.locator('#install-update')).toBeEnabled();
  await page.locator('#install-update').click();
  const call=await page.evaluate(()=>window.__maintenanceCalls.find(item=>item.command==='install_desktop_update'));
  expect(call.args).toEqual({review:'synthetic-repair',confirm:true});
  await page.evaluate(()=>window.__finishMaintenance());await expect(page.locator('#maintenance-status')).toContainText('could not complete');await fits(page);
});

test('desktop unfinished finalization keeps the exact reviewed operation selectable without starting it',async({page})=>{
  await page.setViewportSize({width:320,height:740});
  await openMaintenance(page,{status:{version:'1.0.0',updates_configured:true,recovery:{incomplete:true,recovery_points:[{id:'synthetic-point',old_version:'1.0.0',new_version:'1.0.1',status:'upgraded',pending_finalization:true}]}},review:null});
  await expect(page.locator('#maintenance-status')).toContainText('unfinished update is stopping your workspace');
  await expect(page.locator('#check-update')).toBeDisabled();await expect(page.locator('#repair-install')).toBeDisabled();
  await expect(page.locator('#resume-maintenance')).toBeDisabled();
  await page.locator('#maintenance-incomplete').selectOption('synthetic-point');await expect(page.locator('#resume-maintenance')).toBeEnabled();
  expect(await page.evaluate(()=>window.__maintenanceCalls.length)).toBe(1);
  await page.locator('#resume-maintenance').focus();await page.keyboard.press('Enter');
  expect(await page.evaluate(()=>window.__maintenanceCalls.at(-1))).toEqual({command:'resume_desktop_maintenance',args:{id:'synthetic-point',confirm:true}});
  await page.evaluate(()=>window.__finishMaintenance());await expect(page.locator('#maintenance-status')).toContainText('could not complete');await fits(page);
  await page.getByText('Details for support',{exact:true}).click();await expect(page.locator('#maintenance-logs')).toBeDisabled();
  await page.locator('#maintenance-log-point').selectOption('synthetic-point');await page.locator('#maintenance-logs').focus();await page.keyboard.press('Enter');
  await expect(page.locator('#maintenance-details')).toContainText('Synthetic local installation log');await expect(page.locator('#maintenance-details script')).toHaveCount(0);
  expect(await page.evaluate(()=>window.__maintenanceCalls.at(-1))).toEqual({command:'desktop_maintenance_logs',args:{id:'synthetic-point'}});
  await fits(page);
});

test('desktop proposed signing transition downloads exact review material without granting installation',async({page})=>{
  await page.setViewportSize({width:320,height:740});
  const envelope=JSON.parse(fs.readFileSync(path.resolve(__dirname,'../../../maverick-core/tests/fixtures/tauri_identity_bridge.json'),'utf8')).envelope;
  await openMaintenance(page,{status:{version:'1.0.0',updates_configured:true},review:{review:'synthetic-bridge-review',version:'1.0.1',identity_transition:envelope,notes:'Signing transition fixture only; no installer execution.'}});
  await page.locator('#check-update').click();
  await expect(page.locator('#identity-transition-notice')).toBeVisible();
  await expect(page.locator('#install-update')).toBeDisabled();
  const pending=page.waitForEvent('download');await page.locator('#save-identity-transition').focus();await page.keyboard.press('Enter');
  const download=await pending;
  expect(download.suggestedFilename()).toBe('lightwork-signing-transition.json');
  expect(JSON.parse(fs.readFileSync(await download.path(),'utf8'))).toEqual(envelope);
  expect(await page.evaluate(()=>window.__maintenanceCalls.map(call=>call.command))).toEqual(['maintenance_status','check_desktop_update']);
  await expect(page.locator('#install-update')).toBeDisabled();await fits(page);
});
