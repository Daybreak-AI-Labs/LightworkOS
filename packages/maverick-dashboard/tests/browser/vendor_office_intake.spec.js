const {test,expect}=require('@playwright/test');
const path=require('node:path'),fs=require('node:fs'),crypto=require('node:crypto');
const fixtures=path.resolve(__dirname,'../../../..','scripts/acceptance/fixtures/vendor-documents');
test.beforeEach(async({context,page,baseURL})=>{
  const origin=new URL(baseURL).origin;
  await context.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort('blockedbyclient'));
  page.__errors=[];page.on('pageerror',error=>page.__errors.push(error.message));
});
test.afterEach(async({page,context})=>{await context.unrouteAll({behavior:'ignoreErrors'});expect(page.__errors).toEqual([]);});
async function fits(page){
  const widths=await page.evaluate(()=>({client:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,
    preview:[...document.querySelectorAll('#vo-upload-review pre')].filter(el=>el.clientWidth).map(el=>({client:el.clientWidth,scroll:el.scrollWidth}))}));
  expect(widths.scroll).toBeLessThanOrEqual(widths.client+1);
  for(const value of widths.preview)expect(value.scroll).toBeLessThanOrEqual(value.client+1);
}
async function screenshot(page,info,name){const target=info.outputPath(name);await page.screenshot({path:target});await info.attach(name,{path:target,contentType:'image/png'});}
async function freshCase(request,page){
  const response=await request.post('/api/v1/vendor-onboarding/cases',{data:{vendor_name:'Synthetic Office browser review',document_ids:[],project:'VEND',purpose:'Synthetic local document compatibility; no provider execution'}});
  expect(response.status()).toBe(201);const row=await response.json();
  await page.goto('/third-party/vendor-onboarding?case='+row.id);await expect(page.locator('#vo-message')).toContainText('Linked request loaded');
  await page.locator('#vo-document-date').fill(new Date(Date.now()-86400000).toISOString().slice(0,10));return row;
}
async function selectPreview(page,name){await page.locator('#vo-upload').setInputFiles(path.join(fixtures,name));await page.locator('#vo-upload-submit').click();await expect(page.locator('#vo-message')).toContainText('Preview ready');}
async function accept(page){await page.locator('#vo-upload-confirm').check();await page.locator('#vo-upload-accept').press('Enter');await expect(page.locator('#vo-message')).toContainText('Reviewed evidence added');}
async function step(request,row,name,extra={}){const response=await request.post(`/api/v1/vendor-onboarding/cases/${row.id}/${name}`,{data:{expected_revision:row.revision,...extra}});expect(response.status()).toBe(200);return response.json();}

test('authored Word and Excel evidence requires review, preserves failed work and cites original paragraphs and cells',async({page,request},info)=>{
  await page.setViewportSize({width:320,height:900});const row=await freshCase(request,page);
  await selectPreview(page,'northstar-policy.docx');
  await expect(page.locator('#vo-upload-text')).toContainText('Model provenance is documented');
  await expect(page.locator('#vo-upload-text')).not.toContainText('Header outside');
  await expect(page.locator('#vo-upload-accept')).toBeDisabled();
  expect(await page.locator('label:has(#vo-upload-confirm)').evaluate(el=>getComputedStyle(el).display)).toBe('flex');
  const unchanged=await(await request.get('/api/v1/vendor-onboarding/cases/'+row.id)).json();
  expect(unchanged.revision).toBe(row.revision);expect(unchanged.uploads).toEqual([]);
  const hash=crypto.createHash('sha256').update(fs.readFileSync(path.join(fixtures,'northstar-policy.docx'))).digest('hex');
  await page.locator('#vo-upload-review details summary').click();await expect(page.locator('#vo-upload-fingerprints')).toContainText(hash);
  await page.locator('#vo-upload-text').scrollIntoViewIfNeeded();await fits(page);await screenshot(page,info,'word-review-320.png');await accept(page);
  await page.locator('#vo-purpose').fill('Other unsaved form work');
  await page.route('**/upload-preview',route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({detail:'Synthetic interrupted preview'})}));
  await page.locator('#vo-upload').setInputFiles(path.join(fixtures,'northstar-policy.xlsx'));await page.locator('#vo-upload-submit').click();
  await expect(page.locator('#vo-message')).toContainText('Synthetic interrupted preview');await expect(page.locator('#vo-purpose')).toHaveValue('Other unsaved form work');
  await expect(page.locator('#vo-uploaded-documents')).toContainText('northstar-policy.docx');await expect(page.locator('#vo-upload-accept')).toBeDisabled();
  await page.unroute('**/upload-preview');await page.locator('#vo-upload-submit').click();await expect(page.locator('#vo-message')).toContainText('Preview ready');
  await expect(page.locator('#vo-upload-text')).not.toContainText('undisclosed');await accept(page);
  await page.locator('#vo-collect').click();await expect(page.locator('#vo-assess')).toBeEnabled();await page.locator('#vo-assess').click();
  await expect(page.locator('#vo-assessment')).toContainText('paragraph 2');await expect(page.locator('#vo-assessment')).toContainText('Evidence & controls, cell B2');
  const saved=await(await request.get('/api/v1/vendor-onboarding/cases/'+row.id)).json();expect(saved.uploads).toHaveLength(2);expect(saved.operation).toBeNull();
  await page.setViewportSize({width:1280,height:900});await page.locator('#vo-assessment').scrollIntoViewIfNeeded();await fits(page);await screenshot(page,info,'office-citations-1280.png');
});

test('image-only PDF offers explicit transcription, retains original hash and refuses changed review context',async({page,request},info)=>{
  await page.setViewportSize({width:320,height:900});const row=await freshCase(request,page);
  await page.locator('#vo-upload').setInputFiles(path.join(fixtures,'northstar-scan.pdf'));await page.locator('#vo-upload-submit').click();
  await expect(page.locator('#vo-upload-fallback')).toBeVisible();await expect(page.locator('#vo-upload-accept')).toBeDisabled();
  await page.locator('#vo-upload-transcription').fill('Model provenance is documented with provider and version. Transcribed from the image; no other policy statements appear on this page.');
  await page.locator('#vo-upload-transcribe').click();await expect(page.locator('#vo-upload-summary')).toContainText('text you typed in');
  await page.locator('#vo-upload-text').scrollIntoViewIfNeeded();await fits(page);await screenshot(page,info,'manual-transcription-320.png');
  // A separate legitimate editor changes the request after this preview.
  expect((await request.post(`/api/v1/vendor-onboarding/cases/${row.id}/documents`,{data:{expected_revision:row.revision,document_ids:[],upload_ids:[]}})).status()).toBe(200);
  await page.locator('#vo-upload-confirm').check();await page.locator('#vo-upload-accept').click();await expect(page.locator('#vo-message')).toContainText('revision changed');
  await expect(page.locator('#vo-upload-review')).toBeHidden();await expect(page.locator('#vo-upload-accept')).toBeDisabled();
  expect((await(await request.get('/api/v1/vendor-onboarding/cases/'+row.id)).json()).uploads).toEqual([]);
  await page.reload();await expect(page.locator('#vo-message')).toContainText('Linked request loaded');
  await page.locator('#vo-document-date').fill(new Date(Date.now()-86400000).toISOString().slice(0,10));
  await page.locator('#vo-upload').setInputFiles(path.join(fixtures,'northstar-scan.pdf'));await page.locator('#vo-upload-submit').click();await expect(page.locator('#vo-upload-fallback')).toBeVisible();
  await page.locator('#vo-upload-transcription').fill('Model provenance is documented with provider and version.');await page.locator('#vo-upload-transcribe').click();
  await expect(page.locator('#vo-message')).toContainText('Preview ready');await accept(page);
  await page.locator('#vo-collect').click();await expect(page.locator('#vo-assess')).toBeEnabled();await page.locator('#vo-assess').click();
  await expect(page.locator('#vo-assessment')).toContainText('user-supplied transcription paragraph 1; not verified PDF text');
  const saved=await(await request.get('/api/v1/vendor-onboarding/cases/'+row.id)).json();
  expect(saved.uploads[0].content_sha256).toBe(crypto.createHash('sha256').update(fs.readFileSync(path.join(fixtures,'northstar-scan.pdf'))).digest('hex'));
  expect(saved.uploads[0].extraction.method).toBe('human_transcription');expect(saved.operation).toBeNull();
});

test('malformed Office rejection preserves other work and HTML access denial clears a pending private preview',async({page,request})=>{
  await freshCase(request,page);await page.locator('#vo-purpose').fill('Keep my unrelated unsaved request');
  await page.locator('#vo-upload').setInputFiles({name:'Broken.docx',mimeType:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',buffer:Buffer.from('not a ZIP document')});
  await page.locator('#vo-upload-submit').click();await expect(page.locator('#vo-message')).toContainText('damaged or uses unsupported compression');
  await expect(page.locator('#vo-purpose')).toHaveValue('Keep my unrelated unsaved request');await expect(page.locator('#vo-upload-review')).toBeHidden();
  await selectPreview(page,'northstar-policy.docx');
  await page.route('**/upload-reviewed',route=>route.fulfill({status:401,contentType:'text/html',body:'<html>Sign in</html>'}));
  await page.locator('#vo-upload-confirm').check();await page.locator('#vo-upload-accept').click();
  await expect(page.locator('#vo-message')).toContainText('Access to evidence upload is unavailable');
  await expect(page.locator('#vo-upload-text')).toHaveText('');await expect(page.locator('#vo-upload')).toHaveValue('');
  await expect(page.locator('#vo-upload-submit')).toBeDisabled();await expect(page.locator('#vo-upload-confirm')).not.toBeChecked();
});

test('active markup stays inert text and unsupported media never reaches an assessment',async({page,request},info)=>{
  await page.setViewportSize({width:320,height:900});const row=await freshCase(request,page);
  const active='<script>window.lightworkActiveMarkupExecuted=true</script><img src=x onerror="window.lightworkActiveMarkupExecuted=true">';
  await page.locator('#vo-upload').setInputFiles({name:'active-markup.txt',mimeType:'text/plain',buffer:Buffer.from(active)});
  await page.locator('#vo-upload-submit').click();await expect(page.locator('#vo-message')).toContainText('Preview ready');
  await expect(page.locator('#vo-upload-text')).toContainText('<script>window.lightworkActiveMarkupExecuted=true</script>');
  expect(await page.locator('#vo-upload-text script').count()).toBe(0);
  expect(await page.evaluate(()=>window.lightworkActiveMarkupExecuted)).toBeUndefined();
  await page.locator('#vo-upload-text').scrollIntoViewIfNeeded();await fits(page);await screenshot(page,info,'active-markup-inert-320.png');
  await accept(page);await page.locator('#vo-collect').click();await page.locator('#vo-assess').click();
  await expect(page.locator('#vo-assessment')).toContainText('Gap: no matching source passage');
  expect(await page.evaluate(()=>window.lightworkActiveMarkupExecuted)).toBeUndefined();
  const before=(await(await request.get('/api/v1/vendor-onboarding/cases/'+row.id)).json()).revision;
  await page.locator('#vo-upload').setInputFiles({name:'unsupported.html',mimeType:'text/html',buffer:Buffer.from('<script>alert(1)</script>')});
  await page.locator('#vo-upload-submit').click();await expect(page.locator('#vo-message')).toContainText('Choose a .txt, .pdf, .docx or .xlsx file');
  expect((await(await request.get('/api/v1/vendor-onboarding/cases/'+row.id)).json()).revision).toBe(before);
  expect(await page.evaluate(()=>window.lightworkActiveMarkupExecuted)).toBeUndefined();
});

test('reviewed evidence export shows bounded manifest at desktop and mobile before download',async({page,request},info)=>{
  let response=await request.post('/api/v1/vendor-onboarding/cases',{data:{vendor_name:'Synthetic export browser review',document_id:'browser-policy',project:'VEND',purpose:'Synthetic local export review'}});
  expect(response.status()).toBe(201);let row=await response.json();
  row=await step(request,row,'collect-evidence');row=await step(request,row,'assess');
  row=await step(request,row,'review',{decision:'approved',rationale:'Reviewed every available claim and retained gaps as unknown'});
  row=await step(request,row,'prepare-action');row=await step(request,row,'approve-action',{
    confirm:true,approval_binding_sha256:row.operation.approval_card.binding_sha256});
  row=await step(request,row,'execute',{confirm:true});row=await step(request,row,'accept',{accepted:true,rationale:'Accepted bounded synthetic result'});
  await page.setViewportSize({width:1280,height:900});await page.goto('/third-party/vendor-onboarding?case='+row.id);
  await expect(page.locator('#vo-message')).toContainText('Linked request loaded');await expect(page.locator('#vo-export-preview')).toBeEnabled();
  await page.locator('#vo-export-preview').click();await expect(page.locator('#vo-message')).toContainText('export preview ready');
  await expect(page.locator('#vo-export-status')).toContainText('8 reviewed claims');await expect(page.locator('#vo-export-manifest')).toContainText('Document 1: included (Google Drive document, still valid).');
  await expect(page.locator('#vo-export-download')).toBeDisabled();await page.locator('#vo-export-status').scrollIntoViewIfNeeded();await fits(page);await screenshot(page,info,'evidence-export-1280.png');
  await page.setViewportSize({width:320,height:900});await page.locator('#vo-export-status').scrollIntoViewIfNeeded();await fits(page);await screenshot(page,info,'evidence-export-320.png');
  await page.locator('#vo-export-confirm').check();
  const [download]=await Promise.all([page.waitForEvent('download'),page.locator('#vo-export-download').click()]);
  expect(download.suggestedFilename()).toBe(`lightwork-evidence-${row.id}.json`);
  const target=info.outputPath('reviewed-evidence-export.json');await download.saveAs(target);await info.attach('reviewed-evidence-export.json',{path:target,contentType:'application/json'});
  const exported=JSON.parse(fs.readFileSync(target,'utf8'));
  expect(exported.schema).toBe('lightwork.vendor-onboarding.evidence-export.v1');expect(exported.case.id).toBe(row.id);
  expect(exported.claims).toHaveLength(8);expect(exported.manifest.included_count).toBe(1);expect(exported.manifest.withheld_count).toBe(0);
  expect(JSON.stringify(exported)).not.toContain('browser-policy');
  const reference=exported.manifest.included[0].reference;
  const withheld={...exported,binding_sha256:'f'.repeat(64),
    claims:exported.claims.map(claim=>({...claim,evidence_refs:[],citations:[],
      withheld_evidence_refs:[...new Set([...(claim.withheld_evidence_refs||[]),...claim.evidence_refs])],
      review_justification:claim.review_justification||'Human review retained the source-access limitation'})),
    manifest:{schema:'lightwork.vendor-onboarding.evidence-export-manifest.v1',included:[],
      withheld:[{reference,dependency_type:'external_evidence',disposition:'withheld',reason:'current_source_access_unavailable'}],
      included_count:0,withheld_count:1,complete:false}};
  await page.route('**/evidence-export-preview',route=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(withheld)}));
  await page.locator('#vo-export-preview').click();await expect(page.locator('#vo-export-status')).toContainText('0 evidence sources included; 1 left out.');
  await expect(page.locator('#vo-export-manifest')).toContainText('Document 1: left out because');
  await expect(page.locator('#vo-export-manifest')).not.toContainText('browser-policy');
  await fits(page);await screenshot(page,info,'evidence-export-withheld-320.png');
});
