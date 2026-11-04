// Actual exported HTML and WebCrypto, with installation A removed and B offline.
const {test,expect}=require('@playwright/test');
const {execFile}=require('node:child_process');
const {promisify}=require('node:util');
const fs=require('node:fs/promises'),path=require('node:path'),{pathToFileURL}=require('node:url');
const python=require('./python-runtime');
const run=promisify(execFile);

async function exported(info){
  const output=info.outputPath('receiving-files');
  await run(python,[path.join(__dirname,'archive_fixture.py'),'--output',output],
    {cwd:__dirname,timeout:90000,windowsHide:true,maxBuffer:1024*1024});
  return output;
}
async function offline(browser){
  const context=await browser.newContext({offline:true});
  const requests=[];
  await context.route(/^https?:\/\//,route=>{requests.push(route.request().url());return route.abort();});
  return {context,requests,page:await context.newPage()};
}
const upload=(name,content)=>({name,mimeType:'application/json',buffer:Buffer.from(content)});

test('installation A task archive opens in an independent offline viewer with verified provenance',async({browser},info)=>{
  test.setTimeout(120000);
  const output=await exported(info),receiver=await offline(browser);
  try{
    const {page}=receiver;
    await page.goto(pathToFileURL(path.join(output,'viewer.html')).href);
    await page.locator('#archive').setInputFiles(path.join(output,'task.json'));
    await expect(page.locator('#status')).toContainText('Record counts and content checksum match the manifest.');
    await expect(page.locator('#record')).toContainText('Captured result — café; no external action.');
    await expect(page.locator('#record')).toContainText('Original evidence <img src=https://blocked.invalid/x>');
    await expect(page.locator('#record')).toContainText('Source task 1; recorded version');
    await expect(page.locator('#record script,#record img')).toHaveCount(0);
    await expect(page.getByText('It does not upload files, import live tasks, replay actions or grant access to connected systems.',{exact:false})).toBeVisible();
    expect(receiver.requests).toEqual([]);
  }finally{await receiver.context.close();}
});

test('offline viewer refuses changed, malformed, newer and oversized input without retaining prior task content',async({browser},info)=>{
  test.setTimeout(120000);
  const output=await exported(info),receiver=await offline(browser);
  try{
    const {page}=receiver,original=await fs.readFile(path.join(output,'task.json'),'utf8');
    await page.goto(pathToFileURL(path.join(output,'viewer.html')).href);
    await page.locator('#archive').setInputFiles(upload('valid.json',original));
    await expect(page.locator('#status')).toContainText('checksum match');
    for(const [name,content,message] of [
      ['changed.json',original.replace('Captured result','Tampered result'),'do not match its integrity manifest'],
      ['malformed.json','{','not readable JSON'],
      ['newer.json',JSON.stringify({...JSON.parse(original),v:2}),'not a supported version 1'],
      ['counts.json',original.replace('"event_count":1','"event_count":2'),'record counts do not match'],
      ['large.json',' '.repeat(20*1024*1024+1),'exceeds the supported viewer size'],
    ]){
      await page.locator('#archive').setInputFiles(upload(name,content));
      await expect(page.locator('#status')).toContainText(message);
      await expect(page.locator('#record')).toBeEmpty();
    }
    const legacy=JSON.parse(original);delete legacy.manifest;
    await page.locator('#archive').setInputFiles(upload('legacy.json',JSON.stringify(legacy)));
    await expect(page.locator('#status')).toContainText('Integrity could not be checked for this legacy file.');
    await expect(page.locator('#record')).toContainText('completeness is unknown');
    expect(receiver.requests).toEqual([]);
  }finally{await receiver.context.close();}
});

test('recipient verifies exported bundle content offline and gets a refusal for missing, changed or duplicate files',async({browser},info)=>{
  test.setTimeout(120000);
  const output=await exported(info),directory=path.join(output,'bundle'),receiver=await offline(browser);
  try{
    const {page}=receiver,manifest=JSON.parse(await fs.readFile(path.join(directory,'manifest.json'),'utf8'));
    const files=await Promise.all(manifest.files.map(async item=>({name:item.name,mimeType:'application/octet-stream',buffer:await fs.readFile(path.join(directory,item.name))})));
    const sameLengthTamper=Buffer.from(files[0].buffer);
    expect(sameLengthTamper.length).toBeGreaterThan(0);
    sameLengthTamper[0]^=1;
    await page.goto(pathToFileURL(path.join(directory,'index.html')).href);
    await expect(page.getByRole('heading',{name:'Recipient evidence bundle'})).toBeVisible();
    await expect(page.locator('body')).toContainText('No current human acceptance');
    await expect(page.locator('body')).toContainText('Verify the source figures.');
    await expect(page.locator('body')).not.toContainText('Never include this artifact.');
    await expect(page.locator('table')).toContainText('=UNTRUSTED()');
    await page.getByRole('link',{name:'Verify extracted files offline'}).click();
    for(const [selected,valid] of [[files,true],[files.slice(1),false],
      [[{...files[0],buffer:Buffer.from('changed source')},...files.slice(1)],false],
      [[{...files[0],buffer:sameLengthTamper},...files.slice(1)],false],[[...files,files[0]],false]]){
      await page.locator('#files').setInputFiles(selected);
      await page.getByRole('button',{name:'Check selected files'}).click();
      // The handler clears this list synchronously and appends one result per
      // file after its digest. A previous identical status cannot pass this
      // iteration before its own complete set of hashes has finished.
      await expect(page.locator('#results li')).toHaveCount(manifest.files.length);
      await expect(page.locator('#status')).toContainText(valid?'All manifest content files match.':'Verification incomplete.');
      await expect(page.locator('#results li').first()).toHaveText(manifest.files[0].name+': '+(valid?'Matches captured bytes':'Missing, duplicated or changed'));
    }
    expect(receiver.requests).toEqual([]);
  }finally{await receiver.context.close();}
});
