// Shipped UI with explicit synthetic hosted-cost API responses; no embeddings.
const {test,expect}=require('@playwright/test');

test('hosted rebuild shows a positive small admission ceiling and never retries an uncertain outcome',async({page,context,baseURL},info)=>{
  await page.setViewportSize({width:390,height:844});
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin
    ?route.continue():route.abort('blockedbyclient'));
  const binding='a'.repeat(64),review='b'.repeat(64),writes=[],errors=[];
  let job=null,archived=false;
  page.on('pageerror',error=>errors.push(error.message));
  await page.route('**/api/v1/knowledge/library**',async route=>{
    const request=route.request(),path=new URL(request.url()).pathname;
    if(request.method()==='POST'){
      const body=request.postDataJSON();writes.push({path,body});
      if(path.endsWith('/collections/browser-hosted/reindex')){
        job={job_id:body.job_id,collection:'browser-hosted',count:3,done:1,state:'unconfirmed',
          message:'Synthetic uncertain provider outcome. Check the existing receipt; do not resend.',
          observed_dollars:0.000005,unresolved_dollars:0.00012};
        return route.fulfill({status:202,json:{context:binding,job}});
      }
      if(job&&path.endsWith('/reindex-jobs/'+job.job_id+'/archive')){
        archived=true;return route.fulfill({json:{context:binding,job:{...job,archived:true,receipt_retained:true}}});
      }
      return route.fulfill({status:409,json:{detail:'Unexpected write in synthetic rebuild fixture'}});
    }
    if(path.endsWith('/collections/browser-hosted/reindex-review'))return route.fulfill({json:{context:binding,
      review:{review,count:3,model:'synthetic-hosted-embedding',cost_ceiling:0.000125,
        price_basis:'Captured synthetic standard rate, 2026-10-01. Admission reservation, not a provider invoice.',
        limits:{max_wall_seconds:60}}}});
    if(path.endsWith('/reindex-jobs'))return route.fulfill({json:{context:binding,jobs:job&&!archived?[job]:[]}});
    if(path==='/api/v1/knowledge/library')return route.fulfill({json:{enabled:true,
      collections:[{name:'browser-hosted',chunks:3}],starter_content:[]}});
    return route.fulfill({status:404,json:{detail:'Unknown synthetic rebuild route'}});
  });
  await page.goto('/knowledge-access');
  await page.getByRole('button',{name:'Rebuild the search index for Browser hosted',exact:true}).click();
  const confirm=page.locator('#mv-confirm');await expect(confirm).toBeVisible();
  // A tiny positive ceiling reads as "under $0.01" in the shared money format, never $0.00.
  await expect(confirm).toContainText('Provider admission ceiling: under $0.01');
  await expect(confirm).toContainText('Captured synthetic standard rate, 2026-10-01');
  await expect(confirm).toContainText('not a provider invoice');
  expect(writes).toEqual([]);
  await confirm.getByRole('button',{name:'Start rebuild',exact:true}).click();
  const jobs=page.getByRole('region',{name:'Search index rebuilds',exact:true});
  await expect(jobs).toContainText('Unconfirmed');
  // Sub-cent amounts read as "under $0.01"; the exact figures stay on the receipt.
  await expect(jobs).toContainText('Observed provider usage at reviewed rates: under $0.01');await expect(jobs).toContainText('Unresolved reservation: under $0.01');
  await expect(jobs.getByRole('button',{name:/Continue|Resume|Cancel/})).toHaveCount(0);
  expect(writes).toHaveLength(1);
  expect(writes[0].body).toEqual({context:binding,job_id:expect.stringMatching(/^[a-f0-9]{32}$/),review,confirmed:true});
  await jobs.getByRole('button',{name:'Refresh rebuild progress',exact:true}).click();
  await expect(jobs).toContainText('Unresolved reservation: under $0.01');expect(writes).toHaveLength(1);
  await info.attach('uncertain-hosted-cost',{body:await page.screenshot(),contentType:'image/png'});
  await jobs.getByRole('button',{name:'Archive finished rebuild',exact:true}).click();
  await expect(confirm).toContainText('Its operation receipt remains recorded');
  expect(writes).toHaveLength(1);
  await confirm.getByRole('button',{name:'Archive',exact:true}).click();
  await expect(jobs.locator('.mv-empty__title')).toHaveText('No rebuilds to show');
  await expect(jobs.locator('.mv-empty__body')).toContainText('Archived operation receipts remain recorded.');
  expect(writes).toHaveLength(2);
  expect(writes[1]).toEqual({path:'/api/v1/knowledge/library/reindex-jobs/'+writes[0].body.job_id+'/archive',
    body:{context:binding,confirmed:true}});
  expect(errors).toEqual([]);
});
