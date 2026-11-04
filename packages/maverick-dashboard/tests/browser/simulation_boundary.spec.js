const {test,expect}=require('@playwright/test');

test.beforeEach(async({context,page,baseURL})=>{
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort('blockedbyclient'));
  page.__errors=[];
  page.on('pageerror',error=>page.__errors.push(error.message));
});

test.afterEach(async({page,context},info)=>{
  await context.unrouteAll({behavior:'ignoreErrors'});
  const path=info.outputPath('rendered-simulation.png');
  await page.screenshot({path,fullPage:true});
  await info.attach('rendered-simulation',{path,contentType:'image/png'});
  expect(page.__errors).toEqual([]);
});

async function fits(page){
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth+1)).toBe(true);
}

test('simulation stays visibly separate from a live business outcome on phone and desktop',async({page,request},info)=>{
  const response=await request.get('/api/v1/simulate?surface=browser&action=click&target=text%3DPay%20now');
  expect(response.status()).toBe(200);
  const payload=await response.json();
  expect(payload).toMatchObject({
    result_class:'simulation',evidence_class:'simulated',live_effect:false,
    can_accept_business_outcome:false,authoritative_live_evidence_eligible:false,
    business_outcome_acceptance:'prohibited'
  });

  await page.setViewportSize({width:320,height:780});
  await page.goto('/simulate?surface=browser&action=click&target=text%3DPay%20now');
  const boundary=page.getByTestId('simulation-boundary');
  await expect(boundary).toContainText('Simulation only');
  await expect(boundary).toContainText('No live action ran and no external system changed');
  await expect(boundary).toContainText('cannot be accepted as a live business outcome');
  await expect(page.getByText('Not eligible for acceptance',{exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:/accept.*business outcome/i})).toHaveCount(0);
  await fits(page);
  const phone=info.outputPath('simulation-boundary-320.png');
  await page.screenshot({path:phone,fullPage:true});
  await info.attach('simulation-boundary-320',{path:phone,contentType:'image/png'});

  const surface=page.getByLabel('Where the action happens');
  await surface.focus();
  await expect(surface).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByLabel('What the agent does')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByLabel(/What it acts on/)).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button',{name:'Test this action',exact:true})).toBeFocused();

  await page.setViewportSize({width:1280,height:900});
  await expect(boundary).toBeVisible();
  await fits(page);
  const desktop=info.outputPath('simulation-boundary-1280.png');
  await page.screenshot({path:desktop,fullPage:true});
  await info.attach('simulation-boundary-1280',{path:desktop,contentType:'image/png'});

  const researchResponse=await request.post('/api/v1/simulate/research?component=feature-prefix');
  expect(researchResponse.status()).toBe(200);
  const researchPayload=await researchResponse.json();
  expect(researchPayload).toMatchObject({
    scenario_id:'dashboard-synthetic-research-v1',
    component_id:'feature-prefix-backoff-baseline-v1',
    success:true,component_process_isolated:true,oracle_passed:true,
    authority_requires_approval:true,approver_principal:'user:browser-reviewer',
    action_lineage_valid:true,evidence_class:'simulated',result_class:'simulation',
    live_effect:false,can_accept_business_outcome:false,
    authoritative_live_evidence_eligible:false,business_outcome_acceptance:'prohibited',
    synthetic_fixture:true
  });
  expect(researchPayload.source_ref).toMatch(/^simulator:sim-/);

  await page.getByText('Run a practice study (sample data only)').click();
  await page.getByLabel('Study type').selectOption('feature-prefix');
  await page.getByRole('button',{name:'Approve and run practice study'}).click();
  await expect(page).toHaveURL(/\/simulate\/research$/);
  const researchBoundary=page.getByTestId('research-simulation-boundary');
  await expect(researchBoundary).toContainText('Simulation only');
  await expect(researchBoundary).toContainText('Practice study finished');
  await expect(researchBoundary).toContainText('Built-in made-up software world');
  await expect(researchBoundary).toContainText('Kept separate');
  await expect(researchBoundary).toContainText('Approved by');
  await expect(researchBoundary).toContainText('Not eligible for acceptance');
  await expect(page.getByRole('button',{name:/accept.*business outcome/i})).toHaveCount(0);
  await fits(page);
  const research=info.outputPath('research-simulation-boundary-1280.png');
  await page.screenshot({path:research,fullPage:true});
  await info.attach('research-simulation-boundary-1280',{path:research,contentType:'image/png'});

  await page.setViewportSize({width:320,height:780});
  await expect(researchBoundary).toBeVisible();
  await fits(page);
  const researchTable=page.getByTestId('research-simulation-table');
  expect(await researchTable.evaluate(element=>element.scrollWidth<=element.clientWidth+1)).toBe(true);
  expect(await researchTable.locator('td').evaluateAll(cells=>cells.every(cell=>{
    const cellBox=cell.getBoundingClientRect();
    const tableBox=cell.closest('table').getBoundingClientRect();
    return cellBox.left>=tableBox.left-1&&cellBox.right<=tableBox.right+1;
  }))).toBe(true);
  const researchPhone=info.outputPath('research-simulation-boundary-320.png');
  await page.screenshot({path:researchPhone,fullPage:true});
  await info.attach('research-simulation-boundary-320',{path:researchPhone,contentType:'image/png'});
});
