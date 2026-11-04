const {test,expect}=require('@playwright/test');

async function localOnly(context,baseURL){
  await context.route('**/*',route=>
    new URL(route.request().url()).origin===new URL(baseURL).origin
      ? route.continue():route.abort('blockedbyclient'));
}

async function paginateCohortPilotLists(context){
  await context.route('**/api/v1/outcome-pilots*',async route=>{
    const request=route.request();
    const url=new URL(request.url());
    if(request.method()==='GET'&&url.pathname==='/api/v1/outcome-pilots'){
      url.searchParams.set('limit','1');
      const response=await route.fetch({url:url.toString()});
      await route.fulfill({response});
      return;
    }
    await route.fallback();
  });
}

async function fits(page){
  const widths=await page.evaluate(()=>[
    document.documentElement.scrollWidth,document.documentElement.clientWidth,
  ]);
  expect(widths[0]).toBeLessThanOrEqual(widths[1]+1);
}

async function json(response,label){
  const body=await response.text();
  expect(response.ok(),`${label} failed (${response.status()}): ${body}`).toBe(true);
  return JSON.parse(body);
}

function pilotBody(group,index){
  return {
    operation_id:`browser_value_pilot_${index}_0001`,
    title:index===1?'Browser value evidence pilot':'Browser isolation control pilot',
    customer:'Synthetic browser team',
    workflow:'Local browser acceptance with no provider or customer execution.',
    criteria:'The stored synthetic source result and named-human decision must agree.',
    learning_mode:'observational',
    prior_exposure_statement:'',
    cases:group.map(({kind,reference,label})=>({kind,reference,label})),
  };
}

function observation(row,pilotIndex,caseId,revision,sourceVersion){
  const costCoverage={
    provider_usage:{
      status:'zero',
      note:'The local fixture makes no provider calls.',
    },
    failed_attempts:{
      status:row.fixture_outcome==='failed'?'included':'zero',
      note:row.fixture_outcome==='failed'
        ?'The synthetic all-in total includes the failed attempt.'
        :'The local fixture recorded no failed attempt.',
    },
    setup:{status:'zero',note:'No setup cost was incurred by the local fixture.'},
    review:{
      status:'unknown',
      note:'Delivered review time and its price are intentionally unavailable.',
    },
    exception:{status:'zero',note:'No separate exception cost was recorded.'},
    rework:{
      status:'unknown',
      note:'Delivered rework time and its price are intentionally unavailable.',
    },
    support:{status:'zero',note:'No support cost was incurred by the local fixture.'},
    allocation:{status:'zero',note:'The per-case total requires no shared allocation.'},
  };
  return {
    expected_revision:revision,
    operation_id:`browser_observation_${pilotIndex}_${caseId}_0001`,
    source_version:sourceVersion,
    baseline_minutes:null,
    ai_hands_on_minutes:null,
    review_minutes:null,
    rework_minutes:null,
    corrections:0,
    baseline_wall_minutes:null,
    ai_wall_minutes:null,
    baseline_cost:null,
    ai_total_cost:row.fixture_cost,
    human_cost:null,
    rework_cost:null,
    currency:'USD',
    evidence:`Synthetic ${row.fixture_outcome} source outcome reviewed in the local fixture.`,
    note:'Delivered human-time evidence is intentionally absent for the ROI guard.',
    criteria_met:row.fixture_outcome==='accepted',
    cost_coverage:costCoverage,
  };
}

async function seed(page){
  const setup=await json(
    await page.request.post('/__browser_fixture/outcome-value/setup'),
    'outcome-value source setup',
  );
  expect(setup).toMatchObject({synthetic:true,provider_calls:0});
  expect(setup.groups).toHaveLength(2);
  const headers={'X-Lightwork-Pilot-Context':setup.context};
  const pilots=[];
  for(let index=0;index<setup.groups.length;index+=1){
    const created=await json(await page.request.post('/api/v1/outcome-pilots',{
      headers,data:pilotBody(setup.groups[index],index+1),
    }),`pilot ${index+1} creation and admission`);
    expect(created.context).toBe(setup.context);
    pilots.push(created.id);
  }
  const finished=await json(
    await page.request.post('/__browser_fixture/outcome-value/finish',{
      data:{pilot_ids:pilots},
    }),
    'outcome-value source completion',
  );
  expect(finished).toMatchObject({
    synthetic:true,provider_calls:0,finished:true,pilot_ids:pilots,
  });

  for(let pilotIndex=0;pilotIndex<pilots.length;pilotIndex+=1){
    const report=await json(await page.request.get(
      `/api/v1/outcome-pilots/${pilots[pilotIndex]}`,{headers},
    ),`pilot ${pilotIndex+1} source report`);
    let revision=report.revision;
    for(const item of report.cases){
      const sourceRow=setup.groups[pilotIndex].find(
        row=>row.reference===item.reference,
      );
      expect(sourceRow).toBeTruthy();
      const saved=await json(await page.request.put(
        `/api/v1/outcome-pilots/${pilots[pilotIndex]}/cases/${item.id}`,
        {headers,data:observation(
          sourceRow,pilotIndex+1,item.id,revision,item.source.version,
        )},
      ),`pilot ${pilotIndex+1} case ${item.id} observation and accounting sync`);
      revision=saved.revision;
    }
  }
  return {context:setup.context,headers,pilots};
}

async function cohort(page,pilotId,headers){
  return json(await page.request.get(
    `/api/v1/outcome-accounting/cohort?pilot_id=${encodeURIComponent(pilotId)}`,
    {headers},
  ),`cohort ${pilotId}`);
}

test('real admitted pilot cohorts remain isolated and withhold ROI without human-time evidence',async({page,context,baseURL},info)=>{
  test.setTimeout(90000); // Eight real admissions, independent cohort reads, baseline correction and exact export.
  await localOnly(context,baseURL);
  // Run as a dedicated synthetic owner: the portfolio, pilot pagination and
  // accounting summary assert exact counts, and earlier journeys admit
  // records for the shared reviewer during the same server session.
  await context.setExtraHTTPHeaders({Origin:baseURL,'X-Browser-Principal':'browser-outcome-owner'});
  await paginateCohortPilotLists(context);
  const errors=[];
  const consoleErrors=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('console',message=>{
    if(message.type()==='error')consoleErrors.push(message.text());
  });

  const seeded=await seed(page);
  const [primary,control]=await Promise.all([
    cohort(page,seeded.pilots[0],seeded.headers),
    cohort(page,seeded.pilots[1],seeded.headers),
  ]);
  expect(primary.admitted).toBe(4);
  expect(primary.categories).toEqual({
    accepted:1,rejected:0,failed:1,cancelled:1,unresolved:1,
  });
  expect(primary.costs).toMatchObject({
    known_totals:{USD:'11'},incomplete_records:4,failed_attempts:1,complete:false,
  });
  expect(control.admitted).toBe(4);
  expect(control.categories).toEqual({
    accepted:1,rejected:1,failed:1,cancelled:1,unresolved:0,
  });
  expect(control.costs).toMatchObject({
    known_totals:{USD:'72'},incomplete_records:4,failed_attempts:1,complete:false,
  });
  const primaryIds=new Set(primary.cases.map(item=>item.outcome.id));
  const controlIds=new Set(control.cases.map(item=>item.outcome.id));
  expect([...primaryIds].some(identifier=>controlIds.has(identifier))).toBe(false);
  expect(primary.cohort_binding.record_count).toBe(4);
  expect(control.cohort_binding.record_count).toBe(4);
  expect(primary.cohort_binding.acceptance_contract_ref).toBe(
    `outcome-pilot:${seeded.pilots[0]}:${primary.plan_version}`,
  );
  expect(control.cohort_binding.acceptance_contract_ref).toBe(
    `outcome-pilot:${seeded.pilots[1]}:${control.plan_version}`,
  );

  const portfolio=await json(await page.request.get(
    '/api/v1/outcome-accounting?limit=100',{headers:seeded.headers},
  ),'owner accounting portfolio');
  expect(portfolio.admitted).toBe(8);
  expect(portfolio.records).toHaveLength(8);

  await page.setViewportSize({width:320,height:900});
  await page.goto('/outcome-pilots');
  await expect(page.locator('#op-accounting-summary')).toContainText(
    '8 admitted records shown',
  );
  await expect(page.locator('#op-accounting-summary .op-accounting-record')).toHaveCount(8);
  const pilotSelector=page.locator('#ov-pilot');
  await expect(pilotSelector).toBeEnabled();
  await expect(pilotSelector.locator('option')).toHaveCount(2);
  const firstPagePilot=await pilotSelector.inputValue();
  expect(seeded.pilots).toContain(firstPagePilot);
  const secondPagePilot=seeded.pilots.find(identifier=>identifier!==firstPagePilot);
  const loadMore=page.getByRole('button',{name:'Load more pilot cohorts',exact:true});
  await expect(loadMore).toBeVisible();
  await loadMore.click();
  await expect(pilotSelector.locator('option')).toHaveCount(3);
  await expect(pilotSelector).toHaveValue(firstPagePilot);
  await expect(loadMore).toBeHidden();
  await pilotSelector.selectOption(secondPagePilot);
  await expect(page.locator('#ov-summary')).toContainText(
    secondPagePilot===seeded.pilots[0]?'USD 11':'USD 72',
  );
  await pilotSelector.selectOption(seeded.pilots[0]);
  await expect(page.locator('#ov-summary')).toContainText('4 admitted cases');
  await expect(page.locator('#ov-summary')).toContainText(
    'accepted 1 · rejected 0 · failed 1 · cancelled 1 · unresolved 1',
  );
  await expect(page.locator('#ov-summary')).toContainText('USD 11');
  await expect(page.locator('#ov-summary')).toContainText('4 cases with incomplete cost');
  await expect(page.locator('#ov-summary')).toContainText(
    'Cost comparison unavailable. No net savings or ROI is reported.',
  );
  await expect(page.locator('#ov-summary')).toContainText('Other: USD 11');
  await expect(page.getByRole('button',{name:'Download value evidence'})).toBeEnabled();
  await fits(page);

  await pilotSelector.selectOption(seeded.pilots[1]);
  await expect(page.locator('#ov-summary')).toContainText('USD 72');
  await expect(page.locator('#ov-summary')).toContainText(
    'accepted 1 · rejected 1 · failed 1 · cancelled 1 · unresolved 0',
  );
  await pilotSelector.selectOption(seeded.pilots[0]);
  await expect(page.locator('#ov-summary')).toContainText('USD 11');

  await page.getByText('Record or correct baseline evidence',{exact:true}).click();
  const accepted=primary.cases.find(item=>item.category==='accepted');
  expect(accepted).toBeTruthy();
  await page.locator('#ov-record').selectOption(accepted.outcome.id);
  const form=page.locator('#ov-baseline-form');
  await expect(form.locator('[name="cost_unknown_reason"]')).toBeDisabled();
  await form.locator('[name="cost_basis"]').selectOption('unknown');
  await expect(form.locator('[name="cost_amount"]')).toBeDisabled();
  await expect(form.locator('[name="cost_unknown_reason"]')).toBeEnabled();
  await form.locator('[name="cost_basis"]').selectOption('observed');
  await form.locator('[name="cost_amount"]').fill('20');
  await form.locator('[name="currency"]').fill('USD');
  await form.locator('[name="human_minutes"]').fill('60');
  await form.locator('[name="source_ref"]').fill('timesheet:browser-baseline');
  await form.locator('[name="evidence_note"]').fill(
    'Synthetic observed baseline cost and human-time evidence for browser acceptance.',
  );
  await form.getByRole('button',{name:'Save baseline evidence'}).click();
  await expect(page.locator('#ov-status')).toContainText('Evidence saved');
  await expect(page.locator('#ov-summary')).toContainText(
    'Cost comparison unavailable. No net savings or ROI is reported.',
  );

  const afterBaseline=await cohort(page,seeded.pilots[0],seeded.headers);
  const acceptedAfter=afterBaseline.cases.find(
    item=>item.outcome.id===accepted.outcome.id,
  );
  expect(acceptedAfter.baseline).toMatchObject({
    cost:{basis:'observed',value:'20',currency:'USD'},
    human_effort:{basis:'observed',value:'60'},
  });
  expect(acceptedAfter.outcome.costs).toMatchObject({
    complete:false,known_totals:{USD:'3'},
  });
  expect(acceptedAfter.comparison.human_effort.status).toBe('unavailable');
  expect(acceptedAfter.comparison.missing_components).toContain('delivered_human_time');
  expect(acceptedAfter.comparison.cost).toMatchObject({
    status:'unavailable',net_savings:null,roi_percent:null,
    reason:'delivered cost coverage is incomplete',
  });
  expect(acceptedAfter.comparison.measured_positive_roi).toBe(false);
  expect(afterBaseline.admitted).toBe(4);
  expect(afterBaseline.cases).toHaveLength(4);

  const downloadPromise=page.waitForEvent('download');
  await page.getByRole('button',{name:'Download value evidence'}).click();
  const download=await downloadPromise;
  expect(download.suggestedFilename()).toBe('lightwork-outcome-value-report.json');
  const stream=await download.createReadStream();
  const chunks=[];
  for await(const chunk of stream)chunks.push(chunk);
  const exported=JSON.parse(Buffer.concat(chunks).toString('utf8'));
  expect(exported).toMatchObject({
    schema:'lightwork.outcome-value-export.v1',
    pilot_id:seeded.pilots[0],
    admitted:4,
    context:seeded.context,
  });
  expect(exported.cohort_binding).toEqual(afterBaseline.cohort_binding);
  const exportedAccepted=exported.cases.find(
    item=>item.outcome.id===accepted.outcome.id,
  );
  expect(exportedAccepted.comparison.cost).toMatchObject({
    status:'unavailable',net_savings:null,roi_percent:null,
  });
  await expect(page.locator('#ov-status')).toContainText('Value evidence report downloaded');

  const fixtureState=await json(
    await page.request.get('/__browser_fixture'),
    'browser fixture state',
  );
  expect(fixtureState.outbound_calls).toBe('blocked');
  const phoneScreenshot=info.outputPath('outcome-value-phone.png');
  await page.screenshot({path:phoneScreenshot,fullPage:true});
  await info.attach('outcome-value-phone',{
    path:phoneScreenshot,contentType:'image/png',
  });
  await page.setViewportSize({width:1280,height:900});
  await fits(page);
  const desktopScreenshot=info.outputPath('outcome-value-desktop.png');
  await page.screenshot({path:desktopScreenshot,fullPage:true});
  await info.attach('outcome-value-desktop',{
    path:desktopScreenshot,contentType:'image/png',
  });
  expect(errors).toEqual([]);
  expect(consoleErrors).toEqual([]);
});
