// Automated WCAG 2.2 A/AA check of the most-used pages in the light, dark and
// high-contrast themes, with axe-core (the rules tagged wcag2a, wcag2aa,
// wcag21a, wcag21aa and wcag22aa). Any violation fails the build unless it is
// listed below as a known exception. Automated rules find only part of the
// problems (Deque counts about 57% of issues), so keyboard, screen-reader and
// zoom passes stay manual release checks; the rules axe could not decide
// ("needs review") are attached for that review and do not fail the run.
//
// Pages: 18 fixed pages that make up the most-visited set, plus four pages a
// full-site scan has found failing (tasks and privacy requests need records
// this server does not seed, so they are not scanned here). Reduced motion is emulated so a fade
// caught half way cannot be mistaken for low contrast; colours are unchanged.
const fs=require('node:fs');
const {test,expect}=require('@playwright/test');

const AXE_SOURCE=fs.readFileSync(require.resolve('axe-core/axe.min.js'),'utf8');
const WCAG_TAGS=['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa'];
const ROUTES=['/chat','/start','/goals','/approvals','/deliverables','/me','/settings','/settings/all',
  '/providers','/spending-limits','/users','/tenants','/audit','/privacy','/security','/agents',
  '/workflows','/overview',
  // Pages where a full-site scan found violations the list above does not
  // cover (pinned links, disclosures, scroll boxes).
  '/today','/automations','/skills','/ai-evidence-analysis'];
const THEMES=['light','dark','hicontrast'];

// Known exceptions. Each one names the rule, page, theme ('*' for all), the
// element (an axe target, matched exactly), why it cannot be fixed yet, who
// owns the fix and the date it expires. An expired entry fails the run so it
// is looked at again; an entry that no longer matches anything fails so the
// list only shrinks.
const KNOWN_EXCEPTIONS=[];

function today(){return new Date().toISOString().slice(0,10);}

function excepted(theme,route,rule,target){
  return KNOWN_EXCEPTIONS.find(entry=>entry.rule===rule&&entry.route===route&&entry.target===target
    &&(entry.theme==='*'||entry.theme===theme));
}

async function shellReady(page){
  await expect(page.locator('#navfinder-dialog')).toHaveAttribute('data-navfinder-ready','true');
  // Lists and cards filled by the page's own requests are scanned too; pages
  // that keep a live connection open never go idle, so the wait is bounded.
  await page.waitForLoadState('networkidle',{timeout:4000}).catch(()=>{});
  await page.evaluate(()=>document.fonts.ready);
}

async function useTheme(page,theme){
  // The same request Display preferences makes with "Save on this device only".
  await page.goto('/start');await shellReady(page);
  const status=await page.evaluate(async value=>{
    const context=document.querySelector('meta[name="lightwork-preference-context"]');
    const response=await fetch('/api/v1/preferences/display',{method:'POST',credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({key:'theme',value,context:context?context.content:'',device_only:true})});
    return response.status;
  },theme);
  expect(status,`saving the ${theme} theme`).toBe(200);
}

async function scan(page){
  await page.evaluate(AXE_SOURCE);
  return page.evaluate(async tags=>{
    const result=await window.axe.run(document,{runOnly:{type:'tag',values:tags},resultTypes:['violations']});
    return {version:window.axe.version,
      violations:result.violations.map(rule=>({rule:rule.id,impact:rule.impact,help:rule.help,
        nodes:rule.nodes.map(node=>({target:node.target.join(' '),html:node.html.slice(0,240),
          summary:(node.failureSummary||'').replace(/\s+/g,' ').slice(0,400)}))})),
      // Only violations are aggregated in full (much faster); for the rules
      // that need a person's review, the names are enough to start one.
      needsReview:result.incomplete.map(rule=>rule.id)};
  },WCAG_TAGS);
}

test('every known accessibility exception is complete and not past its date',()=>{
  for(const entry of KNOWN_EXCEPTIONS){
    for(const key of ['rule','route','theme','target','reason','owner','expires'])
      expect(entry[key],`${JSON.stringify(entry)} needs ${key}`).toBeTruthy();
    expect(entry.expires>=today(),`${entry.rule} on ${entry.route} expired on ${entry.expires}`).toBe(true);
  }
});

for(const theme of THEMES) test(`most-used pages pass axe WCAG 2.2 AA in the ${theme} theme`,async({page,context,baseURL},info)=>{
  test.setTimeout(240000);
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin
    ?route.continue():route.abort('blockedbyclient'));
  await page.setViewportSize({width:1280,height:900});
  await page.emulateMedia({reducedMotion:'reduce'});
  await useTheme(page,theme);
  const report=[],unexpected=[],used=new Set();
  for(const route of ROUTES){
    await test.step(route,async()=>{
      const response=await page.goto(route);
      expect(response.status(),`${route} loads`).toBe(200);
      await shellReady(page);
      await expect(page.locator('body')).toHaveClass(new RegExp(`(^|\\s)theme-${theme}(\\s|$)`));
      const result=await scan(page);
      report.push({route,...result});
      for(const rule of result.violations) for(const node of rule.nodes){
        const entry=excepted(theme,route,rule.rule,node.target);
        if(entry)used.add(entry);
        else unexpected.push(`${route} [${theme}] ${rule.rule} (${rule.impact}): ${node.target} -- ${node.summary}`);
      }
    });
  }
  await info.attach(`axe-${theme}.json`,{body:JSON.stringify(report,null,2),contentType:'application/json'});
  const stale=KNOWN_EXCEPTIONS.filter(entry=>(entry.theme==='*'||entry.theme===theme)&&!used.has(entry));
  expect(stale.map(entry=>`${entry.rule} on ${entry.route}: ${entry.target}`),'exceptions that no longer occur').toEqual([]);
  expect(unexpected,unexpected.join('\n')).toEqual([]);
});
