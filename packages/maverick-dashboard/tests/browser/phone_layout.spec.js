// Phones, zoom and covered focus.
// - On a 375 px touch screen the primary controls are 44 x 44 px or
//   larger and text fields use 16 px text (so the page does not zoom on focus).
// - At 320 px nothing scrolls sideways; with text alone at 200% and on
//   a phone turned sideways (844 x 390) nothing scrolls sideways either, and
//   no page locks the orientation.
// - On a 390 px phone, My work shows "Decide by" and "Waiting on" for
//   every waiting decision inside the screen.
// - WCAG 2.4.11: moving through Tasks with Tab, no focused control is
//   hidden behind the floating Copilot button or another fixed control.
const {test,expect}=require('@playwright/test');

async function ready(page){
  await expect(page.locator('#navfinder-dialog')).toHaveAttribute('data-navfinder-ready','true');
  await page.waitForLoadState('networkidle',{timeout:4000}).catch(()=>{});
}
async function seedApproval(request){
  const seeded=await request.post('/__browser_fixture/approvals/setup');expect(seeded.status()).toBe(200);
}
async function sideways(page){
  return page.evaluate(()=>({scroll:document.documentElement.scrollWidth,width:document.documentElement.clientWidth}));
}

test.describe('on a 375 px touch screen',()=>{
  test.use({viewport:{width:375,height:812},isMobile:true,hasTouch:true});
  for(const path of ['/goals','/approvals','/settings','/me']){
    test(`${path}: primary controls fit a thumb and fields do not zoom`,async({page,request})=>{
      if(path==='/approvals')await seedApproval(request);
      await page.goto(path);await ready(page);
      const found=await page.evaluate(()=>{
        const shown=e=>{const r=e.getBoundingClientRect(),cs=getComputedStyle(e);return r.width>0&&r.height>0&&cs.visibility!=='hidden'&&!e.closest('[hidden],[inert],details:not([open]) > :not(summary)');};
        const primary=[...document.querySelectorAll('header.topbar button, header.topbar summary, header.topbar a, #nav-toggle, main .btn, button.approval-btn')].filter(shown);
        const small=primary.map(e=>{const r=e.getBoundingClientRect();return {name:(e.getAttribute('aria-label')||e.textContent).trim().replace(/\s+/g,' ').slice(0,40),w:Math.round(r.width),h:Math.round(r.height)};})
          .filter(t=>t.w<44||t.h<44);
        const fields=[...document.querySelectorAll('input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=range]):not([type=file]):not([type=color]):not([type=submit]):not([type=button]),select,textarea')].filter(shown);
        const zooming=fields.filter(e=>parseFloat(getComputedStyle(e).fontSize)<16).map(e=>(e.id||e.name||e.tagName)+' '+getComputedStyle(e).fontSize);
        return {primary:primary.length,small,fields:fields.length,zooming};
      });
      expect(found.primary).toBeGreaterThan(5);
      expect(found.small).toEqual([]);
      expect(found.zooming).toEqual([]);
    });
  }
});

test.describe('at 320 px',()=>{
  test.use({viewport:{width:320,height:640}});
  for(const path of ['/partner','/goals','/approvals','/me','/settings','/chat','/users','/security']){
    test(`${path} does not scroll sideways`,async({page})=>{
      await page.goto(path);await ready(page);
      const size=await sideways(page);
      expect(size.scroll,JSON.stringify(size)).toBeLessThanOrEqual(size.width+1);
    });
  }
});

test('with text alone at 200% nothing scrolls sideways',async({page})=>{
  await page.setViewportSize({width:1280,height:900});
  for(const path of ['/goals','/approvals','/me','/settings','/users','/chat']){
    await page.goto(path);await ready(page);
    await page.evaluate(()=>{document.documentElement.style.fontSize='200%';});
    const size=await sideways(page);
    expect(size.scroll,`${path} ${JSON.stringify(size)}`).toBeLessThanOrEqual(size.width+1);
  }
});

test.describe('on a phone turned sideways',()=>{
  test.use({viewport:{width:844,height:390},isMobile:true,hasTouch:true});
  test('pages reflow and never lock the orientation',async({page,context})=>{
    await context.addInitScript(()=>{if(screen.orientation&&screen.orientation.lock)screen.orientation.lock=()=>{window.__orientationLocked=true;return Promise.resolve();};});
    for(const path of ['/goals','/approvals','/me','/settings','/chat']){
      await page.goto(path);await ready(page);
      const size=await sideways(page);
      expect(size.scroll,`${path} ${JSON.stringify(size)}`).toBeLessThanOrEqual(size.width+1);
      expect(await page.evaluate(()=>!!window.__orientationLocked),path).toBe(false);
    }
  });
});

test.describe('My work on a 390 px phone',()=>{
  test.use({viewport:{width:390,height:844},isMobile:true,hasTouch:true});
  test('shows when each decision is due and who it waits on, inside the screen',async({page,request})=>{
    await seedApproval(request);
    await page.goto('/me');await ready(page);
    const cells=page.locator('table.table--stacked td[data-label="Decide by"], table.table--stacked td[data-label="Waiting on"]');
    expect(await cells.count()).toBeGreaterThan(1);
    const outside=await cells.evaluateAll(nodes=>nodes.filter(node=>{const r=node.getBoundingClientRect();return r.left<0||r.right>innerWidth+1;}).length);
    expect(outside).toBe(0);
    const size=await sideways(page);
    expect(size.scroll).toBeLessThanOrEqual(size.width+1);
  });
});

test('Tasks: no focused control is hidden behind a floating control',async({page})=>{
  await page.setViewportSize({width:1280,height:900});
  await page.goto('/goals');await ready(page);
  const hidden=[];
  for(let stop=0;stop<120;stop++){
    await page.keyboard.press('Tab');
    const focus=await page.evaluate(()=>{
      const e=document.activeElement;if(!e||e===document.body)return null;
      const r=e.getBoundingClientRect();
      const points=[[r.left+r.width/2,r.top+r.height/2],[r.left+2,r.top+2],[r.right-2,r.top+2],[r.left+2,r.bottom-2],[r.right-2,r.bottom-2]]
        .filter(([x,y])=>x>=0&&y>=0&&x<=innerWidth&&y<=innerHeight);
      const seen=points.filter(([x,y])=>{const hit=document.elementFromPoint(x,y);return hit&&(hit===e||e.contains(hit)||hit.contains(e));}).length;
      return {name:(e.getAttribute('aria-label')||e.textContent||'').trim().replace(/\s+/g,' ').slice(0,40),points:points.length,seen};
    });
    if(focus&&focus.points&&!focus.seen)hidden.push(`${stop+1}: ${focus.name}`);
  }
  expect(hidden).toEqual([]);
});
