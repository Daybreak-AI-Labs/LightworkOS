// Stop follows the run: it is there while a task works, gone once the task is
// over, and the chat list in the sidebar uses the same words as the task page.
// Synthetic local chat records only; no inference runs.
const {test,expect}=require('@playwright/test');

async function localOnly(context,baseURL){
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort('blockedbyclient'));
}
async function openWorkingTask(page,request){
  const created=await request.post('/__browser_fixture/chat');
  expect(created.status(),await created.text()).toBe(200);
  const {goal_id:goal}=await created.json();
  await page.goto(`/chat/goal/${goal}`);
  return {goal,stop:page.locator('#cancel-btn'),recents:page.locator(`#cs-list a[href="/chat/goal/${goal}"] + .cs-list__status`)};
}

test('Stop is offered while a task works and goes away once it has stopped on a problem',async({page,request,context,baseURL})=>{
  await localOnly(context,baseURL);const errors=[];page.on('pageerror',e=>errors.push(e.message));
  const {goal,stop,recents}=await openWorkingTask(page,request);
  await expect(page.locator('#status')).toHaveText('Working');
  await expect(stop).toBeVisible();
  await expect(recents).toHaveText('Working');
  // Guidance while a task works is on by default (owner decision, 4 October):
  // Send stays available for guidance, so no "Send is unavailable" note shows.
  await expect(page.locator('#answer-send')).toBeEnabled();
  await expect(page.locator('#answer-input')).toHaveAttribute('placeholder', /Add guidance/);
  await expect(page.locator('#composer-run-note')).toBeHidden();

  const failed=await request.post(`/__browser_fixture/chat/${goal}/provider-fail`);
  expect(failed.status(),await failed.text()).toBe(200);
  await expect(page.locator('#status')).toHaveText('Stopped');
  await expect(stop).toBeHidden();
  await expect(recents).toHaveText('Stopped');
  await expect(page.locator('#composer-run-note')).toBeHidden();
  expect(errors).toEqual([]);
});

test('pressing Stop once ends a working task, lists its progress and offers Try again',async({page,request,context,baseURL})=>{
  await localOnly(context,baseURL);const errors=[];page.on('pageerror',e=>errors.push(e.message));
  const {stop,recents}=await openWorkingTask(page,request);
  await expect(stop).toBeVisible();
  await expect(stop).toHaveText('Stop task');
  await stop.click();
  // One action: no confirmation dialog stands between the person and Stop.
  // (The shell always holds the shared dialog; it must stay closed.)
  await expect(page.locator('#mv-confirm')).not.toHaveAttribute('open', '');
  await expect(page.locator('#mv-confirm-ok')).toBeHidden();
  await expect(page.locator('#status')).toHaveAttribute('data-status','cancelled');
  await expect(page.locator('#status')).toHaveText('Stopped');
  await expect(stop).toBeHidden();
  await expect(recents).toHaveText('Stopped');
  await expect(page.locator('#halt-progress')).toBeVisible();
  await expect(page.locator('#halt-progress-headline')).toHaveText(/^Stopped/);
  await expect(page.locator('#halt-resume')).toHaveText('Try again');
  expect(errors).toEqual([]);
});

test('a finished task offers no Stop and the sidebar says Done',async({page,request,context,baseURL})=>{
  await localOnly(context,baseURL);const errors=[];page.on('pageerror',e=>errors.push(e.message));
  const {goal,stop,recents}=await openWorkingTask(page,request);
  await expect(stop).toBeVisible();
  const finished=await request.post(`/__browser_fixture/chat/${goal}/finish`);
  expect(finished.status(),await finished.text()).toBe(200);
  await expect(page.locator('#status')).toHaveText('Done');
  await expect(stop).toBeHidden();
  await expect(recents).toHaveText('Done');
  expect(errors).toEqual([]);
});
