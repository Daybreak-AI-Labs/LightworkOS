// Real shipped chat/composer and Chromium focus with synthetic question updates.
const {test,expect}=require('@playwright/test');

test('repeated question polls preserve composer selection and other-control focus',async({page,request,context,baseURL},info)=>{
  const origin=new URL(baseURL).origin,errors=[];
  await context.route('**/*',route=>new URL(route.request().url()).origin===origin
    ?route.continue():route.abort('blockedbyclient'));
  page.on('pageerror',error=>errors.push(error.message));
  const {goal_id:goal}=await (await request.get('/__browser_fixture')).json();
  let question={id:701,version:'question-one',question:'Which evidence should be included?'};
  // Close this synthetic stream without marking the task terminal. The shipped
  // five-second question timer keeps running; no test-only polling hook is used.
  await page.route(`**/api/goal/${goal}/events/stream?*`,route=>route.fulfill({
    contentType:'text/event-stream',
    body:'event: terminal\ndata: {"status":"blocked","terminal":false,"events":[]}\n\n',
  }));
  await page.route(`**/api/v1/goals/${goal}/open_questions`,route=>route.fulfill({
    json:{open_questions:[question]},
  }));
  const composer=page.locator('#answer-input'),text=page.locator('#question-text');
  async function nextPoll(){
    const response=await page.waitForResponse(response=>
      new URL(response.url()).pathname===`/api/v1/goals/${goal}/open_questions`);
    expect(response.status()).toBe(200);await response.finished();
    // Let fetch/JSON continuations and the MutationObserver complete. This does
    // not manufacture a question response or invoke an internal application API.
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
  }
  try {
    await page.goto(`/chat/goal/${goal}`);
    await expect(text).toHaveText(question.question);
    await expect(text).toHaveAttribute('aria-live','polite');
    await expect(composer).toBeEnabled();
    await page.evaluate(()=>{
      window.questionTextMutations=[];
      const text=document.getElementById('question-text');
      window.questionTextObserver=new MutationObserver(records=>{
        window.questionTextMutations.push(...records.map(record=>({type:record.type,text:text.textContent})));
      });
      window.questionTextObserver.observe(text,{childList:true,characterData:true,subtree:true});
    });
    await composer.fill('Preserve this partially selected answer.');
    await composer.evaluate(node=>{node.focus();node.setSelectionRange(9,23,'backward');});
    await nextPoll();await nextPoll();
    await expect(composer).toBeFocused();
    await expect(composer).toHaveValue('Preserve this partially selected answer.');
    expect(await composer.evaluate(node=>[node.selectionStart,node.selectionEnd,node.selectionDirection]))
      .toEqual([9,23,'backward']);
    expect(await page.evaluate(()=>window.questionTextMutations)).toEqual([]);

    const other=page.locator('#reply-attach');await other.focus();await expect(other).toBeFocused();
    await nextPoll();await expect(other).toBeFocused();
    expect(await composer.evaluate(node=>[node.selectionStart,node.selectionEnd])).toEqual([9,23]);
    expect(await page.evaluate(()=>window.questionTextMutations)).toEqual([]);

    // A new ID is announced once without taking focus. Clear the draft explicitly
    // so the separate changed-question draft-review guard does not defer it.
    await composer.fill('');await other.focus();
    question={id:702,version:'question-two',question:'Which reporting period should be used?'};
    await nextPoll();await expect(text).toHaveText(question.question);await expect(other).toBeFocused();
    expect(await page.evaluate(()=>window.questionTextMutations)).toEqual([
      {type:'childList',text:question.question},
    ]);
    await nextPoll();await expect(other).toBeFocused();
    expect(await page.evaluate(()=>window.questionTextMutations)).toHaveLength(1);
    expect(errors).toEqual([]);
    await info.attach('question-poll-observations',{body:JSON.stringify({
      mutations:await page.evaluate(()=>window.questionTextMutations),
      finalFocus:await page.evaluate(()=>document.activeElement.id),
    }),contentType:'application/json'});
  } finally {
    await page.evaluate(()=>window.questionTextObserver?.disconnect()).catch(()=>{});
    await context.unrouteAll({behavior:'ignoreErrors'});
  }
});
