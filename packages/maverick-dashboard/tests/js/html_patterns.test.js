const assert=require('node:assert/strict');
const {test}=require('node:test');
const fs=require('node:fs'),path=require('node:path');
const {parse}=require('parse5');
const templates=path.resolve(__dirname,'../../maverick_dashboard/templates');

test('HTML input patterns compile with the Unicode sets flag used by current browsers',()=>{
  const failures=[];
  let checked=0;
  for(const name of fs.readdirSync(templates).filter(name=>name.endsWith('.html'))){
    // Parse HTML without evaluating Jinja CSS or executing template scripts.
    const nodes=[parse(fs.readFileSync(path.join(templates,name),'utf8'))];
    while(nodes.length){
      const node=nodes.pop();
      nodes.push(...(node.childNodes||[]));
      if(node.content)nodes.push(node.content);
      if(node.tagName==='input'){
        const pattern=node.attrs.find(attribute=>attribute.name==='pattern')?.value;
        if(pattern===undefined||pattern.includes('{{')||pattern.includes('{%'))continue;
        checked++;
        try{new RegExp(pattern,'v');}catch(error){failures.push(`${name}: ${pattern}: ${error.message}`);}
      }
    }
  }
  assert.ok(checked>0,'must review real input patterns');
  assert.deepEqual(failures,[],'an invalid pattern silently disables browser field validation');
});
