const {defineConfig}=require('@playwright/test');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
// On Windows use a workspace-owned temporary root. Some managed user TEMP
// directories prevent Chromium cache cleanup even after the browser exits.
if(process.platform==='win32'){
  const temporary=process.env.LIGHTWORK_BROWSER_TEMP||path.resolve(__dirname,'../../../..','.browser-runtime');
  fs.mkdirSync(temporary,{recursive:true});
  process.env.TEMP=temporary;process.env.TMP=temporary;
}
// The desktop OAuth return profile deliberately accepts the installed dashboard
// origin only. Keep the default browser gate on that real origin; callers that
// override the port are running the non-native browser journeys only.
const port=Number(process.env.LIGHTWORK_BROWSER_PORT||8765);
const pythonExecutable=require('./python-runtime');
const pythonCommand=JSON.stringify(pythonExecutable);
// Capture this test-only opt-in before the server clears LIGHTWORK_* variables.
const showVendorSetup=process.env.LIGHTWORK_BROWSER_SHOW_VENDOR_SETUP==='1'?' --show-vendor-setup':'';
// A journey with its own <journey>.config.js needs that config's fixture
// server; `npm test` (run-journeys.js) runs it there instead of here.
const ownServer=fs.readdirSync(__dirname).filter(name=>name.endsWith('.config.js')&&name!=='playwright.config.js')
  .map(name=>name.replace(/\.config\.js$/,'.spec.js'));
// The expanded suite includes fresh owner, recovery and enterprise lifecycle
// journeys (about 194 tests, 30 to 40 minutes on a hosted runner). Allow the
// complete one-worker qualification run to finish; keep
// each test and assertion deadline unchanged so hangs remain failures.
module.exports=defineConfig({
  testDir:'.',testMatch:'*.spec.js',testIgnore:ownServer,fullyParallel:false,forbidOnly:!!process.env.CI,workers:1,retries:0,globalTimeout:2700000,
  outputDir:process.env.LIGHTWORK_BROWSER_OUTPUT||path.join(os.tmpdir(),'lightwork-browser-results'),
  timeout:45000,expect:{timeout:10000},
  reporter:[['list'],['html',{outputFolder:'browser-report',open:'never'}],['json',{outputFile:'test-results/results.json'}]],
  use:{baseURL:`http://127.0.0.1:${port}`,extraHTTPHeaders:{Origin:`http://127.0.0.1:${port}`},browserName:'chromium',headless:true,trace:'retain-on-failure',screenshot:'only-on-failure'},
  // SIGTERM lets the fixture server delete its temporary home; SIGKILL follows only if it is still running after 10s.
  webServer:{command:`${pythonCommand} server.py --port ${port}${showVendorSetup}`,url:`http://127.0.0.1:${port}/livez`,reuseExistingServer:false,timeout:120000,gracefulShutdown:{signal:'SIGTERM',timeout:10000}},
});
