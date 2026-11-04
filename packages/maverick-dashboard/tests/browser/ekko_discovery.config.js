const {defineConfig}=require('@playwright/test'),path=require('node:path');
const python=require('./python-runtime'),port=Number(process.env.LIGHTWORK_BROWSER_PORT||8893);
module.exports=defineConfig({testDir:'.',testMatch:'ekko_discovery.spec.js',workers:1,retries:0,
  timeout:90000,expect:{timeout:15000},reporter:[['list']],
  outputDir:path.resolve(__dirname,'../../../..','.browser-results-ekko-discovery'),
  use:{baseURL:`http://127.0.0.1:${port}`,extraHTTPHeaders:{Origin:`http://127.0.0.1:${port}`},
    browserName:'chromium',headless:true,trace:'retain-on-failure',screenshot:'only-on-failure'},
  // Reuse the isolated native Ekko store and authenticated dashboard fixture.
  webServer:{command:`${JSON.stringify(python)} intent_value_server.py --port ${port}`,
    url:`http://127.0.0.1:${port}/livez`,reuseExistingServer:false,timeout:120000,
    gracefulShutdown:{signal:'SIGTERM',timeout:10000}}});
