const {defineConfig}=require('@playwright/test'),path=require('node:path');
const python=require('./python-runtime'),port=Number(process.env.LIGHTWORK_BROWSER_PORT||8894);
module.exports=defineConfig({testDir:'.',testMatch:'consent_job_creation.spec.js',workers:1,retries:0,timeout:120000,
 outputDir:path.resolve(__dirname,'../../../..','.browser-consent-creation-results'),reporter:[['list']],
 use:{baseURL:`http://127.0.0.1:${port}`,extraHTTPHeaders:{Origin:`http://127.0.0.1:${port}`},browserName:'chromium',headless:true,actionTimeout:15000,screenshot:'only-on-failure',trace:'retain-on-failure'},
 webServer:{command:`${JSON.stringify(python)} consent_job_creation_server.py --port ${port}`,url:`http://127.0.0.1:${port}/livez`,reuseExistingServer:false,timeout:120000,gracefulShutdown:{signal:'SIGTERM',timeout:10000}}});
