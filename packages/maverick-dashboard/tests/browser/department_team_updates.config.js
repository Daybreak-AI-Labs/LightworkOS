const {defineConfig}=require('@playwright/test'),path=require('node:path');
const python=require('./python-runtime'),port=Number(process.env.LIGHTWORK_BROWSER_PORT||8898);
module.exports=defineConfig({testDir:'.',testMatch:'department_team_updates.spec.js',workers:1,retries:0,timeout:90000,
 outputDir:path.resolve(__dirname,'../../../..','.browser-department-team-results'),reporter:[['list']],
 use:{baseURL:`http://127.0.0.1:${port}`,extraHTTPHeaders:{Origin:`http://127.0.0.1:${port}`},browserName:'chromium',headless:true,actionTimeout:15000,screenshot:'only-on-failure',trace:'retain-on-failure'},
 webServer:{command:`${JSON.stringify(python)} department_team_updates_server.py --port ${port}`,url:`http://127.0.0.1:${port}/livez`,reuseExistingServer:false,timeout:120000,gracefulShutdown:{signal:'SIGTERM',timeout:10000}}});
