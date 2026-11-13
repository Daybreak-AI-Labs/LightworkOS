# Connectors

Lightwork ships connectors to the systems enterprises actually run on. Every
connector follows governed execution rules. The catalog contains implementation
adapters; a listing does not certify a customer's provider configuration or every
endpoint/version of the upstream service.

- **Scoped credentials.** Generic REST/GraphQL adapters resolve saved connections
  or documented environment variables. Authenticated enterprise requests require
  a saved connection authorized for that principal; they do not borrow the
  operator's process credentials. Dedicated integrations may have their own
  documented authentication modes.
- **External changes require a person.** A connector change is presented in
  Approvals with every request field and non-secret value, plus a digest binding
  the exact request. It is sent once after a fresh decision and a durable
  preparation record. The agent's own `confirm=true` cannot approve it.
  SQL beyond a constant `SELECT 1` check also takes this path because a query
  can invoke effects that a generic SQL parser cannot prove safe.
- **Fail closed, fail loud.** Missing config or an API error returns an
  `ERROR:`-prefixed message. A completed HTTP request alone does not establish a
  completed business operation.

For the generic REST/GraphQL factories, small successful responses retain the
legacy JSON body. Set `response_format="metadata"` to receive `status_code`,
`body`, `truncated`, and the allowlisted `etag`, `last-modified`, and `retry-after`
headers. For PUT/PATCH/DELETE, pass the current remote ETag as `if_match` when
available. If you omit it, Lightwork cannot verify whether the service offers
an ETag. A signed-in reviewer can approve the exact request after an explicit
warning that newer remote work could be overwritten. A direct connector call
without an ETag or this fresh approval is refused. Review the current record
again after a conflict.

HTTP 202 returns `pending=true`; obtain a later result before claiming completion.
Redirects and conditional 3xx responses are refused. Responses exceeding the
4,000-character envelope become valid JSON with `truncated=true` and a partial
`preview`. Request smaller pages and follow the provider's pagination contract;
the generic adapter does not aggregate an entire collection automatically.
Malformed `body`, `params`, or GraphQL `variables` objects are refused before the
request. These rules are tested with synthetic upstream responses; live
qualification requires the customer's endpoint, scopes, revisions and readback.

There are **2,877 write-capable long-tail enterprise connectors** in the
catalog below, plus dedicated-module connectors (Salesforce, HubSpot, Stripe,
ServiceNow, Snowflake, Notion, Gmail, Microsoft Graph (Outlook/Teams/
OneDrive), Google Drive, Jira, Confluence, ...), part of the **built-in tool
modules** in the kernel. They span nearly every category of enterprise and
SMB software: ITSM/ESM, CRM & sales, ERP & finance, HCM & payroll,
observability & APM, security/IAM/GRC, cloud & infra, DevOps/CI/CD, data/BI/
ETL/CMS, collaboration & content, marketing/commerce/CX, contact center,
e-commerce & payments, healthcare, real estate, legal, insurance,
manufacturing & supply chain, education, nonprofit & government, hospitality
& fitness, media & creative, telecom & messaging, no-code/AI platforms,
fintech & crypto, and region-specific SaaS (EU/UK, India, Japan, China,
LatAm, MENA, Africa, SE Asia).

Automation/iPaaS platforms are first-class: **Zapier**, **n8n**, **Microsoft
Power Automate**, **Make (Integromat)**, and **Workato** all have their own
connector for driving the platform's REST API directly (list/run/activate
workflows), on top of the automation-import pipeline (`maverick.automation_import`)
that turns an *existing* Zap/n8n workflow/Flow/Make scenario/Workato recipe
definition into a runnable Lightwork template — see the Workflow Builder's
"Import" flow in the dashboard.

Alongside these write-capable systems, the kernel ships **37 read-only
primary-source / public-data connectors** (SEC EDGAR, FRED, Treasury, World
Bank, FDIC, Census, BLS, EIA, openFDA, NPPES, ClinicalTrials, USAspending,
SAM.gov, CourtListener, Federal Register, GLEIF, OpenCorporates, NWS/NOAA
weather, EPA, Climatiq, ...) — GET-only, low-risk, and auto-granted to analyst
packs by suite (see **Primary-source data grounding** below).

## Connect from Lightwork

Open **Connections** from Integrations. Search for the service by its business
name. The catalog describes the authentication method and prerequisites; being
listed is not evidence of live provider qualification.

For an approved renewable account, choose **Connect an account**, choose the
profile, and review its fixed permissions before signing in with the provider.
An administrator registers the provider application once. When **Let employees
connect their own approved accounts** is enabled in Settings, employees with
operate permission can connect their own approved profiles. The account stays
owner-only; sharing and application registration need an administrator. If an
application is missing, ask the installation administrator to register it in
Connections; this external provider prerequisite cannot be bypassed.

For a service using a key, an administrator chooses the service, gives the
connection a distinct name, enters the API service address supplied by that
service, and saves the key in the protected field. Basic authentication adapters
need the provider's username/API-key format. Services marked **dedicated setup**
have additional prerequisites; the simple key form cannot complete them. Do not
substitute another adapter or a connection name for its tool binding.

**Credential saved** confirms storage only. **Check service access** performs a
harmless GET and records exactly when, on which credential revision, and with
what result authentication was checked. A public service address may be reachable
without proving authentication. Exact folder, storage or ticket permissions need
the corresponding source or workflow check. Privacy sources link to **Privacy
scanning** for that check. No connection check authorizes a business write.

Choose **Change** on the saved row to edit its metadata. A blank key preserves the
saved credential (including its AWS region); enter all AWS credential fields only
when rotating it. A conflict retains your draft without its secret and requires
a fresh review of the current record. **Remove** deletes the local sealed record;
it does not revoke consent at the provider. Review connected apps in the provider's
account settings separately. An unavailable list disables changes; refresh it
before creating a replacement so an outage does not produce duplicate setup.

### Operator reference

The installer can collect connector prerequisites during advanced setup. Legacy
single-user installations may use the documented environment-variable names in
the catalog below. Authenticated enterprise work still requires the current
principal's saved connection; operator credentials do not grant employee access.
Normal customer setup and credential editing take place in Connections.

## Primary-source data grounding

Separately from the write-capable catalog above, the kernel ships **37
read-only primary-source / public-data connectors** (SEC EDGAR, FRED,
Treasury, World Bank, FDIC, Census, BLS, EIA, openFDA, NPPES, ClinicalTrials,
USAspending, SAM.gov, CourtListener, Federal Register, GLEIF, OpenCorporates,
NWS/NOAA weather, EPA, Climatiq, ...). These are **GET-only, low-risk, and
deferred** (no per-turn context cost).

Each analyst pack is **auto-granted its suite's primary-source connectors**
(`SUITE_DATA_CONNECTORS`, layered in `domain_capability`) so specialists ground
answers in authoritative public data instead of guessing. This is **ON by
default**. Kill-switch: set `[workforce] data_grounding = false` in
`config.toml`, or the env var `MAVERICK_WORKFORCE_DATA_GROUNDING=off`. The
installer wizard (`maverick init`) also has a step for it.


## Catalog

Generic connectors expose one tool per system: `op` (get/post/put/patch/delete),
an API `path`, optional `params`/`body`, and `confirm` for writes. Bespoke
connectors (ServiceNow, Snowflake, SAP, Salesforce, ...) add system-specific
operations.

<!--
  GENERATED TABLE -- do not hand-edit. Source of truth is
  connector_catalog() in packages/maverick-core/maverick/tools/enterprise_connectors.py.
  Regenerate after editing _SPECS/_GRAPHQL_SPECS/_BESPOKE_CATALOG with:

    python3 -c "
    from maverick.tools.enterprise_connectors import connector_catalog
    for e in connector_catalog():
        env = ', '.join(f'\`{n}\`' + ('' if s else ' *(url)*') for n, s in e['env'])
        print(f\"| {e['label']} | \`{e['name']}\` | {env} |\")
    "

  then splice the output between the header row and the "Variables marked"
  note below.
-->
| Connector | Tool name | Environment variables |
| --- | --- | --- |
| AbacusLaw (AbacusNext) legal practice management | `abacuslaw` | `ABACUSLAW_BASE_URL` *(url)*, `ABACUSLAW_TOKEN` |
| ABC Fitness (ABC Trainerize/Ignite) | `abc_fitness` | `ABC_FITNESS_BASE_URL` *(url)*, `ABC_FITNESS_TOKEN` |
| Abnormal Security | `abnormal_security` | `ABNORMAL_SECURITY_BASE_URL` *(url)*, `ABNORMAL_SECURITY_TOKEN` |
| AB Tasty REST API | `abtasty` | `ABTASTY_BASE_URL` *(url)*, `ABTASTY_TOKEN` |
| AbuseIPDB | `abuseipdb` | `ABUSEIPDB_BASE_URL` *(url)*, `ABUSEIPDB_TOKEN` |
| Acalog academic catalog management | `acalog` | `ACALOG_BASE_URL` *(url)*, `ACALOG_TOKEN` |
| Acast podcast hosting | `acast` | `ACAST_BASE_URL` *(url)*, `ACAST_TOKEN` |
| Accela Civic Platform | `accela` | `ACCELA_BASE_URL` *(url)*, `ACCELA_TOKEN` |
| Accelo | `accelo` | `ACCELO_BASE_URL` *(url)*, `ACCELO_TOKEN` |
| Achieve3000 literacy platform | `achieve3000` | `ACHIEVE3000_BASE_URL` *(url)*, `ACHIEVE3000_TOKEN` |
| Oracle Aconex construction collaboration | `aconex` | `ACONEX_BASE_URL` *(url)*, `ACONEX_TOKEN` |
| Acorns micro-investing | `acorns` | `ACORNS_BASE_URL` *(url)*, `ACORNS_TOKEN` |
| Acoustic Campaign REST API | `acoustic` | `ACOUSTIC_BASE_URL` *(url)*, `ACOUSTIC_TOKEN` |
| Acquia Cloud Platform REST API | `acquia` | `ACQUIA_BASE_URL` *(url)*, `ACQUIA_TOKEN` |
| Acquire.io chatbot/live-chat REST API | `acquire_io` | `ACQUIRE_IO_BASE_URL` *(url)*, `ACQUIRE_IO_TOKEN` |
| Actionstep legal practice management | `actionstep` | `ACTIONSTEP_BASE_URL` *(url)*, `ACTIONSTEP_TOKEN` |
| Active Network | `active_network` | `ACTIVE_NETWORK_BASE_URL` *(url)*, `ACTIVE_NETWORK_TOKEN` |
| ActiveCampaign CRM/marketing | `activecampaign` | `ACTIVECAMPAIGN_BASE_URL` *(url)*, `ACTIVECAMPAIGN_TOKEN` |
| Acuity Scheduling | `acuity_scheduling` | `ACUITY_SCHEDULING_BASE_URL` *(url)*, `ACUITY_SCHEDULING_TOKEN` |
| Acumatica | `acumatica` | `ACUMATICA_BASE_URL` *(url)*, `ACUMATICA_TOKEN` |
| Acunetix Premium | `acunetix` | `ACUNETIX_BASE_URL` *(url)*, `ACUNETIX_TOKEN` |
| Ad Astra academic scheduling | `ad_astra` | `AD_ASTRA_BASE_URL` *(url)*, `AD_ASTRA_TOKEN` |
| Ada support chatbot | `ada` | `ADA_BASE_URL` *(url)*, `ADA_TOKEN` |
| Adalo Collections | `adalo` | `ADALO_BASE_URL` *(url)*, `ADALO_TOKEN` |
| Workday Adaptive Planning (Adaptive Insights) | `adaptive_insights` | `ADAPTIVE_INSIGHTS_BASE_URL` *(url)*, `ADAPTIVE_INSIGHTS_TOKEN` |
| Aderant legal practice/billing management | `aderant` | `ADERANT_BASE_URL` *(url)*, `ADERANT_TOKEN` |
| Adjust REST API | `adjust` | `ADJUST_BASE_URL` *(url)*, `ADJUST_TOKEN` |
| Adobe Analytics 2.0 | `adobe_analytics` | `ADOBE_ANALYTICS_BASE_URL` *(url)*, `ADOBE_ANALYTICS_TOKEN` |
| Adobe Express creative design | `adobe_express` | `ADOBE_EXPRESS_BASE_URL` *(url)*, `ADOBE_EXPRESS_TOKEN` |
| Adobe Lightroom photo editing | `adobe_lightroom` | `ADOBE_LIGHTROOM_BASE_URL` *(url)*, `ADOBE_LIGHTROOM_TOKEN` |
| Adobe Acrobat Sign e-signature | `adobe_sign` | `ADOBE_SIGN_BASE_URL` *(url)*, `ADOBE_SIGN_TOKEN` |
| Adobe Stock media | `adobe_stock` | `ADOBE_STOCK_BASE_URL` *(url)*, `ADOBE_STOCK_TOKEN` |
| ADP Workforce Now | `adp` | `ADP_BASE_URL` *(url)*, `ADP_TOKEN` |
| AdRoll REST API | `adroll` | `ADROLL_BASE_URL` *(url)*, `ADROLL_TOKEN` |
| AdvancedMD practice management/EHR REST API | `advancedmd` | `ADVANCEDMD_BASE_URL` *(url)*, `ADVANCEDMD_TOKEN` |
| Adverity data integration REST API | `adverity` | `ADVERITY_BASE_URL` *(url)*, `ADVERITY_TOKEN` |
| Adyen | `adyen` | `ADYEN_BASE_URL` *(url)*, `ADYEN_TOKEN` |
| Adobe Experience Manager | `aem` | `AEM_BASE_URL` *(url)*, `AEM_TOKEN` |
| Aeries SIS | `aeries` | `AERIES_BASE_URL` *(url)*, `AERIES_TOKEN` |
| AFAS Software ERP REST API (Netherlands) | `afas` | `AFAS_BASE_URL` *(url)*, `AFAS_TOKEN` |
| Affirm payments REST API | `affirm` | `AFFIRM_BASE_URL` *(url)*, `AFFIRM_TOKEN` |
| Africa's Talking SMS/voice REST API | `africastalking` | `AFRICASTALKING_BASE_URL` *(url)*, `AFRICASTALKING_TOKEN` |
| Afterpay/Clearpay Merchant REST API | `afterpay` | `AFTERPAY_BASE_URL` *(url)*, `AFTERPAY_TOKEN` |
| AfterShip tracking/returns REST API | `aftership` | `AFTERSHIP_BASE_URL` *(url)*, `AFTERSHIP_TOKEN` |
| Agile CRM | `agilecrm` | `AGILECRM_BASE_URL` *(url)*, `AGILECRM_TOKEN` |
| Agility CMS REST API | `agilitycms` | `AGILITYCMS_BASE_URL` *(url)*, `AGILITYCMS_TOKEN` |
| Agiloft contract lifecycle management | `agiloft` | `AGILOFT_BASE_URL` *(url)*, `AGILOFT_TOKEN` |
| Agora.io real-time video/voice | `agora_io` | `AGORA_IO_BASE_URL` *(url)*, `AGORA_IO_TOKEN` |
| Agorapulse REST API | `agorapulse` | `AGORAPULSE_BASE_URL` *(url)*, `AGORAPULSE_TOKEN` |
| Agworld farm-management REST API | `agworld` | `AGWORLD_BASE_URL` *(url)*, `AGWORLD_TOKEN` |
| Aha! roadmapping | `aha_io` | `AHA_IO_BASE_URL` *(url)*, `AHA_IO_TOKEN` |
| Ahrefs REST API | `ahrefs` | `AHREFS_BASE_URL` *(url)*, `AHREFS_TOKEN` |
| AI21 Labs REST API | `ai21_labs` | `AI21_LABS_BASE_URL` *(url)*, `AI21_LABS_TOKEN` |
| Airbase spend/AP | `airbase` | `AIRBASE_BASE_URL` *(url)*, `AIRBASE_TOKEN` |
| Airbase read-only spend management reporting REST (companion to airbase) | `airbase_read` | `AIRBASE_READ_BASE_URL` *(url)*, `AIRBASE_READ_TOKEN` |
| Airbrake error tracking REST API | `airbrake` | `AIRBRAKE_BASE_URL` *(url)*, `AIRBRAKE_TOKEN` |
| Airbyte REST API | `airbyte` | `AIRBYTE_BASE_URL` *(url)*, `AIRBYTE_TOKEN` |
| Airbyte Cloud REST API (data integration/EL(T)) | `airbyte_cloud` | `AIRBYTE_CLOUD_BASE_URL` *(url)*, `AIRBYTE_CLOUD_TOKEN` |
| Aircall | `aircall` | `AIRCALL_BASE_URL` *(url)*, `AIRCALL_TOKEN` |
| Apache Airflow | `airflow` | `AIRFLOW_BASE_URL` *(url)*, `AIRFLOW_TOKEN` |
| Airship (Urban Airship) REST API (push/engagement) | `airship` | `AIRSHIP_BASE_URL` *(url)*, `AIRSHIP_TOKEN` |
| Airwallex payments REST API | `airwallex` | `AIRWALLEX_BASE_URL` *(url)*, `AIRWALLEX_TOKEN` |
| Aisera AI service desk | `aisera` | `AISERA_BASE_URL` *(url)*, `AISERA_TOKEN` |
| Aiven Cloud Data Platform REST API | `aiven` | `AIVEN_BASE_URL` *(url)*, `AIVEN_TOKEN` |
| Aivo conversational AI chatbot REST API | `aivo_chatbot` | `AIVO_CHATBOT_BASE_URL` *(url)*, `AIVO_CHATBOT_TOKEN` |
| Akamai | `akamai` | `AKAMAI_BASE_URL` *(url)*, `AKAMAI_TOKEN` |
| Akeyless vaultless secrets REST API | `akeyless` | `AKEYLESS_BASE_URL` *(url)*, `AKEYLESS_TOKEN` |
| Akita customer success | `akita` | `AKITA_BASE_URL` *(url)*, `AKITA_TOKEN` |
| Akoya open-banking data | `akoya` | `AKOYA_BASE_URL` *(url)*, `AKOYA_TOKEN` |
| Alamy stock photo | `alamy` | `ALAMY_BASE_URL` *(url)*, `ALAMY_TOKEN` |
| Alchemer (formerly SurveyGizmo) | `alchemer` | `ALCHEMER_BASE_URL` *(url)*, `ALCHEMER_TOKEN` |
| Alegra accounting REST API (Latin America) | `alegra` | `ALEGRA_BASE_URL` *(url)*, `ALEGRA_TOKEN` |
| Alfresco content services | `alfresco` | `ALFRESCO_BASE_URL` *(url)*, `ALFRESCO_TOKEN` |
| Algolia search REST API | `algolia` | `ALGOLIA_BASE_URL` *(url)*, `ALGOLIA_TOKEN` |
| Algolia NeuralSearch REST API (vector-enhanced search) | `algolia_neuralsearch` | `ALGOLIA_NEURALSEARCH_BASE_URL` *(url)*, `ALGOLIA_NEURALSEARCH_TOKEN` |
| Alibaba.com Open Platform REST API | `alibaba` | `ALIBABA_BASE_URL` *(url)*, `ALIBABA_TOKEN` |
| Alibaba Cloud | `alibaba_cloud` | `ALIBABA_CLOUD_BASE_URL` *(url)*, `ALIBABA_CLOUD_TOKEN` |
| Alipay Open Platform REST API | `alipay` | `ALIPAY_BASE_URL` *(url)*, `ALIPAY_TOKEN` |
| Allegro marketplace REST API | `allegro` | `ALLEGRO_BASE_URL` *(url)*, `ALLEGRO_TOKEN` |
| Alloy identity/KYC decisioning | `alloy_kyc` | `ALLOY_KYC_BASE_URL` *(url)*, `ALLOY_KYC_TOKEN` |
| Ally Bank | `ally_bank` | `ALLY_BANK_BASE_URL` *(url)*, `ALLY_BANK_TOKEN` |
| Ally Invest brokerage | `ally_invest` | `ALLY_INVEST_BASE_URL` *(url)*, `ALLY_INVEST_TOKEN` |
| Almabase alumni/fundraising engagement | `almabase` | `ALMABASE_BASE_URL` *(url)*, `ALMABASE_TOKEN` |
| Almanac docs | `almanac_hq` | `ALMANAC_HQ_BASE_URL` *(url)*, `ALMANAC_HQ_TOKEN` |
| Alpaca brokerage/trading | `alpaca_markets` | `ALPACA_MARKETS_BASE_URL` *(url)*, `ALPACA_MARKETS_TOKEN` |
| Alteryx Server/Analytics Cloud REST API | `alteryx` | `ALTERYX_BASE_URL` *(url)*, `ALTERYX_TOKEN` |
| Alyne (Diligent) risk/GRC | `alyne_grc` | `ALYNE_GRC_BASE_URL` *(url)*, `ALYNE_GRC_TOKEN` |
| Amadeus for Developers travel REST API | `amadeus` | `AMADEUS_BASE_URL` *(url)*, `AMADEUS_TOKEN` |
| Amazon Connect contact center REST API | `amazon_connect` | `AMAZON_CONNECT_BASE_URL` *(url)*, `AMAZON_CONNECT_TOKEN` |
| Amazon Interactive Video Service (IVS) REST/AWS API | `amazon_ivs` | `AMAZON_IVS_BASE_URL` *(url)*, `AMAZON_IVS_TOKEN` |
| Amazon Lex V2 conversational bot runtime REST API | `amazon_lex` | `AMAZON_LEX_BASE_URL` *(url)*, `AMAZON_LEX_TOKEN` |
| Amazon Selling Partner API | `amazon_sp_api` | `AMAZON_SP_API_BASE_URL` *(url)*, `AMAZON_SP_API_TOKEN` |
| Amazon Advertising API | `amazonads` | `AMAZONADS_BASE_URL` *(url)*, `AMAZONADS_TOKEN` |
| Ameyo contact center | `ameyo` | `AMEYO_BASE_URL` *(url)*, `AMEYO_TOKEN` |
| Amicus Attorney legal practice management | `amicus_attorney` | `AMICUS_ATTORNEY_BASE_URL` *(url)*, `AMICUS_ATTORNEY_TOKEN` |
| Kommo (amoCRM) | `amocrm` | `AMOCRM_BASE_URL` *(url)*, `AMOCRM_TOKEN` |
| AmpliFund grants management | `amplifund` | `AMPLIFUND_BASE_URL` *(url)*, `AMPLIFUND_TOKEN` |
| Amplitude Analytics | `amplitude` | `AMPLITUDE_BASE_URL` *(url)*, `AMPLITUDE_TOKEN` |
| Anaconda.org REST API | `anaconda_cloud` | `ANACONDA_CLOUD_BASE_URL` *(url)*, `ANACONDA_CLOUD_TOKEN` |
| Anaplan | `anaplan` | `ANAPLAN_BASE_URL` *(url)*, `ANAPLAN_TOKEN` |
| Anchor (Spotify for Podcasters) | `anchor_fm` | `ANCHOR_FM_BASE_URL` *(url)*, `ANCHOR_FM_TOKEN` |
| Anchorage Digital custody | `anchorage_digital` | `ANCHORAGE_DIGITAL_BASE_URL` *(url)*, `ANCHORAGE_DIGITAL_TOKEN` |
| Anchore Enterprise | `anchore` | `ANCHORE_BASE_URL` *(url)*, `ANCHORE_TOKEN` |
| Anomali ThreatStream | `anomali` | `ANOMALI_BASE_URL` *(url)*, `ANOMALI_TOKEN` |
| Ansible Automation Platform (Tower/AWX) REST API | `ansible_tower` | `ANSIBLE_TOWER_BASE_URL` *(url)*, `ANSIBLE_TOWER_TOKEN` |
| Anthology Student (formerly Campus Management) | `anthology` | `ANTHOLOGY_BASE_URL` *(url)*, `ANTHOLOGY_TOKEN` |
| Anthropic Messages REST API | `anthropic_api` | `ANTHROPIC_API_BASE_URL` *(url)*, `ANTHROPIC_API_TOKEN` |
| Anvil (anvil.works) REST/App Server API | `anvil_works` | `ANVIL_WORKS_BASE_URL` *(url)*, `ANVIL_WORKS_TOKEN` |
| AnyDesk for Business | `anydesk` | `ANYDESK_BASE_URL` *(url)*, `ANYDESK_TOKEN` |
| Anyscale Endpoints REST API | `anyscale_endpoints` | `ANYSCALE_ENDPOINTS_BASE_URL` *(url)*, `ANYSCALE_ENDPOINTS_TOKEN` |
| Apache Hop orchestration REST API | `apache_hop` | `APACHE_HOP_BASE_URL` *(url)*, `APACHE_HOP_TOKEN` |
| Apex Clearing brokerage-as-a-service | `apex_clearing` | `APEX_CLEARING_BASE_URL` *(url)*, `APEX_CLEARING_TOKEN` |
| APITable REST API (Airtable-like spreadsheet database) | `apitable` | `APITABLE_BASE_URL` *(url)*, `APITABLE_TOKEN` |
| api.video REST API for video hosting | `apivideo` | `APIVIDEO_BASE_URL` *(url)*, `APIVIDEO_TOKEN` |
| Aplos nonprofit accounting | `aplos` | `APLOS_BASE_URL` *(url)*, `APLOS_TOKEN` |
| Apollo.io | `apollo` | `APOLLO_BASE_URL` *(url)*, `APOLLO_TOKEN` |
| AppDynamics | `appdynamics` | `APPDYNAMICS_BASE_URL` *(url)*, `APPDYNAMICS_TOKEN` |
| AppFolio Property Manager Report/Data REST API | `appfolio` | `APPFOLIO_BASE_URL` *(url)*, `APPFOLIO_TOKEN` |
| SAP AppGyver REST API (no-code app builder) | `appgyver` | `APPGYVER_BASE_URL` *(url)*, `APPGYVER_TOKEN` |
| Appian REST (Integration / Records API) | `appian` | `APPIAN_BASE_URL` *(url)*, `APPIAN_TOKEN` |
| Applied Epic insurance-agency-management REST API | `applied_epic` | `APPLIED_EPIC_BASE_URL` *(url)*, `APPLIED_EPIC_TOKEN` |
| Applitools Eyes REST API | `applitools` | `APPLITOOLS_BASE_URL` *(url)*, `APPLITOOLS_TOKEN` |
| Appointlet scheduling | `appointlet` | `APPOINTLET_BASE_URL` *(url)*, `APPOINTLET_TOKEN` |
| AppointmentPlus | `appointmentplus` | `APPOINTMENTPLUS_BASE_URL` *(url)*, `APPOINTMENTPLUS_TOKEN` |
| Appointy scheduling | `appointy` | `APPOINTY_BASE_URL` *(url)*, `APPOINTY_TOKEN` |
| ApproveMe (WordPress e-signature) | `approveme` | `APPROVEME_BASE_URL` *(url)*, `APPROVEME_TOKEN` |
| AppsFlyer REST API | `appsflyer` | `APPSFLYER_BASE_URL` *(url)*, `APPSFLYER_TOKEN` |
| Google AppSheet REST API | `appsheet` | `APPSHEET_BASE_URL` *(url)*, `APPSHEET_TOKEN` |
| Apptivo CRM | `apptivo` | `APPTIVO_BASE_URL` *(url)*, `APPTIVO_TOKEN` |
| AppVeyor REST API | `appveyor` | `APPVEYOR_BASE_URL` *(url)*, `APPVEYOR_TOKEN` |
| Aqua Security (CSPM/scanning) REST API | `aqua_security` | `AQUA_SECURITY_BASE_URL` *(url)*, `AQUA_SECURITY_TOKEN` |
| Aras Innovator PLM | `aras_innovator` | `ARAS_INNOVATOR_BASE_URL` *(url)*, `ARAS_INNOVATOR_TOKEN` |
| ArbiterSports | `arbiter_sports` | `ARBITER_SPORTS_BASE_URL` *(url)*, `ARBITER_SPORTS_TOKEN` |
| Archdesk construction management platform | `archdesk` | `ARCHDESK_BASE_URL` *(url)*, `ARCHDESK_TOKEN` |
| RSA Archer GRC | `archer` | `ARCHER_BASE_URL` *(url)*, `ARCHER_TOKEN` |
| RSA Archer GRC platform | `archer_grc` | `ARCHER_GRC_BASE_URL` *(url)*, `ARCHER_GRC_TOKEN` |
| ArchiSnapper site visit/punch list reporting | `archisnapper` | `ARCHISNAPPER_BASE_URL` *(url)*, `ARCHISNAPPER_TOKEN` |
| Arctic Wolf Platform | `arctic_wolf` | `ARCTIC_WOLF_BASE_URL` *(url)*, `ARCTIC_WOLF_TOKEN` |
| PTC Arena PLM | `arena_plm` | `ARENA_PLM_BASE_URL` *(url)*, `ARENA_PLM_TOKEN` |
| Argo CD | `argocd` | `ARGOCD_BASE_URL` *(url)*, `ARGOCD_TOKEN` |
| SAP Ariba | `ariba` | `ARIBA_BASE_URL` *(url)*, `ARIBA_TOKEN` |
| Arkieva supply-chain planning | `arkieva` | `ARKIEVA_BASE_URL` *(url)*, `ARKIEVA_TOKEN` |
| Artgrid stock footage | `artgrid` | `ARTGRID_BASE_URL` *(url)*, `ARTGRID_TOKEN` |
| Artlist music/footage licensing | `artlist` | `ARTLIST_BASE_URL` *(url)*, `ARTLIST_TOKEN` |
| Ascent RegTech regulatory compliance | `ascent_regtech` | `ASCENT_REGTECH_BASE_URL` *(url)*, `ASCENT_REGTECH_TOKEN` |
| Ashby recruiting/ATS | `ashby` | `ASHBY_BASE_URL` *(url)*, `ASHBY_TOKEN` |
| Aspiration banking | `aspiration` | `ASPIRATION_BASE_URL` *(url)*, `ASPIRATION_TOKEN` |
| Assembled contact-center workforce management | `assembled` | `ASSEMBLED_BASE_URL` *(url)*, `ASSEMBLED_TOKEN` |
| AssemblyAI REST API | `assemblyai` | `ASSEMBLYAI_BASE_URL` *(url)*, `ASSEMBLYAI_TOKEN` |
| Assignar construction workforce/asset management | `assignar` | `ASSIGNAR_BASE_URL` *(url)*, `ASSIGNAR_TOKEN` |
| AssurX quality/compliance management | `assurx` | `ASSURX_BASE_URL` *(url)*, `ASSURX_TOKEN` |
| Astea Alliance field service management | `astea_alliance` | `ASTEA_ALLIANCE_BASE_URL` *(url)*, `ASTEA_ALLIANCE_TOKEN` |
| At-Bay cyber insurance | `at_bay` | `AT_BAY_BASE_URL` *(url)*, `AT_BAY_TOKEN` |
| athenahealth athenaOne REST API for practice/EHR data | `athenahealth` | `ATHENAHEALTH_BASE_URL` *(url)*, `ATHENAHEALTH_TOKEN` |
| John Galt Solutions Atlas Planning Platform | `atlas_planning` | `ATLAS_PLANNING_BASE_URL` *(url)*, `ATLAS_PLANNING_TOKEN` |
| AttackIQ Security Optimization Platform | `attackiq` | `ATTACKIQ_BASE_URL` *(url)*, `ATTACKIQ_TOKEN` |
| Attentive REST API (SMS/email marketing) | `attentive` | `ATTENTIVE_BASE_URL` *(url)*, `ATTENTIVE_TOKEN` |
| ATTOM Data property data | `attom` | `ATTOM_BASE_URL` *(url)*, `ATTOM_TOKEN` |
| Attune commercial insurance platform | `attune_insurance` | `ATTUNE_INSURANCE_BASE_URL` *(url)*, `ATTUNE_INSURANCE_TOKEN` |
| Auctria auction management | `auctria` | `AUCTRIA_BASE_URL` *(url)*, `AUCTRIA_TOKEN` |
| Audioboom podcast hosting | `audioboom` | `AUDIOBOOM_BASE_URL` *(url)*, `AUDIOBOOM_TOKEN` |
| Audiomack REST API | `audiomack` | `AUDIOMACK_BASE_URL` *(url)*, `AUDIOMACK_TOKEN` |
| AuditBoard GRC | `auditboard` | `AUDITBOARD_BASE_URL` *(url)*, `AUDITBOARD_TOKEN` |
| Augury machine health monitoring | `augury` | `AUGURY_BASE_URL` *(url)*, `AUGURY_TOKEN` |
| Auth0 Management | `auth0` | `AUTH0_BASE_URL` *(url)*, `AUTH0_TOKEN` |
| Authorize.Net Payments REST/XML API | `authorize_net` | `AUTHORIZE_NET_BASE_URL` *(url)*, `AUTHORIZE_NET_TOKEN` |
| Autodesk Construction Cloud (BIM 360) | `autodesk_construction` | `AUTODESK_CONSTRUCTION_BASE_URL` *(url)*, `AUTODESK_CONSTRUCTION_TOKEN` |
| Autoklose sales engagement | `autoklose` | `AUTOKLOSE_BASE_URL` *(url)*, `AUTOKLOSE_TOKEN` |
| Avail (Realtor.com) landlord/property management | `avail` | `AVAIL_BASE_URL` *(url)*, `AVAIL_TOKEN` |
| Avalara AvaTax REST (sales/use tax) | `avalara` | `AVALARA_BASE_URL` *(url)*, `AVALARA_TOKEN` |
| Avant consumer credit | `avant_credit` | `AVANT_CREDIT_BASE_URL` *(url)*, `AVANT_CREDIT_TOKEN` |
| Avaya OneCloud/Aura REST API | `avaya` | `AVAYA_BASE_URL` *(url)*, `AVAYA_TOKEN` |
| Avaza | `avaza` | `AVAZA_BASE_URL` *(url)*, `AVAZA_TOKEN` |
| AVEVA (Wonderware) industrial/energy REST API | `aveva` | `AVEVA_BASE_URL` *(url)*, `AVEVA_TOKEN` |
| Aviso revenue intelligence/forecasting | `aviso` | `AVISO_BASE_URL` *(url)*, `AVISO_TOKEN` |
| Avoma meeting/revenue intelligence | `avoma` | `AVOMA_BASE_URL` *(url)*, `AVOMA_TOKEN` |
| AWeber REST API | `aweber` | `AWEBER_BASE_URL` *(url)*, `AWEBER_TOKEN` |
| Awin REST API (affiliate marketing) | `awin` | `AWIN_BASE_URL` *(url)*, `AWIN_TOKEN` |
| awork project management REST API (Germany) | `awork` | `AWORK_BASE_URL` *(url)*, `AWORK_TOKEN` |
| AWS SageMaker Runtime REST API (model inference) | `aws_sagemaker` | `AWS_SAGEMAKER_BASE_URL` *(url)*, `AWS_SAGEMAKER_TOKEN` |
| Axonaut CRM/invoicing REST API (France) | `axonaut` | `AXONAUT_BASE_URL` *(url)*, `AXONAUT_TOKEN` |
| Axonius Cyber Asset Management | `axonius` | `AXONIUS_BASE_URL` *(url)*, `AXONIUS_TOKEN` |
| Azimo remittance | `azimo` | `AZIMO_BASE_URL` *(url)*, `AZIMO_TOKEN` |
| Microsoft Azure Resource Manager | `azure` | `AZURE_BASE_URL` *(url)*, `AZURE_TOKEN` |
| Azure DevOps | `azure_devops` | `AZURE_DEVOPS_BASE_URL` *(url)*, `AZURE_DEVOPS_TOKEN` |
| Azure OpenAI Service REST API | `azure_openai` | `AZURE_OPENAI_BASE_URL` *(url)*, `AZURE_OPENAI_TOKEN` |
| B2W Software heavy construction operations | `b2w_software` | `B2W_SOFTWARE_BASE_URL` *(url)*, `B2W_SOFTWARE_TOKEN` |
| Back4App (Parse Platform hosting) REST API | `back4app` | `BACK4APP_BASE_URL` *(url)*, `BACK4APP_TOKEN` |
| Back Market marketplace REST API | `back_market` | `BACK_MARKET_BASE_URL` *(url)*, `BACK_MARKET_TOKEN` |
| Backblaze B2 Cloud Storage REST API | `backblaze` | `BACKBLAZE_BASE_URL` *(url)*, `BACKBLAZE_TOKEN` |
| Backendless REST API (no-code backend) | `backendless` | `BACKENDLESS_BASE_URL` *(url)*, `BACKENDLESS_TOKEN` |
| Baidu AI Cloud REST API (China) | `baidu` | `BAIDU_BASE_URL` *(url)*, `BAIDU_TOKEN` |
| Balto real-time call guidance | `balto` | `BALTO_BASE_URL` *(url)*, `BALTO_TOKEN` |
| Atlassian Bamboo REST API | `bamboo` | `BAMBOO_BASE_URL` *(url)*, `BAMBOO_TOKEN` |
| BambooHR | `bamboohr` | `BAMBOOHR_BASE_URL` *(url)*, `BAMBOOHR_TOKEN` |
| Banana.dev REST API (model inference) | `banana_dev` | `BANANA_DEV_BASE_URL` *(url)*, `BANANA_DEV_TOKEN` |
| Band (Naver) group | `band_app` | `BAND_APP_BASE_URL` *(url)*, `BAND_APP_TOKEN` |
| Bandwidth messaging/voice REST API | `bandwidth` | `BANDWIDTH_BASE_URL` *(url)*, `BANDWIDTH_TOKEN` |
| Banxa on/off-ramp | `banxa` | `BANXA_BASE_URL` *(url)*, `BANXA_TOKEN` |
| Baremetrics REST API | `baremetrics` | `BAREMETRICS_BASE_URL` *(url)*, `BAREMETRICS_TOKEN` |
| Barracuda Cloud Control | `barracuda` | `BARRACUDA_BASE_URL` *(url)*, `BARRACUDA_TOKEN` |
| Seagull Scientific BarTender label management | `bartender_label` | `BARTENDER_LABEL_BASE_URL` *(url)*, `BARTENDER_LABEL_TOKEN` |
| Basecamp | `basecamp` | `BASECAMP_BASE_URL` *(url)*, `BASECAMP_TOKEN` |
| Baserow | `baserow` | `BASEROW_BASE_URL` *(url)*, `BASEROW_TOKEN` |
| Baseten REST API (model deployment/inference) | `baseten` | `BASETEN_BASE_URL` *(url)*, `BASETEN_TOKEN` |
| Basiq open-banking | `basiq` | `BASIQ_BASE_URL` *(url)*, `BASIQ_TOKEN` |
| Batch.com push notification REST API | `batch_push` | `BATCH_PUSH_BASE_URL` *(url)*, `BATCH_PUSH_TOKEN` |
| Battlefy REST API (esports tournaments) | `battlefy` | `BATTLEFY_BASE_URL` *(url)*, `BATTLEFY_TOKEN` |
| Battle.net (Blizzard) REST API | `battlenet` | `BATTLENET_BASE_URL` *(url)*, `BATTLENET_TOKEN` |
| Bazaarvoice REST API | `bazaarvoice` | `BAZAARVOICE_BASE_URL` *(url)*, `BAZAARVOICE_TOKEN` |
| Bbot in-venue ordering | `bbot` | `BBOT_BASE_URL` *(url)*, `BBOT_TOKEN` |
| Beam Cloud REST API (serverless GPU/model deployment) | `beam_cloud` | `BEAM_CLOUD_BASE_URL` *(url)*, `BEAM_CLOUD_TOKEN` |
| Beamable game backend REST API | `beamable` | `BEAMABLE_BASE_URL` *(url)*, `BEAMABLE_TOKEN` |
| Bear notes X-callback/REST (via Bear API) | `bear_notes` | `BEAR_NOTES_BASE_URL` *(url)*, `BEAR_NOTES_TOKEN` |
| Beautiful.ai presentation design | `beautiful_ai` | `BEAUTIFUL_AI_BASE_URL` *(url)*, `BEAUTIFUL_AI_TOKEN` |
| Beekeeper employee comms | `beekeeper` | `BEEKEEPER_BASE_URL` *(url)*, `BEEKEEPER_TOKEN` |
| BeFunky photo editing/design | `befunky` | `BEFUNKY_BASE_URL` *(url)*, `BEFUNKY_TOKEN` |
| Behance REST API | `behance` | `BEHANCE_BASE_URL` *(url)*, `BEHANCE_TOKEN` |
| Benchmark Email REST API | `benchmarkemail` | `BENCHMARKEMAIL_BASE_URL` *(url)*, `BENCHMARKEMAIL_TOKEN` |
| Benefitfocus benefits administration | `benefitfocus` | `BENEFITFOCUS_BASE_URL` *(url)*, `BENEFITFOCUS_TOKEN` |
| Benevity corporate giving/volunteering | `benevity` | `BENEVITY_BASE_URL` *(url)*, `BENEVITY_TOKEN` |
| BentoBox restaurant site/ordering | `bentobox` | `BENTOBOX_BASE_URL` *(url)*, `BENTOBOX_TOKEN` |
| Better Impact volunteer management | `betterimpact` | `BETTERIMPACT_BASE_URL` *(url)*, `BETTERIMPACT_TOKEN` |
| Betterment robo-advisor | `betterment` | `BETTERMENT_BASE_URL` *(url)*, `BETTERMENT_TOKEN` |
| Better Proposals | `betterproposals` | `BETTERPROPOSALS_BASE_URL` *(url)*, `BETTERPROPOSALS_TOKEN` |
| Better Stack (Better Uptime) REST API | `betteruptime` | `BETTERUPTIME_BASE_URL` *(url)*, `BETTERUPTIME_TOKEN` |
| Betterview property risk intelligence (insurance) | `betterview` | `BETTERVIEW_BASE_URL` *(url)*, `BETTERVIEW_TOKEN` |
| Betterworks OKR/performance | `betterworks` | `BETTERWORKS_BASE_URL` *(url)*, `BETTERWORKS_TOKEN` |
| Betty Blocks | `betty_blocks` | `BETTY_BLOCKS_BASE_URL` *(url)*, `BETTY_BLOCKS_TOKEN` |
| BeyondTrust Password Safe/PRA | `beyondtrust` | `BEYONDTRUST_BASE_URL` *(url)*, `BEYONDTRUST_TOKEN` |
| BiddingOwl auction | `biddingowl` | `BIDDINGOWL_BASE_URL` *(url)*, `BIDDINGOWL_TOKEN` |
| Bidsketch proposal | `bidsketch` | `BIDSKETCH_BASE_URL` *(url)*, `BIDSKETCH_TOKEN` |
| Big Cartel REST API | `bigcartel` | `BIGCARTEL_BASE_URL` *(url)*, `BIGCARTEL_TOKEN` |
| BigChange (JobWatch) field service | `bigchange` | `BIGCHANGE_BASE_URL` *(url)*, `BIGCHANGE_TOKEN` |
| BigCommerce | `bigcommerce` | `BIGCOMMERCE_BASE_URL` *(url)*, `BIGCOMMERCE_TOKEN` |
| BigID Data Intelligence Platform | `bigid` | `BIGID_BASE_URL` *(url)*, `BIGID_TOKEN` |
| Google BigQuery | `bigquery` | `BIGQUERY_PROJECT` *(url)*, `BIGQUERY_ACCESS_TOKEN` |
| Bigstock (Bigstockphoto) stock media | `bigstockphoto` | `BIGSTOCKPHOTO_BASE_URL` *(url)*, `BIGSTOCKPHOTO_TOKEN` |
| Bill4Time legal time/billing | `bill4time` | `BILL4TIME_BASE_URL` *(url)*, `BILL4TIME_TOKEN` |
| BILL.com read-only reporting REST (companion to billdotcom) | `bill_com_read` | `BILL_COM_READ_BASE_URL` *(url)*, `BILL_COM_READ_TOKEN` |
| Billbee multichannel ecommerce REST API (Germany) | `billbee` | `BILLBEE_BASE_URL` *(url)*, `BILLBEE_TOKEN` |
| BillDesk payment gateway REST API (India) | `billdesk` | `BILLDESK_BASE_URL` *(url)*, `BILLDESK_TOKEN` |
| Bill.com | `billdotcom` | `BILLDOTCOM_BASE_URL` *(url)*, `BILLDOTCOM_TOKEN` |
| Billomat invoicing REST API (Germany, sevDesk group) | `billomat` | `BILLOMAT_BASE_URL` *(url)*, `BILLOMAT_TOKEN` |
| Billplz payment gateway REST API (Malaysia) | `billplz` | `BILLPLZ_BASE_URL` *(url)*, `BILLPLZ_TOKEN` |
| Billwerk+ subscription billing REST API | `billwerk` | `BILLWERK_BASE_URL` *(url)*, `BILLWERK_TOKEN` |
| Binance exchange | `binance` | `BINANCE_BASE_URL` *(url)*, `BINANCE_TOKEN` |
| Binance.US exchange | `binanceus` | `BINANCEUS_BASE_URL` *(url)*, `BINANCEUS_TOKEN` |
| Bindable insurance marketplace platform | `bindable` | `BINDABLE_BASE_URL` *(url)*, `BINDABLE_TOKEN` |
| Microsoft Advertising (Bing Ads) API | `bingads` | `BINGADS_BASE_URL` *(url)*, `BINGADS_TOKEN` |
| Birst (Infor) BI REST API | `birst` | `BIRST_BASE_URL` *(url)*, `BIRST_TOKEN` |
| Bitbucket | `bitbucket` | `BITBUCKET_ACCESS_TOKEN` |
| Bitdefender GravityZone REST/JSON-RPC | `bitdefender` | `BITDEFENDER_BASE_URL` *(url)*, `BITDEFENDER_TOKEN` |
| Bitfinex exchange | `bitfinex` | `BITFINEX_BASE_URL` *(url)*, `BITFINEX_TOKEN` |
| bitFlyer exchange | `bitflyer` | `BITFLYER_BASE_URL` *(url)*, `BITFLYER_TOKEN` |
| BitGo custody | `bitgo` | `BITGO_BASE_URL` *(url)*, `BITGO_TOKEN` |
| Bithumb exchange | `bithumb` | `BITHUMB_BASE_URL` *(url)*, `BITHUMB_TOKEN` |
| Bitpanda exchange | `bitpanda` | `BITPANDA_BASE_URL` *(url)*, `BITPANDA_TOKEN` |
| BitPay crypto payments | `bitpay` | `BITPAY_BASE_URL` *(url)*, `BITPAY_TOKEN` |
| Bitrix24 | `bitrix24` | `BITRIX24_BASE_URL` *(url)*, `BITRIX24_TOKEN` |
| BitSight Security Ratings | `bitsight` | `BITSIGHT_BASE_URL` *(url)*, `BITSIGHT_TOKEN` |
| Bitso exchange | `bitso` | `BITSO_BASE_URL` *(url)*, `BITSO_TOKEN` |
| Bitstamp exchange | `bitstamp` | `BITSTAMP_BASE_URL` *(url)*, `BITSTAMP_TOKEN` |
| Bitvavo exchange | `bitvavo` | `BITVAVO_BASE_URL` *(url)*, `BITVAVO_TOKEN` |
| Bitwarden Organization/Public API | `bitwarden` | `BITWARDEN_BASE_URL` *(url)*, `BITWARDEN_TOKEN` |
| BlaBlaCar carpooling partner REST API (France) | `blablacar` | `BLABLACAR_BASE_URL` *(url)*, `BLABLACAR_TOKEN` |
| Blackbaud Grantmaking (formerly MicroEdge GIFTS) | `blackbaud_grantmaking` | `BLACKBAUD_GRANTMAKING_BASE_URL` *(url)*, `BLACKBAUD_GRANTMAKING_TOKEN` |
| Blackbaud SIS (Education Management) | `blackbaud_sis` | `BLACKBAUD_SIS_BASE_URL` *(url)*, `BLACKBAUD_SIS_TOKEN` |
| Blackboard Learn REST API | `blackboard` | `BLACKBOARD_BASE_URL` *(url)*, `BLACKBOARD_TOKEN` |
| Black Duck (Synopsys) SCA REST API | `blackduck` | `BLACKDUCK_BASE_URL` *(url)*, `BLACKDUCK_TOKEN` |
| BlackLine REST (financial close) | `blackline` | `BLACKLINE_BASE_URL` *(url)*, `BLACKLINE_TOKEN` |
| Blameless incident-management REST API | `blameless` | `BLAMELESS_BASE_URL` *(url)*, `BLAMELESS_TOKEN` |
| Bling ERP REST API (Brazil) | `bling` | `BLING_BASE_URL` *(url)*, `BLING_TOKEN` |
| Blockchain.com wallet/exchange | `blockchain_com` | `BLOCKCHAIN_COM_BASE_URL` *(url)*, `BLOCKCHAIN_COM_TOKEN` |
| Blockchair blockchain explorer | `blockchair` | `BLOCKCHAIR_BASE_URL` *(url)*, `BLOCKCHAIR_TOKEN` |
| Bloomerang | `bloomerang` | `BLOOMERANG_BASE_URL` *(url)*, `BLOOMERANG_TOKEN` |
| Bloomreach Content/Discovery REST API | `bloomreach` | `BLOOMREACH_BASE_URL` *(url)*, `BLOOMREACH_TOKEN` |
| Bloomz school-family communication | `bloomz` | `BLOOMZ_BASE_URL` *(url)*, `BLOOMZ_TOKEN` |
| Blubrry podcast hosting | `blubrry` | `BLUBRRY_BASE_URL` *(url)*, `BLUBRRY_TOKEN` |
| Blue Yonder (JDA) supply-chain REST API | `blue_yonder` | `BLUE_YONDER_BASE_URL` *(url)*, `BLUE_YONDER_TOKEN` |
| Bluebeam construction document/markup | `bluebeam` | `BLUEBEAM_BASE_URL` *(url)*, `BLUEBEAM_TOKEN` |
| BlueConic REST API (CDP) | `blueconic` | `BLUECONIC_BASE_URL` *(url)*, `BLUECONIC_TOKEN` |
| Bluecore REST API | `bluecore` | `BLUECORE_BASE_URL` *(url)*, `BLUECORE_TOKEN` |
| BlueJeans Meetings | `bluejeans` | `BLUEJEANS_BASE_URL` *(url)*, `BLUEJEANS_TOKEN` |
| Bluesky AT Protocol XRPC REST API | `bluesky` | `BLUESKY_BASE_URL` *(url)*, `BLUESKY_TOKEN` |
| BlueSnap payments REST API | `bluesnap` | `BLUESNAP_BASE_URL` *(url)*, `BLUESNAP_TOKEN` |
| BlueVine business banking/lending | `bluevine` | `BLUEVINE_BASE_URL` *(url)*, `BLUEVINE_TOKEN` |
| BMC Helix / Remedy | `bmc_helix` | `BMC_HELIX_BASE_URL` *(url)*, `BMC_HELIX_TOKEN` |
| Board CPM/BI platform | `board_cpm` | `BOARD_CPM_BASE_URL` *(url)*, `BOARD_CPM_TOKEN` |
| Board International BI/CPM REST API | `boardintl` | `BOARDINTL_BASE_URL` *(url)*, `BOARDINTL_TOKEN` |
| Bold Commerce REST API | `bold_commerce` | `BOLD_COMMERCE_BASE_URL` *(url)*, `BOLD_COMMERCE_TOKEN` |
| Bold Penguin commercial insurance quoting | `boldpenguin` | `BOLDPENGUIN_BASE_URL` *(url)*, `BOLDPENGUIN_TOKEN` |
| BoldSign e-signature | `boldsign` | `BOLDSIGN_BASE_URL` *(url)*, `BOLDSIGN_TOKEN` |
| Bolt checkout/payments REST API | `bolt` | `BOLT_BASE_URL` *(url)*, `BOLT_TOKEN` |
| BombBomb video email | `bombbomb` | `BOMBBOMB_BASE_URL` *(url)*, `BOMBBOMB_TOKEN` |
| Bonfire public-sector procurement/sourcing | `bonfirehub` | `BONFIREHUB_BASE_URL` *(url)*, `BONFIREHUB_TOKEN` |
| Bonterra (Social Solutions/EveryAction case management) | `bonterra` | `BONTERRA_BASE_URL` *(url)*, `BONTERRA_TOKEN` |
| Bookeo | `bookeo` | `BOOKEO_BASE_URL` *(url)*, `BOOKEO_TOKEN` |
| Booker (Booker Software) appointment | `booker` | `BOOKER_BASE_URL` *(url)*, `BOOKER_TOKEN` |
| Booking.com Connectivity/XML-REST API for property inventory | `bookingcom` | `BOOKINGCOM_BASE_URL` *(url)*, `BOOKINGCOM_TOKEN` |
| Bookly (WordPress) scheduling | `bookly` | `BOOKLY_BASE_URL` *(url)*, `BOOKLY_TOKEN` |
| Booksy scheduling | `booksy` | `BOOKSY_BASE_URL` *(url)*, `BOOKSY_TOKEN` |
| Boomi AtomSphere | `boomi` | `BOOMI_BASE_URL` *(url)*, `BOOMI_TOKEN` |
| BoomTown real estate CRM | `boomtown` | `BOOMTOWN_BASE_URL` *(url)*, `BOOMTOWN_TOKEN` |
| BoostUp revenue intelligence | `boostup` | `BOOSTUP_BASE_URL` *(url)*, `BOOSTUP_TOKEN` |
| Botpress REST API (chatbot builder) | `botpress` | `BOTPRESS_BASE_URL` *(url)*, `BOTPRESS_TOKEN` |
| Botsify chatbot REST API | `botsify` | `BOTSIFY_BASE_URL` *(url)*, `BOTSIFY_TOKEN` |
| HashiCorp Boundary REST API | `boundary` | `BOUNDARY_BASE_URL` *(url)*, `BOUNDARY_TOKEN` |
| Box content | `box` | `BOX_BASE_URL` *(url)*, `BOX_TOKEN` |
| BQE Core professional services/AEC management | `bqe_core` | `BQE_CORE_BASE_URL` *(url)*, `BQE_CORE_TOKEN` |
| Braintree (PayPal) payments REST/GraphQL API | `braintree` | `BRAINTREE_BASE_URL` *(url)*, `BRAINTREE_TOKEN` |
| Braintree (PayPal) payments REST/GraphQL | `braintree_pay` | `BRAINTREE_PAY_BASE_URL` *(url)*, `BRAINTREE_PAY_TOKEN` |
| Braintrust REST API (LLM eval platform) | `braintrust_data` | `BRAINTRUST_DATA_BASE_URL` *(url)*, `BRAINTRUST_DATA_TOKEN` |
| Branch.io REST API (mobile attribution/deep linking) | `branchio` | `BRANCHIO_BASE_URL` *(url)*, `BRANCHIO_TOKEN` |
| Braze | `braze` | `BRAZE_BASE_URL` *(url)*, `BRAZE_TOKEN` |
| Breadcrumb POS | `breadcrumb_pos` | `BREADCRUMB_POS_BASE_URL` *(url)*, `BREADCRUMB_POS_TOKEN` |
| Breezy HR recruiting | `breezyhr` | `BREEZYHR_BASE_URL` *(url)*, `BREEZYHR_TOKEN` |
| Brevo (formerly Sendinblue) REST API | `brevo` | `BREVO_BASE_URL` *(url)*, `BREVO_TOKEN` |
| Brex REST (spend) | `brex` | `BREX_BASE_URL` *(url)*, `BREX_TOKEN` |
| Bridgit Bench construction workforce planning | `bridgit_bench` | `BRIDGIT_BENCH_BASE_URL` *(url)*, `BRIDGIT_BENCH_TOKEN` |
| Brightcove video cloud REST API | `brightcove` | `BRIGHTCOVE_BASE_URL` *(url)*, `BRIGHTCOVE_TOKEN` |
| Brightflag legal spend management | `brightflag` | `BRIGHTFLAG_BASE_URL` *(url)*, `BRIGHTFLAG_TOKEN` |
| Brightpearl retail-ops REST API | `brightpearl` | `BRIGHTPEARL_BASE_URL` *(url)*, `BRIGHTPEARL_TOKEN` |
| D2L Brightspace LMS REST API | `brightspace` | `BRIGHTSPACE_BASE_URL` *(url)*, `BRIGHTSPACE_TOKEN` |
| Bring (Posten Norge) logistics REST API (Norway) | `bring` | `BRING_BASE_URL` *(url)*, `BRING_TOKEN` |
| Brinqa Cyber Risk Platform | `brinqa` | `BRINQA_BASE_URL` *(url)*, `BRINQA_TOKEN` |
| Britive Cloud Privileged Access Management | `britive` | `BRITIVE_BASE_URL` *(url)*, `BRITIVE_TOKEN` |
| BrowserStack REST API | `browserstack` | `BROWSERSTACK_BASE_URL` *(url)*, `BROWSERSTACK_TOKEN` |
| bswift (Aon) benefits administration | `bswift` | `BSWIFT_BASE_URL` *(url)*, `BSWIFT_TOKEN` |
| BTCPay Server self-hosted crypto payments | `btcpay_server` | `BTCPAY_SERVER_BASE_URL` *(url)*, `BTCPAY_SERVER_TOKEN` |
| Bubble.io Data API | `bubble_io` | `BUBBLE_IO_BASE_URL` *(url)*, `BUBBLE_IO_TOKEN` |
| Buffer REST API (social media scheduling) | `buffer` | `BUFFER_BASE_URL` *(url)*, `BUFFER_TOKEN` |
| Bugsnag (SmartBear Insight Hub) REST API | `bugsnag` | `BUGSNAG_BASE_URL` *(url)*, `BUGSNAG_TOKEN` |
| Builder.io headless CMS REST API | `builderio` | `BUILDERIO_BASE_URL` *(url)*, `BUILDERIO_TOKEN` |
| Buildertrend construction project management | `buildertrend` | `BUILDERTREND_BASE_URL` *(url)*, `BUILDERTREND_TOKEN` |
| Buildium property management | `buildium` | `BUILDIUM_BASE_URL` *(url)*, `BUILDIUM_TOKEN` |
| Buildkite REST API | `buildkite` | `BUILDKITE_BASE_URL` *(url)*, `BUILDKITE_TOKEN` |
| BuildOps commercial contractor management | `buildops` | `BUILDOPS_BASE_URL` *(url)*, `BUILDOPS_TOKEN` |
| Buildout commercial real estate marketing | `buildout` | `BUILDOUT_BASE_URL` *(url)*, `BUILDOUT_TOKEN` |
| Buildxact construction estimating/project management | `buildxact` | `BUILDXACT_BASE_URL` *(url)*, `BUILDXACT_TOKEN` |
| BulkSMS messaging REST API | `bulksms` | `BULKSMS_BASE_URL` *(url)*, `BULKSMS_TOKEN` |
| Bullhorn ATS/staffing | `bullhorn` | `BULLHORN_BASE_URL` *(url)*, `BULLHORN_TOKEN` |
| bunny.net CDN REST API | `bunny_net` | `BUNNY_NET_BASE_URL` *(url)*, `BUNNY_NET_TOKEN` |
| Bunny.net Stream video hosting | `bunny_stream` | `BUNNY_STREAM_BASE_URL` *(url)*, `BUNNY_STREAM_TOKEN` |
| bunny.net (BunnyCDN/Bunny Stream) REST API | `bunnycdn` | `BUNNYCDN_BASE_URL` *(url)*, `BUNNYCDN_TOKEN` |
| bunq banking | `bunq` | `BUNQ_BASE_URL` *(url)*, `BUNQ_TOKEN` |
| PortSwigger Burp Suite Enterprise | `burp_suite` | `BURP_SUITE_BASE_URL` *(url)*, `BURP_SUITE_TOKEN` |
| Burst SMS REST API | `burstsms` | `BURSTSMS_BASE_URL` *(url)*, `BURSTSMS_TOKEN` |
| Businessolver benefits administration | `businessolver` | `BUSINESSOLVER_BASE_URL` *(url)*, `BUSINESSOLVER_TOKEN` |
| busybusy construction time tracking/GPS | `busybusy` | `BUSYBUSY_BASE_URL` *(url)*, `BUSYBUSY_TOKEN` |
| ButterCMS REST API | `buttercms` | `BUTTERCMS_BASE_URL` *(url)*, `BUTTERCMS_TOKEN` |
| ButterflyMX property access control | `butterflymx` | `BUTTERFLYMX_BASE_URL` *(url)*, `BUTTERFLYMX_TOKEN` |
| Buy Me a Coffee creator support | `buymeacoffee` | `BUYMEACOFFEE_BASE_URL` *(url)*, `BUYMEACOFFEE_TOKEN` |
| Buzzsprout podcast hosting | `buzzsprout` | `BUZZSPROUT_BASE_URL` *(url)*, `BUZZSPROUT_TOKEN` |
| BuzzSumo REST API | `buzzsumo` | `BUZZSUMO_BASE_URL` *(url)*, `BUZZSUMO_TOKEN` |
| Bybit exchange | `bybit` | `BYBIT_BASE_URL` *(url)*, `BYBIT_TOKEN` |
| C3 AI enterprise AI platform | `c3ai` | `C3AI_BASE_URL` *(url)*, `C3AI_TOKEN` |
| CacheFly CDN REST API | `cachefly` | `CACHEFLY_BASE_URL` *(url)*, `CACHEFLY_TOKEN` |
| Sysco CAKE POS | `cake_pos` | `CAKE_POS_BASE_URL` *(url)*, `CAKE_POS_TOKEN` |
| Cal.com scheduling | `cal_com` | `CAL_COM_BASE_URL` *(url)*, `CAL_COM_TOKEN` |
| Calabrio workforce management (contact center) | `calabrio` | `CALABRIO_BASE_URL` *(url)*, `CALABRIO_TOKEN` |
| Calameo digital publishing | `calameo` | `CALAMEO_BASE_URL` *(url)*, `CALAMEO_TOKEN` |
| CalendarHero scheduling | `calendarhero` | `CALENDARHERO_BASE_URL` *(url)*, `CALENDARHERO_TOKEN` |
| Calendly | `calendly` | `CALENDLY_TOKEN` |
| CallFire voice/SMS REST API | `callfire` | `CALLFIRE_BASE_URL` *(url)*, `CALLFIRE_TOKEN` |
| CallHippo cloud telephony REST API | `callhippo` | `CALLHIPPO_BASE_URL` *(url)*, `CALLHIPPO_TOKEN` |
| CallMiner conversation analytics | `callminer` | `CALLMINER_BASE_URL` *(url)*, `CALLMINER_TOKEN` |
| CallRail call tracking | `callrail` | `CALLRAIL_BASE_URL` *(url)*, `CALLRAIL_TOKEN` |
| Campaign Monitor REST API | `campaignmonitor` | `CAMPAIGNMONITOR_BASE_URL` *(url)*, `CAMPAIGNMONITOR_TOKEN` |
| CampusLogic financial aid | `campuslogic` | `CAMPUSLOGIC_BASE_URL` *(url)*, `CAMPUSLOGIC_TOKEN` |
| Camunda 8 (Zeebe/Operate) REST API | `camunda` | `CAMUNDA_BASE_URL` *(url)*, `CAMUNDA_TOKEN` |
| Canary Labs industrial process historian | `canary_labs` | `CANARY_LABS_BASE_URL` *(url)*, `CANARY_LABS_TOKEN` |
| Candid Health medical billing REST API | `candidhealth` | `CANDIDHEALTH_BASE_URL` *(url)*, `CANDIDHEALTH_TOKEN` |
| Can Stock Photo stock media | `canstockphoto` | `CANSTOCKPHOTO_BASE_URL` *(url)*, `CANSTOCKPHOTO_TOKEN` |
| Canva Connect REST API | `canva` | `CANVA_BASE_URL` *(url)*, `CANVA_TOKEN` |
| Canvas Medical EHR REST/FHIR API | `canvas_medical` | `CANVAS_MEDICAL_BASE_URL` *(url)*, `CANVAS_MEDICAL_TOKEN` |
| Canvas LMS REST API for courses/grades | `canvaslms` | `CANVASLMS_BASE_URL` *(url)*, `CANVASLMS_TOKEN` |
| Capillary Technologies loyalty/CRM REST API (India) | `capillary_tech` | `CAPILLARY_TECH_BASE_URL` *(url)*, `CAPILLARY_TECH_TOKEN` |
| Capsule CRM | `capsulecrm` | `CAPSULECRM_BASE_URL` *(url)*, `CAPSULECRM_TOKEN` |
| Captivate.fm podcast hosting | `captivate_fm` | `CAPTIVATE_FM_BASE_URL` *(url)*, `CAPTIVATE_FM_TOKEN` |
| VMware Carbon Black Cloud | `carbon_black` | `CARBON_BLACK_BASE_URL` *(url)*, `CARBON_BLACK_TOKEN` |
| CareCloud practice management/EHR REST API | `carecloud` | `CARECLOUD_BASE_URL` *(url)*, `CARECLOUD_TOKEN` |
| Carfax vehicle-history REST API | `carfax` | `CARFAX_BASE_URL` *(url)*, `CARFAX_TOKEN` |
| WiseTech CargoWise logistics REST API | `cargowise` | `CARGOWISE_BASE_URL` *(url)*, `CARGOWISE_TOKEN` |
| Carta cap-table / equity | `carta` | `CARTA_BASE_URL` *(url)*, `CARTA_TOKEN` |
| Casepoint e-discovery/legal hold | `casepoint` | `CASEPOINT_BASE_URL` *(url)*, `CASEPOINT_TOKEN` |
| Casetext legal research | `casetext` | `CASETEXT_BASE_URL` *(url)*, `CASETEXT_TOKEN` |
| Cashfree Payments REST API | `cashfree` | `CASHFREE_BASE_URL` *(url)*, `CASHFREE_TOKEN` |
| Caspio Bridge | `caspio` | `CASPIO_BASE_URL` *(url)*, `CASPIO_TOKEN` |
| Castos podcast hosting | `castos` | `CASTOS_BASE_URL` *(url)*, `CASTOS_TOKEN` |
| Castr live streaming | `castr` | `CASTR_BASE_URL` *(url)*, `CASTR_TOKEN` |
| Catalyst customer success | `catalyst` | `CATALYST_BASE_URL` *(url)*, `CATALYST_TOKEN` |
| Catapult Sports | `catapult_sports` | `CATAPULT_SPORTS_BASE_URL` *(url)*, `CATAPULT_SPORTS_TOKEN` |
| Catapush secure push messaging REST API | `catapush` | `CATAPUSH_BASE_URL` *(url)*, `CATAPUSH_TOKEN` |
| Catchpoint REST API | `catchpoint` | `CATCHPOINT_BASE_URL` *(url)*, `CATCHPOINT_TOKEN` |
| CauseVox fundraising | `causevox` | `CAUSEVOX_BASE_URL` *(url)*, `CAUSEVOX_TOKEN` |
| CCAvenue payment gateway REST API (India) | `ccavenue` | `CCAVENUE_BASE_URL` *(url)*, `CCAVENUE_TOKEN` |
| CCC Intelligent Solutions auto claims | `ccc_intelligent` | `CCC_INTELLIGENT_BASE_URL` *(url)*, `CCC_INTELLIGENT_TOKEN` |
| Wolters Kluwer CCH Axcess Open Integration Platform REST (Tax / Document / Workstream) | `cch_axcess` | `CCH_AXCESS_BASE_URL` *(url)*, `CCH_AXCESS_TOKEN`, `CCH_AXCESS_SUBSCRIPTION_KEY` |
| CDK Global automotive dealer-management REST API | `cdk_global` | `CDK_GLOBAL_BASE_URL` *(url)*, `CDK_GLOBAL_TOKEN` |
| Cegid ERP/retail/HR REST API (France) | `cegid` | `CEGID_BASE_URL` *(url)*, `CEGID_TOKEN` |
| Ceipal ATS/staffing | `ceipal` | `CEIPAL_BASE_URL` *(url)*, `CEIPAL_TOKEN` |
| Celerant Technology retail POS REST API | `celerant` | `CELERANT_BASE_URL` *(url)*, `CELERANT_TOKEN` |
| Celigo Integrator.io REST API | `celigo` | `CELIGO_BASE_URL` *(url)*, `CELIGO_TOKEN` |
| Celoxis project management | `celoxis` | `CELOXIS_BASE_URL` *(url)*, `CELOXIS_TOKEN` |
| Censys Search/Platform | `censys` | `CENSYS_BASE_URL` *(url)*, `CENSYS_TOKEN` |
| Centage budgeting/planning | `centage` | `CENTAGE_BASE_URL` *(url)*, `CENTAGE_TOKEN` |
| CentralSquare public-safety/government | `centralsquare` | `CENTRALSQUARE_BASE_URL` *(url)*, `CENTRALSQUARE_TOKEN` |
| Cequence Security (Unified API Protection) | `cequence` | `CEQUENCE_BASE_URL` *(url)*, `CEQUENCE_TOKEN` |
| Cerebrium REST API (serverless ML model deployment) | `cerebrium` | `CEREBRIUM_BASE_URL` *(url)*, `CEREBRIUM_TOKEN` |
| Ceridian Dayforce HCM | `ceridian_dayforce` | `CERIDIAN_DAYFORCE_BASE_URL` *(url)*, `CERIDIAN_DAYFORCE_TOKEN` |
| Oracle Cerner (Millennium) FHIR REST API for EHR data | `cerner` | `CERNER_BASE_URL` *(url)*, `CERNER_TOKEN` |
| Certify (Emburse) expense/travel | `certify` | `CERTIFY_BASE_URL` *(url)*, `CERTIFY_TOKEN` |
| CERVIS volunteer management | `cervis` | `CERVIS_BASE_URL` *(url)*, `CERVIS_TOKEN` |
| Chainalysis crypto compliance/AML | `chainalysis` | `CHAINALYSIS_BASE_URL` *(url)*, `CHAINALYSIS_TOKEN` |
| ChannelAdvisor marketplace-management | `channeladvisor` | `CHANNELADVISOR_BASE_URL` *(url)*, `CHANNELADVISOR_TOKEN` |
| Chanty team chat | `chanty` | `CHANTY_BASE_URL` *(url)*, `CHANTY_TOKEN` |
| Chargebee subscription-billing REST (v2) | `chargebee` | `CHARGEBEE_BASE_URL` *(url)*, `CHARGEBEE_TOKEN` |
| Chargify (Maxio) subscription billing REST API | `chargify` | `CHARGIFY_BASE_URL` *(url)*, `CHARGIFY_TOKEN` |
| CharityEngine | `charityengine` | `CHARITYENGINE_BASE_URL` *(url)*, `CHARITYENGINE_TOKEN` |
| CharityProud donor management | `charityproud` | `CHARITYPROUD_BASE_URL` *(url)*, `CHARITYPROUD_TOKEN` |
| CharlieHR | `charliehr` | `CHARLIEHR_BASE_URL` *(url)*, `CHARLIEHR_TOKEN` |
| ChartMogul SaaS analytics REST API | `chartmogul` | `CHARTMOGUL_BASE_URL` *(url)*, `CHARTMOGUL_TOKEN` |
| Chatbase REST API (no-code AI chatbot builder) | `chatbase` | `CHATBASE_BASE_URL` *(url)*, `CHATBASE_TOKEN` |
| Chatbot.com builder REST API | `chatbot_com` | `CHATBOT_COM_BASE_URL` *(url)*, `CHATBOT_COM_TOKEN` |
| Chatfuel REST API (chatbot builder) | `chatfuel` | `CHATFUEL_BASE_URL` *(url)*, `CHATFUEL_TOKEN` |
| Chatra live chat | `chatra` | `CHATRA_BASE_URL` *(url)*, `CHATRA_TOKEN` |
| Chatwork | `chatwork` | `CHATWORK_BASE_URL` *(url)*, `CHATWORK_TOKEN` |
| Checkfront booking | `checkfront` | `CHECKFRONT_BASE_URL` *(url)*, `CHECKFRONT_TOKEN` |
| Checkly monitoring REST API | `checkly` | `CHECKLY_BASE_URL` *(url)*, `CHECKLY_TOKEN` |
| Checkmarx One AppSec REST API | `checkmarx` | `CHECKMARX_BASE_URL` *(url)*, `CHECKMARX_TOKEN` |
| Checkout.com Payments REST API | `checkout_com` | `CHECKOUT_COM_BASE_URL` *(url)*, `CHECKOUT_COM_TOKEN` |
| Check Point Infinity/Smart-1 Cloud | `checkpoint` | `CHECKPOINT_BASE_URL` *(url)*, `CHECKPOINT_TOKEN` |
| Checkr background check | `checkr` | `CHECKR_BASE_URL` *(url)*, `CHECKR_TOKEN` |
| Chef Automate REST API | `chef` | `CHEF_BASE_URL` *(url)*, `CHEF_TOKEN` |
| Cherwell Service Management | `cherwell` | `CHERWELL_BASE_URL` *(url)*, `CHERWELL_TOKEN` |
| Chili Piper scheduling | `chili_piper` | `CHILI_PIPER_BASE_URL` *(url)*, `CHILI_PIPER_TOKEN` |
| Amazon Chime | `chime` | `CHIME_BASE_URL` *(url)*, `CHIME_TOKEN` |
| Chorus.ai (ZoomInfo) conversation intelligence | `chorus` | `CHORUS_BASE_URL` *(url)*, `CHORUS_TOKEN` |
| ChowNow ordering | `chownow` | `CHOWNOW_BASE_URL` *(url)*, `CHOWNOW_TOKEN` |
| Chroma Cloud REST API (vector database) | `chroma_cloud` | `CHROMA_CLOUD_BASE_URL` *(url)*, `CHROMA_CLOUD_TOKEN` |
| Chromatic (Storybook) REST API | `chromatic` | `CHROMATIC_BASE_URL` *(url)*, `CHROMATIC_TOKEN` |
| Chrometa automatic legal time-tracking | `chrometa` | `CHROMETA_BASE_URL` *(url)*, `CHROMETA_TOKEN` |
| ChronoTrack | `chronotrack` | `CHRONOTRACK_BASE_URL` *(url)*, `CHRONOTRACK_TOKEN` |
| ChurnZero customer success | `churnzero` | `CHURNZERO_BASE_URL` *(url)*, `CHURNZERO_TOKEN` |
| Cin7 (Core/DEAR) inventory | `cin7` | `CIN7_BASE_URL` *(url)*, `CIN7_TOKEN` |
| CINC real estate CRM/lead generation | `cinc` | `CINC_BASE_URL` *(url)*, `CINC_TOKEN` |
| Circle (USDC) | `circle_usdc` | `CIRCLE_USDC_BASE_URL` *(url)*, `CIRCLE_USDC_TOKEN` |
| CircleCI | `circleci` | `CIRCLECI_BASE_URL` *(url)*, `CIRCLECI_TOKEN` |
| Cirrus Insight sales engagement | `cirrusinsight` | `CIRRUSINSIGHT_BASE_URL` *(url)*, `CIRRUSINSIGHT_TOKEN` |
| Cisco Umbrella | `cisco_umbrella` | `UMBRELLA_BASE_URL` *(url)*, `UMBRELLA_TOKEN` |
| CityBase government payments | `citybase` | `CITYBASE_BASE_URL` *(url)*, `CITYBASE_TOKEN` |
| CivicPlus government CMS/engagement | `civicplus` | `CIVICPLUS_BASE_URL` *(url)*, `CIVICPLUS_TOKEN` |
| Civitas Learning student-success analytics | `civitas_learning` | `CIVITAS_LEARNING_BASE_URL` *(url)*, `CIVITAS_LEARNING_TOKEN` |
| Civo Cloud REST API | `civo` | `CIVO_BASE_URL` *(url)*, `CIVO_TOKEN` |
| CJ Affiliate (Commission Junction) REST API | `cjaffiliate` | `CJAFFILIATE_BASE_URL` *(url)*, `CJAFFILIATE_TOKEN` |
| Clari | `clari` | `CLARI_BASE_URL` *(url)*, `CLARI_TOKEN` |
| Clarifai REST API (AI/ML model hosting) | `clarifai` | `CLARIFAI_BASE_URL` *(url)*, `CLARIFAI_TOKEN` |
| Clarizen (Planview) project | `clarizen` | `CLARIZEN_BASE_URL` *(url)*, `CLARIZEN_TOKEN` |
| ClassDojo REST API for classroom communication | `classdojo` | `CLASSDOJO_BASE_URL` *(url)*, `CLASSDOJO_TOKEN` |
| ClassLink OneRoster REST API | `classlink` | `CLASSLINK_BASE_URL` *(url)*, `CLASSLINK_TOKEN` |
| Classy fundraising | `classy` | `CLASSY_BASE_URL` *(url)*, `CLASSY_TOKEN` |
| Clay.run REST API (no-code data enrichment tables) | `clay_run` | `CLAY_RUN_BASE_URL` *(url)*, `CLAY_RUN_TOKEN` |
| Clearbit | `clearbit` | `CLEARBIT_BASE_URL` *(url)*, `CLEARBIT_TOKEN` |
| ClearBlade industrial IoT edge platform | `clearblade` | `CLEARBLADE_BASE_URL` *(url)*, `CLEARBLADE_TOKEN` |
| Clear Books accounting | `clearbooks` | `CLEARBOOKS_BASE_URL` *(url)*, `CLEARBOOKS_TOKEN` |
| ClearML REST API (MLOps platform) | `clearml` | `CLEARML_BASE_URL` *(url)*, `CLEARML_TOKEN` |
| ClearSlide sales enablement | `clearslide` | `CLEARSLIDE_BASE_URL` *(url)*, `CLEARSLIDE_TOKEN` |
| Clever education data-sync REST API | `clever` | `CLEVER_BASE_URL` *(url)*, `CLEVER_TOKEN` |
| CleverTap REST API | `clevertap` | `CLEVERTAP_BASE_URL` *(url)*, `CLEVERTAP_TOKEN` |
| Clickatell messaging REST API | `clickatell` | `CLICKATELL_BASE_URL` *(url)*, `CLICKATELL_TOKEN` |
| ClickFunnels REST API | `clickfunnels` | `CLICKFUNNELS_BASE_URL` *(url)*, `CLICKFUNNELS_TOKEN` |
| ClickHouse HTTP/REST interface | `clickhouse` | `CLICKHOUSE_BASE_URL` *(url)*, `CLICKHOUSE_TOKEN` |
| ClickPay property/HOA payments | `clickpay` | `CLICKPAY_BASE_URL` *(url)*, `CLICKPAY_TOKEN` |
| ClientSuccess customer success | `clientsuccess` | `CLIENTSUCCESS_BASE_URL` *(url)*, `CLIENTSUCCESS_TOKEN` |
| Climate FieldView agriculture REST API | `climate_fieldview` | `CLIMATE_FIELDVIEW_BASE_URL` *(url)*, `CLIMATE_FIELDVIEW_TOKEN` |
| Clio legal practice-management REST (v4) | `clio` | `CLIO_BASE_URL` *(url)*, `CLIO_TOKEN` |
| Clio Payments legal billing REST (distinct from generic clio entry) | `clio_payments` | `CLIO_PAYMENTS_BASE_URL` *(url)*, `CLIO_PAYMENTS_TOKEN` |
| Clip payments REST API (Mexico) | `clip` | `CLIP_BASE_URL` *(url)*, `CLIP_TOKEN` |
| Clipdrop (Stability AI) image API | `clipdrop` | `CLIPDROP_BASE_URL` *(url)*, `CLIPDROP_TOKEN` |
| Clockify time tracking | `clockify` | `CLOCKIFY_BASE_URL` *(url)*, `CLOCKIFY_TOKEN` |
| Clockodo time tracking REST API (Germany) | `clockodo` | `CLOCKODO_BASE_URL` *(url)*, `CLOCKODO_TOKEN` |
| Close CRM | `close` | `CLOSE_BASE_URL` *(url)*, `CLOSE_TOKEN` |
| Cloudbeds hotel PMS REST API | `cloudbeds` | `CLOUDBEDS_BASE_URL` *(url)*, `CLOUDBEDS_TOKEN` |
| Cloudera Manager | `cloudera` | `CLOUDERA_BASE_URL` *(url)*, `CLOUDERA_TOKEN` |
| Cloudflare | `cloudflare` | `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ZONE_ID` *(url)* |
| Cloudflare Stream video | `cloudflare_stream` | `CLOUDFLARE_STREAM_BASE_URL` *(url)*, `CLOUDFLARE_STREAM_TOKEN` |
| Cloudinary media-management REST API | `cloudinary` | `CLOUDINARY_BASE_URL` *(url)*, `CLOUDINARY_TOKEN` |
| Cloudsmith package registry REST API | `cloudsmith` | `CLOUDSMITH_BASE_URL` *(url)*, `CLOUDSMITH_TOKEN` |
| Infor CloudSuite Industrial (SyteLine) | `cloudsuite_industrial` | `CLOUDSUITE_INDUSTRIAL_BASE_URL` *(url)*, `CLOUDSUITE_INDUSTRIAL_TOKEN` |
| CloudTalk contact center | `cloudtalk` | `CLOUDTALK_BASE_URL` *(url)*, `CLOUDTALK_TOKEN` |
| Clover (Fiserv) POS REST API | `clover` | `CLOVER_BASE_URL` *(url)*, `CLOVER_TOKEN` |
| CloverDX (CloverETL) REST API | `cloverdx` | `CLOVERDX_BASE_URL` *(url)*, `CLOVERDX_TOKEN` |
| ClubReady | `clubready` | `CLUBREADY_BASE_URL` *(url)*, `CLUBREADY_TOKEN` |
| CM.com Communications Platform REST API | `cm_com` | `CM_COM_BASE_URL` *(url)*, `CM_COM_TOKEN` |
| CMiC construction ERP/project management | `cmic` | `CMIC_BASE_URL` *(url)*, `CMIC_TOKEN` |
| Coalition cyber insurance | `coalition_insurance` | `COALITION_INSURANCE_BASE_URL` *(url)*, `COALITION_INSURANCE_TOKEN` |
| Cockpit CMS REST API | `cockpitcms` | `COCKPITCMS_BASE_URL` *(url)*, `COCKPITCMS_TOKEN` |
| CockroachDB Cloud REST API | `cockroachcloud` | `COCKROACHCLOUD_BASE_URL` *(url)*, `COCKROACHCLOUD_TOKEN` |
| CockroachDB Cloud REST API | `cockroachlabs` | `COCKROACHLABS_BASE_URL` *(url)*, `COCKROACHLABS_TOKEN` |
| CoConstruct residential construction management | `coconstruct` | `COCONSTRUCT_BASE_URL` *(url)*, `COCONSTRUCT_TOKEN` |
| Coda | `coda` | `CODA_BASE_URL` *(url)*, `CODA_TOKEN` |
| Codacy code-quality REST API | `codacy` | `CODACY_BASE_URL` *(url)*, `CODACY_TOKEN` |
| Codat accounting/commerce data aggregation | `codat` | `CODAT_BASE_URL` *(url)*, `CODAT_TOKEN` |
| Code Climate REST API | `codeclimate` | `CODECLIMATE_BASE_URL` *(url)*, `CODECLIMATE_TOKEN` |
| Codecov REST API | `codecov` | `CODECOV_BASE_URL` *(url)*, `CODECOV_TOKEN` |
| Codefresh REST API | `codefresh` | `CODEFRESH_BASE_URL` *(url)*, `CODEFRESH_TOKEN` |
| CodeSandbox REST API | `codesandbox` | `CODESANDBOX_BASE_URL` *(url)*, `CODESANDBOX_TOKEN` |
| Codeship (CloudBees) REST API | `codeship` | `CODESHIP_BASE_URL` *(url)*, `CODESHIP_TOKEN` |
| Cofense Triage/Intelligence | `cofense` | `COFENSE_BASE_URL` *(url)*, `COFENSE_TOKEN` |
| Cognigy.AI conversational AI REST API | `cognigy` | `COGNIGY_BASE_URL` *(url)*, `COGNIGY_TOKEN` |
| Cognism prospecting/sales intelligence | `cognism` | `COGNISM_BASE_URL` *(url)*, `COGNISM_TOKEN` |
| Cognite Data Fusion industrial DataOps | `cognite` | `COGNITE_BASE_URL` *(url)*, `COGNITE_TOKEN` |
| Cognito Forms | `cognito_forms` | `COGNITO_FORMS_BASE_URL` *(url)*, `COGNITO_FORMS_TOKEN` |
| IBM Cognos Analytics | `cognos` | `COGNOS_BASE_URL` *(url)*, `COGNOS_TOKEN` |
| Cohere REST API | `cohere_ai` | `COHERE_AI_BASE_URL` *(url)*, `COHERE_AI_TOKEN` |
| Coinbase Advanced Trade | `coinbase` | `COINBASE_BASE_URL` *(url)*, `COINBASE_TOKEN` |
| CoinDCX exchange | `coindcx` | `COINDCX_BASE_URL` *(url)*, `COINDCX_TOKEN` |
| CoinGecko market-data | `coingecko` | `COINGECKO_BASE_URL` *(url)*, `COINGECKO_TOKEN` |
| CoinJar exchange | `coinjar` | `COINJAR_BASE_URL` *(url)*, `COINJAR_TOKEN` |
| CoinMarketCap market-data | `coinmarketcap` | `COINMARKETCAP_BASE_URL` *(url)*, `COINMARKETCAP_TOKEN` |
| Coinone exchange | `coinone` | `COINONE_BASE_URL` *(url)*, `COINONE_TOKEN` |
| CoinPayments | `coinpayments` | `COINPAYMENTS_BASE_URL` *(url)*, `COINPAYMENTS_TOKEN` |
| CoinSpot exchange | `coinspot` | `COINSPOT_BASE_URL` *(url)*, `COINSPOT_TOKEN` |
| CollegeNET Series25 scheduling | `collegenet` | `COLLEGENET_BASE_URL` *(url)*, `COLLEGENET_TOKEN` |
| Column banking API | `column_bank` | `COLUMN_BANK_BASE_URL` *(url)*, `COLUMN_BANK_TOKEN` |
| Comet ML REST API (experiment/model tracking) | `comet_ml` | `COMET_ML_BASE_URL` *(url)*, `COMET_ML_TOKEN` |
| Commerce Layer headless commerce REST API | `commerce_layer` | `COMMERCE_LAYER_BASE_URL` *(url)*, `COMMERCE_LAYER_TOKEN` |
| commercetools headless commerce REST/GraphQL | `commercetools` | `COMMERCETOOLS_BASE_URL` *(url)*, `COMMERCETOOLS_TOKEN` |
| Commusoft field service management | `commusoft` | `COMMUSOFT_BASE_URL` *(url)*, `COMMUSOFT_TOKEN` |
| ComplyAdvantage AML/sanctions screening | `complyadvantage` | `COMPLYADVANTAGE_BASE_URL` *(url)*, `COMPLYADVANTAGE_TOKEN` |
| Computop payment gateway REST API (Germany) | `computop` | `COMPUTOP_BASE_URL` *(url)*, `COMPUTOP_TOKEN` |
| Conceptboard whiteboard | `conceptboard` | `CONCEPTBOARD_BASE_URL` *(url)*, `CONCEPTBOARD_TOKEN` |
| Concord CLM | `concord` | `CONCORD_BASE_URL` *(url)*, `CONCORD_TOKEN` |
| Concord contract lifecycle management | `concord_clm` | `CONCORD_CLM_BASE_URL` *(url)*, `CONCORD_CLM_TOKEN` |
| Concourse CI REST API | `concourse` | `CONCOURSE_BASE_URL` *(url)*, `CONCOURSE_TOKEN` |
| Concrete CMS REST API | `concretecms` | `CONCRETECMS_BASE_URL` *(url)*, `CONCRETECMS_TOKEN` |
| SAP Concur | `concur` | `CONCUR_BASE_URL` *(url)*, `CONCUR_TOKEN` |
| ConductorOne Access Governance | `conductorone` | `CONDUCTORONE_BASE_URL` *(url)*, `CONDUCTORONE_TOKEN` |
| Conekta payments REST API (Mexico) | `conekta` | `CONEKTA_BASE_URL` *(url)*, `CONEKTA_TOKEN` |
| ConfigCat feature-flag management REST API | `configcat` | `CONFIGCAT_BASE_URL` *(url)*, `CONFIGCAT_TOKEN` |
| Confluence | `confluence` | `CONFLUENCE_URL` *(url)*, `CONFLUENCE_USER` *(url)*, `CONFLUENCE_API_TOKEN` |
| Confluent Cloud | `confluent` | `CONFLUENT_BASE_URL` *(url)*, `CONFLUENT_TOKEN` |
| Conga Contracts (CLM) | `conga_contracts` | `CONGA_CONTRACTS_BASE_URL` *(url)*, `CONGA_CONTRACTS_TOKEN` |
| Connecture insurance distribution/quoting | `connecture` | `CONNECTURE_BASE_URL` *(url)*, `CONNECTURE_TOKEN` |
| Constant Contact REST v3 | `constantcontact` | `CONSTANTCONTACT_BASE_URL` *(url)*, `CONSTANTCONTACT_TOKEN` |
| Constructor.io REST API (search/discovery) | `constructor_io` | `CONSTRUCTOR_IO_BASE_URL` *(url)*, `CONSTRUCTOR_IO_TOKEN` |
| Conta Azul accounting REST API (Brazil) | `conta_azul` | `CONTA_AZUL_BASE_URL` *(url)*, `CONTA_AZUL_TOKEN` |
| Contabo Cloud REST API | `contabo` | `CONTABO_BASE_URL` *(url)*, `CONTABO_TOKEN` |
| Contactually CRM | `contactually` | `CONTACTUALLY_BASE_URL` *(url)*, `CONTACTUALLY_TOKEN` |
| Contentful Content Delivery/Management REST API | `contentful` | `CONTENTFUL_BASE_URL` *(url)*, `CONTENTFUL_TOKEN` |
| Content Guru (storm) contact center | `contentguru` | `CONTENTGURU_BASE_URL` *(url)*, `CONTENTGURU_TOKEN` |
| Contentsquare REST API | `contentsquare` | `CONTENTSQUARE_BASE_URL` *(url)*, `CONTENTSQUARE_TOKEN` |
| Contentstack Content Management REST API | `contentstack` | `CONTENTSTACK_BASE_URL` *(url)*, `CONTENTSTACK_TOKEN` |
| Contractbook CLM | `contractbook` | `CONTRACTBOOK_BASE_URL` *(url)*, `CONTRACTBOOK_TOKEN` |
| Contractor Foreman construction management | `contractor_foreman` | `CONTRACTOR_FOREMAN_BASE_URL` *(url)*, `CONTRACTOR_FOREMAN_TOKEN` |
| ContractPodAi CLM | `contractpodai` | `CONTRACTPODAI_BASE_URL` *(url)*, `CONTRACTPODAI_TOKEN` |
| ContractSafe | `contractsafe` | `CONTRACTSAFE_BASE_URL` *(url)*, `CONTRACTSAFE_TOKEN` |
| ContractWorks | `contractworks` | `CONTRACTWORKS_BASE_URL` *(url)*, `CONTRACTWORKS_TOKEN` |
| Contrast Security | `contrast_security` | `CONTRAST_SECURITY_BASE_URL` *(url)*, `CONTRAST_SECURITY_TOKEN` |
| Convercent (OneTrust) ethics/compliance | `convercent` | `CONVERCENT_BASE_URL` *(url)*, `CONVERCENT_TOKEN` |
| Convert.com REST API (A/B testing) | `convertcom` | `CONVERTCOM_BASE_URL` *(url)*, `CONVERTCOM_TOKEN` |
| ConvertKit (Kit) REST API | `convertkit` | `CONVERTKIT_BASE_URL` *(url)*, `CONVERTKIT_TOKEN` |
| Convoy digital freight REST API | `convoy` | `CONVOY_BASE_URL` *(url)*, `CONVOY_TOKEN` |
| Copilot Money personal finance | `copilot_money` | `COPILOT_MONEY_BASE_URL` *(url)*, `COPILOT_MONEY_TOKEN` |
| Copper CRM | `copper` | `COPPER_BASE_URL` *(url)*, `COPPER_TOKEN` |
| Coralogix observability REST API | `coralogix` | `CORALOGIX_BASE_URL` *(url)*, `CORALOGIX_TOKEN` |
| Cordial REST API | `cordial` | `CORDIAL_BASE_URL` *(url)*, `CORDIAL_TOKEN` |
| Corelight Network Detection | `corelight` | `CORELIGHT_BASE_URL` *(url)*, `CORELIGHT_TOKEN` |
| CoreLogic property data | `corelogic` | `CORELOGIC_BASE_URL` *(url)*, `CORELOGIC_TOKEN` |
| CoreWeave REST API (GPU cloud/model serving) | `coreweave` | `COREWEAVE_BASE_URL` *(url)*, `COREWEAVE_TOKEN` |
| Cornerstone OnDemand | `cornerstone` | `CORNERSTONE_BASE_URL` *(url)*, `CORNERSTONE_TOKEN` |
| Cornerstone OnDemand learning module REST (distinct from generic cornerstone entry) | `cornerstone_ondemand_lms` | `CORNERSTONE_ONDEMAND_LMS_BASE_URL` *(url)*, `CORNERSTONE_ONDEMAND_LMS_TOKEN` |
| Corridor legal spend/e-billing | `corridor_gtc` | `CORRIDOR_GTC_BASE_URL` *(url)*, `CORRIDOR_GTC_TOKEN` |
| Corrigo (JLL Technologies) facilities work-order | `corrigo` | `CORRIGO_BASE_URL` *(url)*, `CORRIGO_TOKEN` |
| Palo Alto Networks Cortex XDR | `cortex_xdr` | `CORTEX_XDR_BASE_URL` *(url)*, `CORTEX_XDR_TOKEN` |
| Palo Alto Networks Cortex XSOAR | `cortex_xsoar` | `CORTEX_XSOAR_BASE_URL` *(url)*, `CORTEX_XSOAR_TOKEN` |
| Corteza low-code REST API | `corteza` | `CORTEZA_BASE_URL` *(url)*, `CORTEZA_TOKEN` |
| Corvus Insurance (cyber) | `corvus_insurance` | `CORVUS_INSURANCE_BASE_URL` *(url)*, `CORVUS_INSURANCE_TOKEN` |
| CoSchedule REST API | `coschedule` | `COSCHEDULE_BASE_URL` *(url)*, `COSCHEDULE_TOKEN` |
| CosmoLex legal practice management | `cosmolex` | `COSMOLEX_BASE_URL` *(url)*, `COSMOLEX_TOKEN` |
| CoStar commercial real estate data REST API | `costar` | `COSTAR_BASE_URL` *(url)*, `COSTAR_TOKEN` |
| Count (count.co) REST/GraphQL API | `count_co` | `COUNT_CO_BASE_URL` *(url)*, `COUNT_CO_TOKEN` |
| Countly product analytics REST API | `countly` | `COUNTLY_BASE_URL` *(url)*, `COUNTLY_TOKEN` |
| Coupa spend/procurement | `coupa` | `COUPA_BASE_URL` *(url)*, `COUPA_TOKEN` |
| Coupang WING marketplace REST API | `coupang` | `COUPANG_BASE_URL` *(url)*, `COUPANG_TOKEN` |
| Courier.com notification infrastructure REST API | `courier_api` | `COURIER_API_BASE_URL` *(url)*, `COURIER_API_TOKEN` |
| CourseLeaf curriculum/catalog management | `courseleaf` | `COURSELEAF_BASE_URL` *(url)*, `COURSELEAF_TOKEN` |
| Coursera Business/Partner REST API | `coursera` | `COURSERA_BASE_URL` *(url)*, `COURSERA_TOKEN` |
| Coveo REST API (enterprise search/relevance) | `coveo` | `COVEO_BASE_URL` *(url)*, `COVEO_TOKEN` |
| Cover Genius embedded insurance | `cover_genius` | `COVER_GENIUS_BASE_URL` *(url)*, `COVER_GENIUS_TOKEN` |
| Coveralls REST API | `coveralls` | `COVERALLS_BASE_URL` *(url)*, `COVERALLS_TOKEN` |
| Synopsys Coverity Connect | `coverity` | `COVERITY_BASE_URL` *(url)*, `COVERITY_TOKEN` |
| Covideo video messaging | `covideo` | `COVIDEO_BASE_URL` *(url)*, `COVIDEO_TOKEN` |
| Craft docs | `craft_docs` | `CRAFT_DOCS_BASE_URL` *(url)*, `CRAFT_DOCS_TOKEN` |
| Craft CMS REST/GraphQL API | `craftcms` | `CRAFTCMS_BASE_URL` *(url)*, `CRAFTCMS_TOKEN` |
| Crazy Egg REST API | `crazy_egg` | `CRAZY_EGG_BASE_URL` *(url)*, `CRAZY_EGG_TOKEN` |
| Creately diagramming/whiteboard | `creately` | `CREATELY_BASE_URL` *(url)*, `CREATELY_TOKEN` |
| Creatio (bpm'online) | `creatio` | `CREATIO_BASE_URL` *(url)*, `CREATIO_TOKEN` |
| Crelate ATS/staffing | `crelate` | `CRELATE_BASE_URL` *(url)*, `CRELATE_TOKEN` |
| Cresta contact-center AI coaching | `cresta` | `CRESTA_BASE_URL` *(url)*, `CRESTA_TOKEN` |
| CrewAI Enterprise REST API (multi-agent orchestration platform) | `crewai_studio` | `CREWAI_STUDIO_BASE_URL` *(url)*, `CREWAI_STUDIO_TOKEN` |
| CREXi commercial real estate marketplace | `crexi` | `CREXI_BASE_URL` *(url)*, `CREXI_TOKEN` |
| Crisp chat/support | `crisp` | `CRISP_BASE_URL` *(url)*, `CRISP_TOKEN` |
| Criteo Marketing API | `criteo` | `CRITEO_BASE_URL` *(url)*, `CRITEO_TOKEN` |
| Criteria Corp pre-employment testing | `criteria_corp` | `CRITERIA_CORP_BASE_URL` *(url)*, `CRITERIA_CORP_TOKEN` |
| Critical Manufacturing MES | `critical_manufacturing` | `CRITICAL_MANUFACTURING_BASE_URL` *(url)*, `CRITICAL_MANUFACTURING_TOKEN` |
| Cropin agriculture-intelligence REST API | `cropin` | `CROPIN_BASE_URL` *(url)*, `CROPIN_TOKEN` |
| Crowdcast live event platform | `crowdcast` | `CROWDCAST_BASE_URL` *(url)*, `CROWDCAST_TOKEN` |
| CrowdSec Console/CTI | `crowdsec` | `CROWDSEC_BASE_URL` *(url)*, `CROWDSEC_TOKEN` |
| Crowdsignal (formerly Polldaddy) | `crowdsignal` | `CROWDSIGNAL_BASE_URL` *(url)*, `CROWDSIGNAL_TOKEN` |
| CrowdStrike Falcon | `crowdstrike` | `CROWDSTRIKE_BASE_URL` *(url)*, `CROWDSTRIKE_TOKEN` |
| Crunchbase company / funding data REST (v4) | `crunchbase` | `CRUNCHBASE_BASE_URL` *(url)*, `CRUNCHBASE_TOKEN` |
| Crypto.com Exchange | `crypto_com` | `CRYPTO_COM_BASE_URL` *(url)*, `CRYPTO_COM_TOKEN` |
| Crystallize headless commerce GraphQL API | `crystallize` | `CRYSTALLIZE_BASE_URL` *(url)*, `CRYSTALLIZE_TOKEN` |
| CS-Cart REST API | `cs_cart` | `CS_CART_BASE_URL` *(url)*, `CS_CART_TOKEN` |
| Cube FP&A | `cube_software` | `CUBE_SOFTWARE_BASE_URL` *(url)*, `CUBE_SOFTWARE_TOKEN` |
| Cuboh order aggregation | `cuboh` | `CUBOH_BASE_URL` *(url)*, `CUBOH_TOKEN` |
| Culture Amp employee engagement | `culture_amp` | `CULTURE_AMP_BASE_URL` *(url)*, `CULTURE_AMP_TOKEN` |
| Software AG Cumulocity IoT | `cumulocity` | `CUMULOCITY_BASE_URL` *(url)*, `CUMULOCITY_TOKEN` |
| Currencycloud (Visa) cross-border payments | `currencycloud` | `CURRENCYCLOUD_BASE_URL` *(url)*, `CURRENCYCLOUD_TOKEN` |
| CurrencyFair remittance | `currencyfair` | `CURRENCYFAIR_BASE_URL` *(url)*, `CURRENCYFAIR_TOKEN` |
| Current neobank | `current_banking` | `CURRENT_BANKING_BASE_URL` *(url)*, `CURRENT_BANKING_TOKEN` |
| CurseForge REST API | `curseforge` | `CURSEFORGE_BASE_URL` *(url)*, `CURSEFORGE_TOKEN` |
| Custify customer success | `custify` | `CUSTIFY_BASE_URL` *(url)*, `CUSTIFY_TOKEN` |
| Customer.io REST API (Track + App API) | `customerio` | `CUSTOMERIO_BASE_URL` *(url)*, `CUSTOMERIO_TOKEN` |
| Cvent REST (events) | `cvent` | `CVENT_BASE_URL` *(url)*, `CVENT_TOKEN` |
| CyberArk | `cyberark` | `CYBERARK_BASE_URL` *(url)*, `CYBERARK_TOKEN` |
| Cybereason Defense Platform | `cybereason` | `CYBEREASON_BASE_URL` *(url)*, `CYBEREASON_TOKEN` |
| CyberGrants corporate/foundation grantmaking | `cybergrants` | `CYBERGRANTS_BASE_URL` *(url)*, `CYBERGRANTS_TOKEN` |
| CyberSource (Visa) payments REST API | `cybersource` | `CYBERSOURCE_BASE_URL` *(url)*, `CYBERSOURCE_TOKEN` |
| Cyera Data Security Posture Management | `cyera` | `CYERA_BASE_URL` *(url)*, `CYERA_TOKEN` |
| Cymulate Exposure Management/BAS | `cymulate` | `CYMULATE_BASE_URL` *(url)*, `CYMULATE_TOKEN` |
| Cyware Threat Intelligence/SOAR | `cyware` | `CYWARE_BASE_URL` *(url)*, `CYWARE_TOKEN` |
| Dacast video streaming platform | `dacast` | `DACAST_BASE_URL` *(url)*, `DACAST_TOKEN` |
| Dagster Cloud GraphQL API | `dagster` | `DAGSTER_BASE_URL` *(url)*, `DAGSTER_TOKEN` |
| Daily.co video call | `daily_co` | `DAILY_CO_BASE_URL` *(url)*, `DAILY_CO_TOKEN` |
| Dailymotion REST API | `dailymotion` | `DAILYMOTION_BASE_URL` *(url)*, `DAILYMOTION_TOKEN` |
| Daraz marketplace seller REST API (South Asia, Alibaba) | `daraz` | `DARAZ_BASE_URL` *(url)*, `DARAZ_TOKEN` |
| Darktrace Threat Visualizer | `darktrace` | `DARKTRACE_BASE_URL` *(url)*, `DARKTRACE_TOKEN` |
| Darwinbox HR REST API (India) | `darwinbox` | `DARWINBOX_BASE_URL` *(url)*, `DARWINBOX_TOKEN` |
| Relational database (SQLAlchemy URL) | `database` | `DATABASE_URL` |
| Databox REST API | `databox` | `DATABOX_BASE_URL` *(url)*, `DATABOX_TOKEN` |
| Databricks | `databricks` | `DATABRICKS_HOST` *(url)*, `DATABRICKS_TOKEN`, `DATABRICKS_WAREHOUSE_ID` *(url)* |
| Datadog | `datadog` | `DATADOG_API_KEY`, `DATADOG_APP_KEY` |
| Datarails FP&A | `datarails` | `DATARAILS_BASE_URL` *(url)*, `DATARAILS_TOKEN` |
| DATEV accounting/tax REST API (Germany) | `datev` | `DATEV_BASE_URL` *(url)*, `DATEV_TOKEN` |
| DatoCMS Content Management/Delivery API (REST + GraphQL) | `datocms` | `DATOCMS_BASE_URL` *(url)*, `DATOCMS_TOKEN` |
| Dave neobank | `dave_banking` | `DAVE_BANKING_BASE_URL` *(url)*, `DAVE_BANKING_TOKEN` |
| dbt Cloud | `dbt` | `DBT_BASE_URL` *(url)*, `DBT_TOKEN` |
| DealerSocket automotive CRM/DMS REST API | `dealersocket` | `DEALERSOCKET_BASE_URL` *(url)*, `DEALERSOCKET_TOKEN` |
| Dealertrack (Cox Automotive) F&I REST API | `dealertrack` | `DEALERTRACK_BASE_URL` *(url)*, `DEALERTRACK_TOKEN` |
| Decap CMS (Netlify CMS) git-backed content API | `decapcms` | `DECAPCMS_BASE_URL` *(url)*, `DECAPCMS_TOKEN` |
| Deel REST (global payroll/EOR) | `deel` | `DEEL_BASE_URL` *(url)*, `DEEL_TOKEN` |
| Deepgram REST API | `deepgram` | `DEEPGRAM_BASE_URL` *(url)*, `DEEPGRAM_TOKEN` |
| DeepInfra REST API | `deepinfra` | `DEEPINFRA_BASE_URL` *(url)*, `DEEPINFRA_TOKEN` |
| Deepnote REST API | `deepnote` | `DEEPNOTE_BASE_URL` *(url)*, `DEEPNOTE_TOKEN` |
| deepset Cloud REST API (Haystack RAG pipelines) | `deepset_cloud` | `DEEPSET_CLOUD_BASE_URL` *(url)*, `DEEPSET_CLOUD_TOKEN` |
| DeepSource code-quality REST/GraphQL API | `deepsource` | `DEEPSOURCE_BASE_URL` *(url)*, `DEEPSOURCE_TOKEN` |
| Deepwatch MDR Platform | `deepwatch` | `DEEPWATCH_BASE_URL` *(url)*, `DEEPWATCH_TOKEN` |
| Deezer REST API | `deezer` | `DEEZER_BASE_URL` *(url)*, `DEEZER_TOKEN` |
| Microsoft Defender | `defender` | `DEFENDER_BASE_URL` *(url)*, `DEFENDER_TOKEN` |
| DEGIRO brokerage | `degiro` | `DEGIRO_BASE_URL` *(url)*, `DEGIRO_TOKEN` |
| Degreed learning experience platform | `degreed` | `DEGREED_BASE_URL` *(url)*, `DEGREED_TOKEN` |
| Ellucian Degree Works | `degreeworks` | `DEGREEWORKS_BASE_URL` *(url)*, `DEGREEWORKS_TOKEN` |
| Delhivery logistics REST API (India) | `delhivery` | `DELHIVERY_BASE_URL` *(url)*, `DELHIVERY_TOKEN` |
| Delighted (NPS/CX) | `delighted` | `DELIGHTED_BASE_URL` *(url)*, `DELIGHTED_TOKEN` |
| Delinea (Thycotic) Secret Server REST API | `delinea` | `DELINEA_BASE_URL` *(url)*, `DELINEA_TOKEN` |
| Deliverect delivery integration | `deliverect` | `DELIVERECT_BASE_URL` *(url)*, `DELIVERECT_TOKEN` |
| Deliveroo | `deliveroo` | `DELIVEROO_BASE_URL` *(url)*, `DELIVEROO_TOKEN` |
| Deliverr fulfillment REST API | `deliverr` | `DELIVERR_BASE_URL` *(url)*, `DELIVERR_TOKEN` |
| Delivery Hero partner REST API (Germany) | `delivery_hero` | `DELIVERY_HERO_BASE_URL` *(url)*, `DELIVERY_HERO_TOKEN` |
| Delivery Hero | `deliveryhero` | `DELIVERYHERO_BASE_URL` *(url)*, `DELIVERYHERO_TOKEN` |
| Deltek project management (A/E firms) | `deltek` | `DELTEK_BASE_URL` *(url)*, `DELTEK_TOKEN` |
| Demio webinar | `demio` | `DEMIO_BASE_URL` *(url)*, `DEMIO_TOKEN` |
| Deposco Bright Suite WMS/OMS | `deposco` | `DEPOSCO_BASE_URL` *(url)*, `DEPOSCO_TOKEN` |
| Depositphotos stock media | `depositphotos` | `DEPOSITPHOTOS_BASE_URL` *(url)*, `DEPOSITPHOTOS_TOKEN` |
| Deputy workforce scheduling | `deputy` | `DEPUTY_BASE_URL` *(url)*, `DEPUTY_TOKEN` |
| Deribit derivatives exchange | `deribit` | `DERIBIT_BASE_URL` *(url)*, `DERIBIT_TOKEN` |
| Descartes Systems logistics/customs REST API | `descartes` | `DESCARTES_BASE_URL` *(url)*, `DESCARTES_TOKEN` |
| Descript audio/video editing | `descript` | `DESCRIPT_BASE_URL` *(url)*, `DESCRIPT_TOKEN` |
| Deskpro helpdesk | `deskpro` | `DESKPRO_BASE_URL` *(url)*, `DESKPRO_TOKEN` |
| Detectify Surface Monitoring | `detectify` | `DETECTIFY_BASE_URL` *(url)*, `DETECTIFY_TOKEN` |
| Determine (Corcentric) CLM | `determine_clm` | `DETERMINE_CLM_BASE_URL` *(url)*, `DETERMINE_CLM_TOKEN` |
| Determined AI REST API (deep learning training platform) | `determined_ai` | `DETERMINED_AI_BASE_URL` *(url)*, `DETERMINED_AI_TOKEN` |
| DeviantArt | `deviantart` | `DEVIANTART_BASE_URL` *(url)*, `DEVIANTART_TOKEN` |
| Devo Security Data Platform | `devo` | `DEVO_BASE_URL` *(url)*, `DEVO_TOKEN` |
| Dexatel CPaaS messaging REST API | `dexatel` | `DEXATEL_BASE_URL` *(url)*, `DEXATEL_TOKEN` |
| Dext Prepare bookkeeping automation | `dext_prepare` | `DEXT_PREPARE_BASE_URL` *(url)*, `DEXT_PREPARE_TOKEN` |
| Google Dialogflow conversational AI REST API | `dialogflow` | `DIALOGFLOW_BASE_URL` *(url)*, `DIALOGFLOW_TOKEN` |
| Dialpad | `dialpad` | `DIALPAD_BASE_URL` *(url)*, `DIALPAD_TOKEN` |
| DIDWW telecom numbers/voice REST API (JSON:API) | `didww` | `DIDWW_BASE_URL` *(url)*, `DIDWW_TOKEN` |
| Dify REST API (LLM app builder) | `dify_ai` | `DIFY_AI_BASE_URL` *(url)*, `DIFY_AI_TOKEN` |
| DigitalOcean | `digitalocean` | `DIGITALOCEAN_BASE_URL` *(url)*, `DIGITALOCEAN_TOKEN` |
| Diligent One (HighBond) GRC | `diligent` | `DILIGENT_BASE_URL` *(url)*, `DILIGENT_TOKEN` |
| Diligent Boards governance/board management | `diligent_boards` | `DILIGENT_BOARDS_BASE_URL` *(url)*, `DILIGENT_BOARDS_TOKEN` |
| DingTalk enterprise messaging REST API (China, Alibaba) | `dingtalk` | `DINGTALK_BASE_URL` *(url)*, `DINGTALK_TOKEN` |
| Directus headless CMS REST API | `directus` | `DIRECTUS_BASE_URL` *(url)*, `DIRECTUS_TOKEN` |
| DISCO e-discovery/litigation | `disco_ediscovery` | `DISCO_EDISCOVERY_BASE_URL` *(url)*, `DISCO_EDISCOVERY_TOKEN` |
| Discourse forum REST API (self-hosted community platform) | `discourse` | `DISCOURSE_BASE_URL` *(url)*, `DISCOURSE_TOKEN` |
| Discover Bank | `discover_bank` | `DISCOVER_BANK_BASE_URL` *(url)*, `DISCOVER_BANK_TOKEN` |
| Divvy (BILL Spend & Expense) | `divvy` | `DIVVY_BASE_URL` *(url)*, `DIVVY_TOKEN` |
| dLocal payments REST API | `dlocal` | `DLOCAL_BASE_URL` *(url)*, `DLOCAL_TOKEN` |
| Docebo learning management | `docebo` | `DOCEBO_BASE_URL` *(url)*, `DOCEBO_TOKEN` |
| DocJuris CLM | `docjuris` | `DOCJURIS_BASE_URL` *(url)*, `DOCJURIS_TOKEN` |
| Docker Hub | `dockerhub` | `DOCKERHUB_BASE_URL` *(url)*, `DOCKERHUB_TOKEN` |
| Docket Alarm litigation analytics/docket | `docket_alarm` | `DOCKET_ALARM_BASE_URL` *(url)*, `DOCKET_ALARM_TOKEN` |
| Docketwise immigration case management | `docketwise` | `DOCKETWISE_BASE_URL` *(url)*, `DOCKETWISE_TOKEN` |
| DocSend (Dropbox) | `docsend` | `DOCSEND_BASE_URL` *(url)*, `DOCSEND_TOKEN` |
| Documill contract automation | `documill` | `DOCUMILL_BASE_URL` *(url)*, `DOCUMILL_TOKEN` |
| DocuSign eSignature | `docusign` | `DOCUSIGN_BASE_URL` *(url)*, `DOCUSIGN_TOKEN` |
| DocuWare document management | `docuware` | `DOCUWARE_BASE_URL` *(url)*, `DOCUWARE_TOKEN` |
| DOKU payment gateway REST API (Indonesia) | `doku` | `DOKU_BASE_URL` *(url)*, `DOKU_TOKEN` |
| Domo | `domo` | `DOMO_BASE_URL` *(url)*, `DOMO_TOKEN` |
| Donorbox | `donorbox` | `DONORBOX_BASE_URL` *(url)*, `DONORBOX_TOKEN` |
| DonorDock nonprofit CRM | `donordock` | `DONORDOCK_BASE_URL` *(url)*, `DONORDOCK_TOKEN` |
| DonorPerfect | `donorperfect` | `DONORPERFECT_BASE_URL` *(url)*, `DONORPERFECT_TOKEN` |
| DonorSearch wealth screening | `donorsearch` | `DONORSEARCH_BASE_URL` *(url)*, `DONORSEARCH_TOKEN` |
| DonorSnap | `donorsnap` | `DONORSNAP_BASE_URL` *(url)*, `DONORSNAP_TOKEN` |
| DoNotPay consumer legal automation | `donotpay` | `DONOTPAY_BASE_URL` *(url)*, `DONOTPAY_TOKEN` |
| Doodle scheduling | `doodle` | `DOODLE_BASE_URL` *(url)*, `DOODLE_TOKEN` |
| DoorDash Drive/Marketplace | `doordash` | `DOORDASH_BASE_URL` *(url)*, `DOORDASH_TOKEN` |
| DoorLoop property management | `doorloop` | `DOORLOOP_BASE_URL` *(url)*, `DOORLOOP_TOKEN` |
| Doppler secrets-management REST API | `doppler` | `DOPPLER_BASE_URL` *(url)*, `DOPPLER_TOKEN` |
| Apache Doris REST API | `doris` | `DORIS_BASE_URL` *(url)*, `DORIS_TOKEN` |
| Dotloop real estate transaction management | `dotloop` | `DOTLOOP_BASE_URL` *(url)*, `DOTLOOP_TOKEN` |
| Double the Donation matching-gifts | `doublethedonation` | `DOUBLETHEDONATION_BASE_URL` *(url)*, `DOUBLETHEDONATION_TOKEN` |
| Dow Jones Risk & Compliance | `dow_jones_riskcenter` | `DOW_JONES_RISKCENTER_BASE_URL` *(url)*, `DOW_JONES_RISKCENTER_TOKEN` |
| Draftbase REST API (no-code web app builder) | `draftbase_no_code` | `DRAFTBASE_NO_CODE_BASE_URL` *(url)*, `DRAFTBASE_NO_CODE_TOKEN` |
| Draftbit REST API | `draftbit` | `DRAFTBIT_BASE_URL` *(url)*, `DRAFTBIT_TOKEN` |
| Drata REST (GRC/compliance) | `drata` | `DRATA_BASE_URL` *(url)*, `DRATA_TOKEN` |
| diagrams.net (draw.io) REST (self-hosted/Confluence app) | `drawio` | `DRAWIO_BASE_URL` *(url)*, `DRAWIO_TOKEN` |
| DrChrono EHR REST API | `drchrono` | `DRCHRONO_BASE_URL` *(url)*, `DRCHRONO_TOKEN` |
| DreamBox Learning | `dreambox` | `DREAMBOX_BASE_URL` *(url)*, `DREAMBOX_TOKEN` |
| Dreamstime stock media | `dreamstime` | `DREAMSTIME_BASE_URL` *(url)*, `DREAMSTIME_TOKEN` |
| Dremio REST API | `dremio` | `DREMIO_BASE_URL` *(url)*, `DREMIO_TOKEN` |
| Dribbble REST API | `dribbble` | `DRIBBBLE_BASE_URL` *(url)*, `DRIBBBLE_TOKEN` |
| Drift conversational marketing/chat | `drift` | `DRIFT_BASE_URL` *(url)*, `DRIFT_TOKEN` |
| Drip REST API | `drip` | `DRIP_BASE_URL` *(url)*, `DRIP_TOKEN` |
| DriveWealth brokerage-as-a-service | `drivewealth` | `DRIVEWEALTH_BASE_URL` *(url)*, `DRIVEWEALTH_TOKEN` |
| Drone CI REST API | `drone` | `DRONE_BASE_URL` *(url)*, `DRONE_TOKEN` |
| Dropbox Paper | `dropbox_paper` | `DROPBOX_PAPER_BASE_URL` *(url)*, `DROPBOX_PAPER_TOKEN` |
| Dropbox Sign e-signature REST (rebrand of HelloSign; distinct name entry) | `dropbox_sign` | `DROPBOX_SIGN_BASE_URL` *(url)*, `DROPBOX_SIGN_TOKEN` |
| Apache Druid REST API | `druid` | `DRUID_BASE_URL` *(url)*, `DRUID_TOKEN` |
| Drupal JSON:API | `drupal` | `DRUPAL_BASE_URL` *(url)*, `DRUPAL_TOKEN` |
| Duck Creek Technologies insurance-platform REST API | `duck_creek` | `DUCK_CREEK_BASE_URL` *(url)*, `DUCK_CREEK_TOKEN` |
| Duda website builder REST API | `duda` | `DUDA_BASE_URL` *(url)*, `DUDA_TOKEN` |
| Duetto hotel revenue-management REST API | `duetto` | `DUETTO_BASE_URL` *(url)*, `DUETTO_TOKEN` |
| Cisco Duo Admin | `duo` | `DUO_BASE_URL` *(url)*, `DUO_TOKEN` |
| Duro PLM | `duro_plm` | `DURO_PLM_BASE_URL` *(url)*, `DURO_PLM_TOKEN` |
| Dwolla ACH payments | `dwolla` | `DWOLLA_BASE_URL` *(url)*, `DWOLLA_TOKEN` |
| Dynalist | `dynalist` | `DYNALIST_BASE_URL` *(url)*, `DYNALIST_TOKEN` |
| Microsoft Dynamics 365 | `dynamics` | `DYNAMICS_RESOURCE_URL` *(url)*, `DYNAMICS_TOKEN`, `DYNAMICS_API_VERSION` *(url)* |
| Microsoft Dynamics 365 Field Service | `dynamics_fsm` | `DYNAMICS_FSM_BASE_URL` *(url)*, `DYNAMICS_FSM_TOKEN` |
| Dynamic Yield REST API (personalization) | `dynamicyield` | `DYNAMICYIELD_BASE_URL` *(url)*, `DYNAMICYIELD_TOKEN` |
| Dynatrace | `dynatrace` | `DYNATRACE_BASE_URL` *(url)*, `DYNATRACE_TOKEN` |
| Shoptech E2 Shop System | `e2_shop_system` | `E2_SHOP_SYSTEM_BASE_URL` *(url)*, `E2_SHOP_SYSTEM_TOKEN` |
| E2open supply-chain management | `e2open` | `E2OPEN_BASE_URL` *(url)*, `E2OPEN_TOKEN` |
| EAB Navigate student-success/advising | `eab_navigate` | `EAB_NAVIGATE_BASE_URL` *(url)*, `EAB_NAVIGATE_TOKEN` |
| Ease benefits administration | `ease_benefits` | `EASE_BENEFITS_BASE_URL` *(url)*, `EASE_BENEFITS_TOKEN` |
| EasyPost shipping | `easypost` | `EASYPOST_BASE_URL` *(url)*, `EASYPOST_TOKEN` |
| Easy Projects | `easyprojects` | `EASYPROJECTS_BASE_URL` *(url)*, `EASYPROJECTS_TOKEN` |
| EasyVista Service Manager | `easyvista` | `EASYVISTA_BASE_URL` *(url)*, `EASYVISTA_TOKEN` |
| Eat App reservations | `eat_app` | `EAT_APP_BASE_URL` *(url)*, `EAT_APP_TOKEN` |
| EBANX payments REST API | `ebanx` | `EBANX_BASE_URL` *(url)*, `EBANX_TOKEN` |
| eBay REST API (Sell/Buy platform) | `ebay` | `EBAY_BASE_URL` *(url)*, `EBAY_TOKEN` |
| Ebix insurance exchange/agency platform | `ebix` | `EBIX_BASE_URL` *(url)*, `EBIX_TOKEN` |
| e-Builder (Trimble) capital program management | `ebuilder` | `EBUILDER_BASE_URL` *(url)*, `EBUILDER_TOKEN` |
| eCivis grants management | `ecivis` | `ECIVIS_BASE_URL` *(url)*, `ECIVIS_TOKEN` |
| eClinicalWorks EHR REST/FHIR API | `eclinicalworks` | `ECLINICALWORKS_BASE_URL` *(url)*, `ECLINICALWORKS_TOKEN` |
| Ecwid REST API | `ecwid` | `ECWID_BASE_URL` *(url)*, `ECWID_TOKEN` |
| Edgescan Fullstack Vulnerability Management | `edgescan` | `EDGESCAN_BASE_URL` *(url)*, `EDGESCAN_TOKEN` |
| Edmentum online curriculum REST API | `edmentum` | `EDMENTUM_BASE_URL` *(url)*, `EDMENTUM_TOKEN` |
| Edulastic assessment | `edulastic` | `EDULASTIC_BASE_URL` *(url)*, `EDULASTIC_TOKEN` |
| Open edX REST API | `edx` | `EDX_BASE_URL` *(url)*, `EDX_TOKEN` |
| eFax | `efax` | `EFAX_BASE_URL` *(url)*, `EFAX_TOKEN` |
| Efficy CRM REST API (Belgium/France) | `efficy_crm` | `EFFICY_CRM_BASE_URL` *(url)*, `EFFICY_CRM_TOKEN` |
| Egnyte content/document | `egnyte` | `EGNYTE_BASE_URL` *(url)*, `EGNYTE_TOKEN` |
| 8x8 contact center/CPaaS | `eightx8` | `EIGHTX8_BASE_URL` *(url)*, `EIGHTX8_TOKEN` |
| Elastic Path (Moltin) commerce | `elastic_path` | `ELASTIC_PATH_BASE_URL` *(url)*, `ELASTIC_PATH_TOKEN` |
| Elasticsearch | `elasticsearch` | `ES_URL` *(url)*, `ES_API_KEY` |
| Elasticsearch/Elastic Cloud vector search REST API (dense_vector/kNN) | `elasticsearch_vector` | `ELASTICSEARCH_VECTOR_BASE_URL` *(url)*, `ELASTICSEARCH_VECTOR_TOKEN` |
| Elation Health EHR REST API | `elation_health` | `ELATION_HEALTH_BASE_URL` *(url)*, `ELATION_HEALTH_TOKEN` |
| Element/Matrix client-server | `element_im` | `ELEMENT_IM_BASE_URL` *(url)*, `ELEMENT_IM_TOKEN` |
| ElevenLabs REST API | `elevenlabs` | `ELEVENLABS_BASE_URL` *(url)*, `ELEVENLABS_TOKEN` |
| Ellucian Ethos Integration REST (Banner/Colleague) | `ellucian` | `ELLUCIAN_BASE_URL` *(url)*, `ELLUCIAN_TOKEN` |
| Oracle Eloqua REST API | `eloqua` | `ELOQUA_BASE_URL` *(url)*, `ELOQUA_TOKEN` |
| EmailOctopus REST API | `emailoctopus` | `EMAILOCTOPUS_BASE_URL` *(url)*, `EMAILOCTOPUS_TOKEN` |
| eMaint (Fluke) CMMS | `emaint` | `EMAINT_BASE_URL` *(url)*, `EMAINT_TOKEN` |
| Emburse Spend/Expense | `emburse` | `EMBURSE_BASE_URL` *(url)*, `EMBURSE_TOKEN` |
| EMnify IoT SIM connectivity REST API | `emnify` | `EMNIFY_BASE_URL` *(url)*, `EMNIFY_TOKEN` |
| Employee Navigator benefits administration | `employee_navigator` | `EMPLOYEE_NAVIGATOR_BASE_URL` *(url)*, `EMPLOYEE_NAVIGATOR_TOKEN` |
| Employment Hero HR/payroll | `employment_hero` | `EMPLOYMENT_HERO_BASE_URL` *(url)*, `EMPLOYMENT_HERO_TOKEN` |
| Empower (Personal Capital) wealth | `empower_personal` | `EMPOWER_PERSONAL_BASE_URL` *(url)*, `EMPOWER_PERSONAL_TOKEN` |
| Engati chatbot/conversational AI REST API | `engati` | `ENGATI_BASE_URL` *(url)*, `ENGATI_TOKEN` |
| Dassault Systemes ENOVIA PLM | `enovia` | `ENOVIA_BASE_URL` *(url)*, `ENOVIA_TOKEN` |
| Enphase Energy solar-monitoring REST API | `enphase` | `ENPHASE_BASE_URL` *(url)*, `ENPHASE_TOKEN` |
| Microsoft Entra ID (Azure AD) Graph | `entra_id` | `ENTRA_ID_BASE_URL` *(url)*, `ENTRA_ID_TOKEN` |
| Entrata property management REST/JSON-RPC API | `entrata` | `ENTRATA_BASE_URL` *(url)*, `ENTRATA_TOKEN` |
| Envato Elements creative assets | `envato_elements` | `ENVATO_ELEMENTS_BASE_URL` *(url)*, `ENVATO_ELEMENTS_TOKEN` |
| Envato Market (GraphicRiver/VideoHive/AudioJungle) | `envato_market` | `ENVATO_MARKET_BASE_URL` *(url)*, `ENVATO_MARKET_TOKEN` |
| Epic on FHIR REST API for EHR data | `epic_fhir` | `EPIC_FHIR_BASE_URL` *(url)*, `EPIC_FHIR_TOKEN` |
| Epic Games / Epic Online Services REST API | `epicgames` | `EPICGAMES_BASE_URL` *(url)*, `EPICGAMES_TOKEN` |
| Epicor ERP | `epicor` | `EPICOR_BASE_URL` *(url)*, `EPICOR_TOKEN` |
| Epidemic Sound music licensing | `epidemic_sound` | `EPIDEMIC_SOUND_BASE_URL` *(url)*, `EPIDEMIC_SOUND_TOKEN` |
| Epos Now POS REST API | `epos_now` | `EPOS_NOW_BASE_URL` *(url)*, `EPOS_NOW_TOKEN` |
| Equinix Metal (bare-metal cloud) REST API | `equinix_metal` | `EQUINIX_METAL_BASE_URL` *(url)*, `EQUINIX_METAL_TOKEN` |
| Erply POS/retail-management REST API | `erply` | `ERPLY_BASE_URL` *(url)*, `ERPLY_TOKEN` |
| Esendex messaging REST API | `esendex` | `ESENDEX_BASE_URL` *(url)*, `ESENDEX_TOKEN` |
| ESET PROTECT | `eset` | `ESET_BASE_URL` *(url)*, `ESET_TOKEN` |
| eSign Genie | `esigngenie` | `ESIGNGENIE_BASE_URL` *(url)*, `ESIGNGENIE_TOKEN` |
| EspoCRM REST (self-hosted) | `espocrm` | `ESPOCRM_BASE_URL` *(url)*, `ESPOCRM_TOKEN` |
| Estuary Flow REST API | `estuary` | `ESTUARY_BASE_URL` *(url)*, `ESTUARY_TOKEN` |
| eSUB subcontractor project management | `esub` | `ESUB_BASE_URL` *(url)*, `ESUB_TOKEN` |
| Blackbaud eTapestry | `etapestry` | `ETAPESTRY_BASE_URL` *(url)*, `ETAPESTRY_TOKEN` |
| Etherscan blockchain explorer | `etherscan` | `ETHERSCAN_BASE_URL` *(url)*, `ETHERSCAN_TOKEN` |
| Etleap ETL REST API | `etleap` | `ETLEAP_BASE_URL` *(url)*, `ETLEAP_TOKEN` |
| ETQ Reliance quality management | `etq_reliance` | `ETQ_RELIANCE_BASE_URL` *(url)*, `ETQ_RELIANCE_TOKEN` |
| E*TRADE brokerage | `etrade` | `ETRADE_BASE_URL` *(url)*, `ETRADE_TOKEN` |
| Etsy Open API v3 | `etsy` | `ETSY_BASE_URL` *(url)*, `ETSY_TOKEN` |
| Eventbrite | `eventbrite` | `EVENTBRITE_BASE_URL` *(url)*, `EVENTBRITE_TOKEN` |
| Eventzilla | `eventzilla` | `EVENTZILLA_BASE_URL` *(url)*, `EVENTZILLA_TOKEN` |
| Everlaw e-discovery/litigation | `everlaw` | `EVERLAW_BASE_URL` *(url)*, `EVERLAW_TOKEN` |
| Evernote | `evernote` | `EVERNOTE_BASE_URL` *(url)*, `EVERNOTE_TOKEN` |
| eversign | `eversign` | `EVERSIGN_BASE_URL` *(url)*, `EVERSIGN_TOKEN` |
| EverTrue alumni/advancement CRM | `evertrue` | `EVERTRUE_BASE_URL` *(url)*, `EVERTRUE_TOKEN` |
| EverWebinar automated webinar | `everwebinar` | `EVERWEBINAR_BASE_URL` *(url)*, `EVERWEBINAR_TOKEN` |
| EveryAction / NGP VAN | `everyaction` | `EVERYACTION_BASE_URL` *(url)*, `EVERYACTION_TOKEN` |
| Evisort CLM | `evisort` | `EVISORT_BASE_URL` *(url)*, `EVISORT_TOKEN` |
| Exabeam Security Operations Platform | `exabeam` | `EXABEAM_BASE_URL` *(url)*, `EXABEAM_TOKEN` |
| Exact Online ERP/accounting REST API (Netherlands/Belgium) | `exact_online` | `EXACT_ONLINE_BASE_URL` *(url)*, `EXACT_ONLINE_TOKEN` |
| ExakTime construction time/attendance tracking | `exaktime` | `EXAKTIME_BASE_URL` *(url)*, `EXAKTIME_TOKEN` |
| Exasol REST/WebSocket API | `exasol` | `EXASOL_BASE_URL` *(url)*, `EXASOL_TOKEN` |
| ExecVision conversation intelligence | `execvision` | `EXECVISION_BASE_URL` *(url)*, `EXECVISION_TOKEN` |
| Exercise.com | `exercise_com` | `EXERCISE_COM_BASE_URL` *(url)*, `EXERCISE_COM_TOKEN` |
| Exoscale Cloud REST API | `exoscale` | `EXOSCALE_BASE_URL` *(url)*, `EXOSCALE_TOKEN` |
| Exotel contact center | `exotel` | `EXOTEL_BASE_URL` *(url)*, `EXOTEL_TOKEN` |
| Expedia Partner Solutions (Rapid) REST API for bookings | `expedia` | `EXPEDIA_BASE_URL` *(url)*, `EXPEDIA_TOKEN` |
| Expel MDR Workbench | `expel` | `EXPEL_BASE_URL` *(url)*, `EXPEL_TOKEN` |
| ExpenseWatch expense management | `expensewatch` | `EXPENSEWATCH_BASE_URL` *(url)*, `EXPENSEWATCH_TOKEN` |
| Expensify expense management | `expensify` | `EXPENSIFY_BASE_URL` *(url)*, `EXPENSIFY_TOKEN` |
| Exposure Events | `exposure_events` | `EXPOSURE_EVENTS_BASE_URL` *(url)*, `EXPOSURE_EVENTS_TOKEN` |
| Extensiv (3PL Warehouse Manager) REST API | `extensiv` | `EXTENSIV_BASE_URL` *(url)*, `EXTENSIV_TOKEN` |
| Exterro e-discovery/legal GRC | `exterro` | `EXTERRO_BASE_URL` *(url)*, `EXTERRO_TOKEN` |
| ExtraHop Reveal(x) | `extrahop` | `EXTRAHOP_BASE_URL` *(url)*, `EXTRAHOP_TOKEN` |
| EZLynx insurance-agency-management REST API | `ezlynx` | `EZLYNX_BASE_URL` *(url)*, `EZLYNX_TOKEN` |
| EZ Texting REST API (SMS marketing) | `eztexting` | `EZTEXTING_BASE_URL` *(url)*, `EZTEXTING_TOKEN` |
| F5 BIG-IP/Distributed Cloud | `f5` | `F5_BASE_URL` *(url)*, `F5_TOKEN` |
| Facebook Graph API | `facebook` | `FACEBOOK_BASE_URL` *(url)*, `FACEBOOK_TOKEN` |
| FACEIT REST API (esports platform) | `faceit` | `FACEIT_BASE_URL` *(url)*, `FACEIT_TOKEN` |
| Factorial HR | `factorial_hr` | `FACTORIAL_HR_BASE_URL` *(url)*, `FACTORIAL_HR_TOKEN` |
| Aegis FactoryLogix MES | `factorylogix` | `FACTORYLOGIX_BASE_URL` *(url)*, `FACTORYLOGIX_TOKEN` |
| Rockwell FactoryTalk Cloud | `factorytalk` | `FACTORYTALK_BASE_URL` *(url)*, `FACTORYTALK_TOKEN` |
| FACTS SIS (RenWeb, Nelnet) | `facts_sis` | `FACTS_SIS_BASE_URL` *(url)*, `FACTS_SIS_TOKEN` |
| Facturama e-invoicing REST API (Mexico) | `facturama` | `FACTURAMA_BASE_URL` *(url)*, `FACTURAMA_TOKEN` |
| Faire wholesale marketplace REST API | `faire` | `FAIRE_BASE_URL` *(url)*, `FAIRE_TOKEN` |
| fal.ai REST API | `fal_ai` | `FAL_AI_BASE_URL` *(url)*, `FAL_AI_TOKEN` |
| Falkonry predictive industrial analytics | `falkonry` | `FALKONRY_BASE_URL` *(url)*, `FALKONRY_TOKEN` |
| Fastcase legal research | `fastcase` | `FASTCASE_BASE_URL` *(url)*, `FASTCASE_TOKEN` |
| Fastly | `fastly` | `FASTLY_BASE_URL` *(url)*, `FASTLY_TOKEN` |
| FastSpring commerce/billing REST API | `fastspring` | `FASTSPRING_BASE_URL` *(url)*, `FASTSPRING_TOKEN` |
| Fathom financial reporting/analysis | `fathom_analytics_fin` | `FATHOM_ANALYTICS_FIN_BASE_URL` *(url)*, `FATHOM_ANALYTICS_FIN_TOKEN` |
| Fathom video meeting | `fathom_video` | `FATHOM_VIDEO_BASE_URL` *(url)*, `FATHOM_VIDEO_TOKEN` |
| Fauna database REST/FQL API | `fauna` | `FAUNA_BASE_URL` *(url)*, `FAUNA_TOKEN` |
| Fauna REST/GraphQL API | `faunadb` | `FAUNADB_BASE_URL` *(url)*, `FAUNADB_TOKEN` |
| Favro | `favro` | `FAVRO_BASE_URL` *(url)*, `FAVRO_TOKEN` |
| Fawry payments REST API (Egypt) | `fawry` | `FAWRY_BASE_URL` *(url)*, `FAWRY_TOKEN` |
| Featurespace fraud/AML detection | `featurespace` | `FEATURESPACE_BASE_URL` *(url)*, `FEATURESPACE_TOKEN` |
| Feedier | `feedier` | `FEEDIER_BASE_URL` *(url)*, `FEEDIER_TOKEN` |
| Feishu/Lark collaboration REST API (China, ByteDance) | `feishu` | `FEISHU_BASE_URL` *(url)*, `FEISHU_TOKEN` |
| Fellow.app meeting notes | `fellow_app` | `FELLOW_APP_BASE_URL` *(url)*, `FELLOW_APP_TOKEN` |
| Fergus job management for trades | `fergus` | `FERGUS_BASE_URL` *(url)*, `FERGUS_TOKEN` |
| Fidelity investments | `fidelity` | `FIDELITY_BASE_URL` *(url)*, `FIDELITY_TOKEN` |
| FieldAware field service management | `fieldaware` | `FIELDAWARE_BASE_URL` *(url)*, `FIELDAWARE_TOKEN` |
| FieldEdge field service management | `fieldedge` | `FIELDEDGE_BASE_URL` *(url)*, `FIELDEDGE_TOKEN` |
| Fieldpoint field service management | `fieldpoint` | `FIELDPOINT_BASE_URL` *(url)*, `FIELDPOINT_TOKEN` |
| Fieldwire construction field management | `fieldwire` | `FIELDWIRE_BASE_URL` *(url)*, `FIELDWIRE_TOKEN` |
| Figma | `figma` | `FIGMA_BASE_URL` *(url)*, `FIGMA_TOKEN` |
| Fiix CMMS (Rockwell) | `fiix_cmms` | `FIIX_CMMS_BASE_URL` *(url)*, `FIIX_CMMS_TOKEN` |
| FileCloud | `filecloud` | `FILECLOUD_BASE_URL` *(url)*, `FILECLOUD_TOKEN` |
| FileHold document management | `filehold` | `FILEHOLD_BASE_URL` *(url)*, `FILEHOLD_TOKEN` |
| Filestack file/image processing | `filestack` | `FILESTACK_BASE_URL` *(url)*, `FILESTACK_TOKEN` |
| Filevine legal case management | `filevine` | `FILEVINE_BASE_URL` *(url)*, `FILEVINE_TOKEN` |
| Fillout Forms REST API | `fillout` | `FILLOUT_BASE_URL` *(url)*, `FILLOUT_TOKEN` |
| Final Surge | `final_surge` | `FINAL_SURGE_BASE_URL` *(url)*, `FINAL_SURGE_TOKEN` |
| Blackbaud Financial Edge NXT REST (SKY API) | `financial_edge` | `FINANCIAL_EDGE_BASE_URL` *(url)*, `FINANCIAL_EDGE_TOKEN` |
| Finch unified HR/payroll API | `finch_hr` | `FINCH_HR_BASE_URL` *(url)*, `FINCH_HR_TOKEN` |
| FindMyShift | `findmyshift` | `FINDMYSHIFT_BASE_URL` *(url)*, `FINDMYSHIFT_TOKEN` |
| FINEOS life/group/absence insurance core | `fineos` | `FINEOS_BASE_URL` *(url)*, `FINEOS_TOKEN` |
| Finicity (Mastercard) open banking | `finicity` | `FINICITY_BASE_URL` *(url)*, `FINICITY_TOKEN` |
| Firebase (Google) REST API | `firebase` | `FIREBASE_BASE_URL` *(url)*, `FIREBASE_TOKEN` |
| Fireblocks custody | `fireblocks` | `FIREBLOCKS_BASE_URL` *(url)*, `FIREBLOCKS_TOKEN` |
| Firebolt cloud data warehouse REST API | `firebolt` | `FIREBOLT_BASE_URL` *(url)*, `FIREBOLT_TOKEN` |
| Fireflies.ai meeting-notes REST/GraphQL | `fireflies` | `FIREFLIES_BASE_URL` *(url)*, `FIREFLIES_TOKEN` |
| FireHydrant incident-management REST API | `firehydrant` | `FIREHYDRANT_BASE_URL` *(url)*, `FIREHYDRANT_TOKEN` |
| Fireside.fm podcast hosting | `fireside_fm` | `FIRESIDE_FM_BASE_URL` *(url)*, `FIRESIDE_FM_TOKEN` |
| Firespring nonprofit website/donor tools | `firespring` | `FIRESPRING_BASE_URL` *(url)*, `FIRESPRING_TOKEN` |
| Fireworks AI REST API | `fireworks_ai` | `FIREWORKS_AI_BASE_URL` *(url)*, `FIREWORKS_AI_TOKEN` |
| FIS Global banking/payments | `fis_global` | `FIS_GLOBAL_BASE_URL` *(url)*, `FIS_GLOBAL_TOKEN` |
| Fiserv (Commerce Hub) payments REST API | `fiserv` | `FISERV_BASE_URL` *(url)*, `FISERV_TOKEN` |
| Fishbowl Inventory REST API | `fishbowl_inventory` | `FISHBOWL_INVENTORY_BASE_URL` *(url)*, `FISHBOWL_INVENTORY_TOKEN` |
| Fitbit Web API | `fitbit` | `FITBIT_BASE_URL` *(url)*, `FITBIT_TOKEN` |
| Five9 | `five9` | `FIVE9_BASE_URL` *(url)*, `FIVE9_TOKEN` |
| Fivestars loyalty | `fivestars` | `FIVESTARS_BASE_URL` *(url)*, `FIVESTARS_TOKEN` |
| Fivetran | `fivetran` | `FIVETRAN_BASE_URL` *(url)*, `FIVETRAN_TOKEN` |
| Flagsmith feature-flag REST API | `flagsmith` | `FLAGSMITH_BASE_URL` *(url)*, `FLAGSMITH_TOKEN` |
| Fleetio fleet-maintenance REST API | `fleetio` | `FLEETIO_BASE_URL` *(url)*, `FLEETIO_TOKEN` |
| Flexe warehousing/fulfillment REST API | `flexe` | `FLEXE_BASE_URL` *(url)*, `FLEXE_TOKEN` |
| Flexmls (FBS) MLS system | `flexmls` | `FLEXMLS_BASE_URL` *(url)*, `FLEXMLS_TOKEN` |
| Flexport freight / logistics | `flexport` | `FLEXPORT_BASE_URL` *(url)*, `FLEXPORT_TOKEN` |
| Flickr REST API | `flickr` | `FLICKR_BASE_URL` *(url)*, `FLICKR_TOKEN` |
| Flinks open-banking | `flinks` | `FLINKS_BASE_URL` *(url)*, `FLINKS_TOKEN` |
| Flipdish ordering | `flipdish` | `FLIPDISH_BASE_URL` *(url)*, `FLIPDISH_TOKEN` |
| Flipkart Seller/Marketplace REST API | `flipkart` | `FLIPKART_BASE_URL` *(url)*, `FLIPKART_TOKEN` |
| Flipsnack digital flipbook publishing | `flipsnack` | `FLIPSNACK_BASE_URL` *(url)*, `FLIPSNACK_TOKEN` |
| FlixBus travel partner REST API (Germany) | `flixbus` | `FLIXBUS_BASE_URL` *(url)*, `FLIXBUS_TOKEN` |
| Flock team chat | `flock` | `FLOCK_BASE_URL` *(url)*, `FLOCK_TOKEN` |
| FloQast close & reconciliation | `floqast` | `FLOQAST_BASE_URL` *(url)*, `FLOQAST_TOKEN` |
| Flow XO chatbot automation REST API | `flow_xo` | `FLOW_XO_BASE_URL` *(url)*, `FLOW_XO_TOKEN` |
| Flowise REST API (LLM flow builder) | `flowise_ai` | `FLOWISE_AI_BASE_URL` *(url)*, `FLOWISE_AI_TOKEN` |
| Flowlu | `flowlu` | `FLOWLU_BASE_URL` *(url)*, `FLOWLU_TOKEN` |
| Flowroute SMS/voice REST API | `flowroute` | `FLOWROUTE_BASE_URL` *(url)*, `FLOWROUTE_TOKEN` |
| FloydHub REST API (ML model training platform) | `floydhub` | `FLOYDHUB_BASE_URL` *(url)*, `FLOYDHUB_TOKEN` |
| FlutterFlow REST API | `flutterflow` | `FLUTTERFLOW_BASE_URL` *(url)*, `FLUTTERFLOW_TOKEN` |
| Flutterwave payments REST API | `flutterwave` | `FLUTTERWAVE_BASE_URL` *(url)*, `FLUTTERWAVE_TOKEN` |
| Fluxx Grantmaker | `fluxx` | `FLUXX_BASE_URL` *(url)*, `FLUXX_TOKEN` |
| Fly.io Machines REST API | `fly_io` | `FLY_IO_BASE_URL` *(url)*, `FLY_IO_TOKEN` |
| Focus POS | `focus_pos` | `FOCUS_POS_BASE_URL` *(url)*, `FOCUS_POS_TOKEN` |
| FogHorn Systems edge intelligence | `foghorn` | `FOGHORN_BASE_URL` *(url)*, `FOGHORN_TOKEN` |
| Follow Up Boss (real estate CRM) | `followupboss` | `FOLLOWUPBOSS_BASE_URL` *(url)*, `FOLLOWUPBOSS_TOKEN` |
| Fonoa tax-automation REST API | `fonoa` | `FONOA_BASE_URL` *(url)*, `FONOA_TOKEN` |
| foodpanda (Delivery Hero) | `foodpanda` | `FOODPANDA_BASE_URL` *(url)*, `FOODPANDA_TOKEN` |
| Forethought AI customer support | `forethought` | `FORETHOUGHT_BASE_URL` *(url)*, `FORETHOUGHT_TOKEN` |
| ForgeRock Identity Platform | `forgerock` | `FORGEROCK_BASE_URL` *(url)*, `FORGEROCK_TOKEN` |
| FormAssembly | `formassembly` | `FORMASSEMBLY_BASE_URL` *(url)*, `FORMASSEMBLY_TOKEN` |
| Formsite | `formsite` | `FORMSITE_BASE_URL` *(url)*, `FORMSITE_TOKEN` |
| Formstack REST API | `formstack` | `FORMSTACK_BASE_URL` *(url)*, `FORMSTACK_TOKEN` |
| Forsta (Confirmit/FocusVision) survey | `forsta` | `FORSTA_BASE_URL` *(url)*, `FORSTA_TOKEN` |
| Forter fraud prevention | `forter` | `FORTER_BASE_URL` *(url)*, `FORTER_TOKEN` |
| OpenText Fortify on Demand | `fortify` | `FORTIFY_BASE_URL` *(url)*, `FORTIFY_TOKEN` |
| Fortinet FortiGate/FortiManager | `fortinet` | `FORTINET_BASE_URL` *(url)*, `FORTINET_TOKEN` |
| Fortnox accounting REST API (Sweden) | `fortnox` | `FORTNOX_BASE_URL` *(url)*, `FORTNOX_TOKEN` |
| FOSSA license/SCA REST API | `fossa` | `FOSSA_BASE_URL` *(url)*, `FOSSA_TOKEN` |
| Fotor photo editing | `fotor` | `FOTOR_BASE_URL` *(url)*, `FOTOR_TOKEN` |
| Foundant Technologies Grants Lifecycle Manager (GLM) | `foundant` | `FOUNDANT_BASE_URL` *(url)*, `FOUNDANT_TOKEN` |
| Fountain high-volume hiring | `fountain_ats` | `FOUNTAIN_ATS_BASE_URL` *(url)*, `FOUNTAIN_ATS_TOKEN` |
| FourKites supply-chain visibility REST API | `fourkites` | `FOURKITES_BASE_URL` *(url)*, `FOURKITES_TOKEN` |
| Fracttal One CMMS | `fracttal` | `FRACTTAL_BASE_URL` *(url)*, `FRACTTAL_TOKEN` |
| Frame.io (Adobe) REST API | `frameio` | `FRAMEIO_BASE_URL` *(url)*, `FRAMEIO_TOKEN` |
| Framer REST API | `framer` | `FRAMER_BASE_URL` *(url)*, `FRAMER_TOKEN` |
| FreeAgent accounting | `freeagent` | `FREEAGENT_BASE_URL` *(url)*, `FREEAGENT_TOKEN` |
| Freedcamp | `freedcamp` | `FREEDCAMP_BASE_URL` *(url)*, `FREEDCAMP_TOKEN` |
| freee accounting REST API (Japan) | `freee` | `FREEE_BASE_URL` *(url)*, `FREEE_TOKEN` |
| Freepik stock graphics | `freepik` | `FREEPIK_BASE_URL` *(url)*, `FREEPIK_TOKEN` |
| Freightos freight-rate REST API | `freightos` | `FREIGHTOS_BASE_URL` *(url)*, `FREIGHTOS_TOKEN` |
| Fresha booking | `fresha` | `FRESHA_BASE_URL` *(url)*, `FRESHA_TOKEN` |
| Fresha payments/invoicing | `fresha_pay` | `FRESHA_PAY_BASE_URL` *(url)*, `FRESHA_PAY_TOKEN` |
| FreshBooks accounting | `freshbooks` | `FRESHBOOKS_BASE_URL` *(url)*, `FRESHBOOKS_TOKEN` |
| Freshcaller (Freshworks contact center) | `freshcaller` | `FRESHCALLER_BASE_URL` *(url)*, `FRESHCALLER_TOKEN` |
| Freshchat (Freshworks) messaging REST API | `freshchat` | `FRESHCHAT_BASE_URL` *(url)*, `FRESHCHAT_TOKEN` |
| Freshdesk | `freshdesk` | `FRESHDESK_BASE_URL` *(url)*, `FRESHDESK_TOKEN` |
| Freshsales (Freshworks CRM) | `freshsales` | `FRESHSALES_BASE_URL` *(url)*, `FRESHSALES_TOKEN` |
| Freshservice ITSM | `freshservice` | `FRESHSERVICE_BASE_URL` *(url)*, `FRESHSERVICE_TOKEN` |
| Freshteam (Freshworks) HR/ATS | `freshteam` | `FRESHTEAM_BASE_URL` *(url)*, `FRESHTEAM_TOKEN` |
| Front REST (shared inbox) | `front` | `FRONT_BASE_URL` *(url)*, `FRONT_TOKEN` |
| Frontline Education (Central/Absence Management) | `frontline_education` | `FRONTLINE_EDUCATION_BASE_URL` *(url)*, `FRONTLINE_EDUCATION_TOKEN` |
| FRONTSTEPS community/HOA management | `frontsteps` | `FRONTSTEPS_BASE_URL` *(url)*, `FRONTSTEPS_TOKEN` |
| Fulcrum manufacturing operations platform | `fulcrum_mfg` | `FULCRUM_MFG_BASE_URL` *(url)*, `FULCRUM_MFG_TOKEN` |
| FullStory REST API | `fullstory` | `FULLSTORY_BASE_URL` *(url)*, `FULLSTORY_TOKEN` |
| Fundbox business financing | `fundbox` | `FUNDBOX_BASE_URL` *(url)*, `FUNDBOX_TOKEN` |
| Funding Circle lending | `funding_circle` | `FUNDING_CIRCLE_BASE_URL` *(url)*, `FUNDING_CIRCLE_TOKEN` |
| Fundly crowdfunding | `fundly` | `FUNDLY_BASE_URL` *(url)*, `FUNDLY_TOKEN` |
| FundraiseUp | `fundraiseup` | `FUNDRAISEUP_BASE_URL` *(url)*, `FUNDRAISEUP_TOKEN` |
| Funnel.io marketing data REST API | `funnelio` | `FUNNELIO_BASE_URL` *(url)*, `FUNNELIO_TOKEN` |
| Funraise | `funraise` | `FUNRAISE_BASE_URL` *(url)*, `FUNRAISE_TOKEN` |
| Autodesk Fusion Manage (Fusion Lifecycle) PLM | `fusion_lifecycle` | `FUSION_LIFECYCLE_BASE_URL` *(url)*, `FUSION_LIFECYCLE_TOKEN` |
| Fyle expense management | `fyle` | `FYLE_BASE_URL` *(url)*, `FYLE_TOKEN` |
| Google Analytics 4 | `ga4` | `GA4_PROPERTY_ID` *(url)*, `GA4_MEASUREMENT_ID` *(url)*, `GA4_ACCESS_TOKEN`, `GA4_API_SECRET` |
| Gainsight | `gainsight` | `GAINSIGHT_BASE_URL` *(url)*, `GAINSIGHT_TOKEN` |
| Galaxy Digital (Get Connected) volunteer management | `galaxydigital` | `GALAXYDIGITAL_BASE_URL` *(url)*, `GALAXYDIGITAL_TOKEN` |
| Galileo AI REST API (LLM observability/eval) | `galileo_ai` | `GALILEO_AI_BASE_URL` *(url)*, `GALILEO_AI_TOKEN` |
| Galileo Financial Solutions card processing | `galileo_fs` | `GALILEO_FS_BASE_URL` *(url)*, `GALILEO_FS_TOKEN` |
| Diligent (Galvanize/HighBond) GRC | `galvanize_grc` | `GALVANIZE_GRC_BASE_URL` *(url)*, `GALVANIZE_GRC_TOKEN` |
| Game Jolt REST API | `gamejolt` | `GAMEJOLT_BASE_URL` *(url)*, `GAMEJOLT_TOKEN` |
| GanttPRO | `ganttpro` | `GANTTPRO_BASE_URL` *(url)*, `GANTTPRO_TOKEN` |
| Garmin Connect/Health | `garmin_connect` | `GARMIN_CONNECT_BASE_URL` *(url)*, `GARMIN_CONNECT_TOKEN` |
| Gate.io exchange | `gate_io` | `GATE_IO_BASE_URL` *(url)*, `GATE_IO_TOKEN` |
| GateKeeper contract management | `gatekeeper_clm` | `GATEKEEPER_CLM_BASE_URL` *(url)*, `GATEKEEPER_CLM_TOKEN` |
| Gather (gather.town) virtual space | `gathertown` | `GATHERTOWN_BASE_URL` *(url)*, `GATHERTOWN_TOKEN` |
| Google Cloud REST (Compute/Resource Manager/...) | `gcp` | `GCP_BASE_URL` *(url)*, `GCP_TOKEN` |
| GCPay (Procore) construction payment applications | `gcpay` | `GCPAY_BASE_URL` *(url)*, `GCPAY_TOKEN` |
| Geckoboard REST API | `geckoboard` | `GECKOBOARD_BASE_URL` *(url)*, `GECKOBOARD_TOKEN` |
| Geidea payments REST API (Saudi Arabia) | `geidea` | `GEIDEA_BASE_URL` *(url)*, `GEIDEA_TOKEN` |
| Gemfury package registry REST API | `gemfury` | `GEMFURY_BASE_URL` *(url)*, `GEMFURY_TOKEN` |
| Gemini crypto exchange | `gemini_exchange` | `GEMINI_EXCHANGE_BASE_URL` *(url)*, `GEMINI_EXCHANGE_TOKEN` |
| Genbook scheduling | `genbook` | `GENBOOK_BASE_URL` *(url)*, `GENBOOK_TOKEN` |
| Genesys Cloud | `genesys` | `GENESYS_BASE_URL` *(url)*, `GENESYS_TOKEN` |
| Genially interactive content design | `genially` | `GENIALLY_BASE_URL` *(url)*, `GENIALLY_TOKEN` |
| Geotab fleet-telematics REST API (MyGeotab) | `geotab` | `GEOTAB_BASE_URL` *(url)*, `GEOTAB_TOKEN` |
| GetAccept | `getaccept` | `GETACCEPT_BASE_URL` *(url)*, `GETACCEPT_TOKEN` |
| GetFeedback | `getfeedback` | `GETFEEDBACK_BASE_URL` *(url)*, `GETFEEDBACK_TOKEN` |
| GetInsured health exchange/enrollment | `getinsured` | `GETINSURED_BASE_URL` *(url)*, `GETINSURED_TOKEN` |
| Otter (getotter.com) order management | `getotter` | `GETOTTER_BASE_URL` *(url)*, `GETOTTER_TOKEN` |
| GetResponse REST API | `getresponse` | `GETRESPONSE_BASE_URL` *(url)*, `GETRESPONSE_TOKEN` |
| Getty Images REST API | `getty_images` | `GETTY_IMAGES_BASE_URL` *(url)*, `GETTY_IMAGES_TOKEN` |
| GetYourGuide activities partner REST API (Germany) | `getyourguide` | `GETYOURGUIDE_BASE_URL` *(url)*, `GETYOURGUIDE_TOKEN` |
| Ghost CMS Admin/Content REST API | `ghost` | `GHOST_BASE_URL` *(url)*, `GHOST_TOKEN` |
| Giant Bomb REST API (video game wiki/database) | `giantbomb` | `GIANTBOMB_BASE_URL` *(url)*, `GIANTBOMB_TOKEN` |
| GIPHY REST API | `giphy` | `GIPHY_BASE_URL` *(url)*, `GIPHY_TOKEN` |
| Gitea REST API | `gitea` | `GITEA_BASE_URL` *(url)*, `GITEA_TOKEN` |
| GitGuardian Secrets Detection | `gitguardian` | `GITGUARDIAN_BASE_URL` *(url)*, `GITGUARDIAN_TOKEN` |
| Gitpod REST API | `gitpod` | `GITPOD_BASE_URL` *(url)*, `GITPOD_TOKEN` |
| Givebutter | `givebutter` | `GIVEBUTTER_BASE_URL` *(url)*, `GIVEBUTTER_TOKEN` |
| GiveGab (Bonterra Volunteer) | `givegab` | `GIVEGAB_BASE_URL` *(url)*, `GIVEGAB_TOKEN` |
| GiveLively | `givelively` | `GIVELIVELY_BASE_URL` *(url)*, `GIVELIVELY_TOKEN` |
| GivePulse volunteer/civic engagement | `givepulse` | `GIVEPULSE_BASE_URL` *(url)*, `GIVEPULSE_TOKEN` |
| GiveSmart | `givesmart` | `GIVESMART_BASE_URL` *(url)*, `GIVESMART_TOKEN` |
| GiveWP (WordPress donation plugin) | `givewp` | `GIVEWP_BASE_URL` *(url)*, `GIVEWP_TOKEN` |
| Gladly | `gladly` | `GLADLY_BASE_URL` *(url)*, `GLADLY_TOKEN` |
| Glasscubes collaboration | `glasscubes` | `GLASSCUBES_BASE_URL` *(url)*, `GLASSCUBES_TOKEN` |
| Glean REST API (enterprise search/AI assistant) | `glean_search` | `GLEAN_SEARCH_BASE_URL` *(url)*, `GLEAN_SEARCH_TOKEN` |
| Glide Apps Tables | `glide_apps` | `GLIDE_APPS_BASE_URL` *(url)*, `GLIDE_APPS_TOKEN` |
| Gliffy diagramming | `gliffy` | `GLIFFY_BASE_URL` *(url)*, `GLIFFY_TOKEN` |
| Global Payments (GP-API) REST API | `global_payments` | `GLOBAL_PAYMENTS_BASE_URL` *(url)*, `GLOBAL_PAYMENTS_TOKEN` |
| Global Shop Solutions ERP/MES | `global_shop_solutions` | `GLOBAL_SHOP_SOLUTIONS_BASE_URL` *(url)*, `GLOBAL_SHOP_SOLUTIONS_TOKEN` |
| Glofox gym/studio management | `glofox` | `GLOFOX_BASE_URL` *(url)*, `GLOFOX_TOKEN` |
| GloriaFood ordering | `gloriafood` | `GLORIAFOOD_BASE_URL` *(url)*, `GLORIAFOOD_TOKEN` |
| Glovo | `glovo` | `GLOVO_BASE_URL` *(url)*, `GLOVO_TOKEN` |
| GoCardless bank-debit | `gocardless` | `GOCARDLESS_BASE_URL` *(url)*, `GOCARDLESS_TOKEN` |
| GoCD REST API | `gocd` | `GOCD_BASE_URL` *(url)*, `GOCD_TOKEN` |
| GoDaddy Websites + Marketing REST API | `godaddy_builder` | `GODADDY_BUILDER_BASE_URL` *(url)*, `GODADDY_BUILDER_TOKEN` |
| Gong revenue-intelligence | `gong` | `GONG_BASE_URL` *(url)*, `GONG_TOKEN` |
| GoodData Cloud REST/GraphQL | `gooddata` | `GOODDATA_BASE_URL` *(url)*, `GOODDATA_TOKEN` |
| GoodHire background check | `goodhire` | `GOODHIRE_BASE_URL` *(url)*, `GOODHIRE_TOKEN` |
| Google Calendar REST v3 | `google_calendar` | `GOOGLE_CALENDAR_BASE_URL` *(url)*, `GOOGLE_CALENDAR_TOKEN` |
| Google Chat | `google_chat` | `GOOGLE_CHAT_BASE_URL` *(url)*, `GOOGLE_CHAT_TOKEN` |
| Google Classroom REST API | `google_classroom` | `GOOGLE_CLASSROOM_BASE_URL` *(url)*, `GOOGLE_CLASSROOM_TOKEN` |
| Google Docs | `google_docs` | `GOOGLE_DOCS_BASE_URL` *(url)*, `GOOGLE_DOCS_TOKEN` |
| Google Forms | `google_forms` | `GOOGLE_FORMS_BASE_URL` *(url)*, `GOOGLE_FORMS_TOKEN` |
| Google Keep REST (via Google Workspace Keep API) | `google_keep` | `GOOGLE_KEEP_BASE_URL` *(url)*, `GOOGLE_KEEP_TOKEN` |
| Google Meet REST (via Google Workspace APIs) | `google_meet` | `GOOGLE_MEET_BASE_URL` *(url)*, `GOOGLE_MEET_TOKEN` |
| Google Sheets | `google_sheets` | `GOOGLE_SHEETS_BASE_URL` *(url)*, `GOOGLE_SHEETS_TOKEN` |
| Google Slides | `google_slides` | `GOOGLE_SLIDES_BASE_URL` *(url)*, `GOOGLE_SLIDES_TOKEN` |
| Google Cloud Vertex AI REST API | `google_vertex_ai` | `GOOGLE_VERTEX_AI_BASE_URL` *(url)*, `GOOGLE_VERTEX_AI_TOKEN` |
| Google Ads API | `googleads` | `GOOGLEADS_BASE_URL` *(url)*, `GOOGLEADS_TOKEN` |
| Gopuff | `gopuff` | `GOPUFF_BASE_URL` *(url)*, `GOPUFF_TOKEN` |
| Gorgias helpdesk | `gorgias` | `GORGIAS_BASE_URL` *(url)*, `GORGIAS_TOKEN` |
| Thomson Reuters GoSystem Tax RS REST (returns, e-file status, locators) | `gosystem_tax` | `GOSYSTEM_TAX_BASE_URL` *(url)*, `GOSYSTEM_TAX_TOKEN` |
| GoTo Meeting | `gotomeeting` | `GOTOMEETING_BASE_URL` *(url)*, `GOTOMEETING_TOKEN` |
| GoTo Webinar | `gotowebinar` | `GOTOWEBINAR_BASE_URL` *(url)*, `GOTOWEBINAR_TOKEN` |
| GovDelivery (Granicus) citizen communications | `govdelivery` | `GOVDELIVERY_BASE_URL` *(url)*, `GOVDELIVERY_TOKEN` |
| GovQA public-records request management | `govqa` | `GOVQA_BASE_URL` *(url)*, `GOVQA_TOKEN` |
| Grab superapp partner REST API (Singapore/SE Asia) | `grab` | `GRAB_BASE_URL` *(url)*, `GRAB_TOKEN` |
| Gradelink SIS | `gradelink` | `GRADELINK_BASE_URL` *(url)*, `GRADELINK_TOKEN` |
| Graduway alumni engagement | `graduway` | `GRADUWAY_BASE_URL` *(url)*, `GRADUWAY_TOKEN` |
| Grafana | `grafana` | `GRAFANA_BASE_URL` *(url)*, `GRAFANA_TOKEN` |
| Grain meeting recording | `grain` | `GRAIN_BASE_URL` *(url)*, `GRAIN_TOKEN` |
| Granicus government engagement | `granicus` | `GRANICUS_BASE_URL` *(url)*, `GRANICUS_TOKEN` |
| GrantHub grant tracking | `granthub` | `GRANTHUB_BASE_URL` *(url)*, `GRANTHUB_TOKEN` |
| Grants.gov federal grants | `grants_gov` | `GRANTS_GOV_BASE_URL` *(url)*, `GRANTS_GOV_TOKEN` |
| GrantWatch grant search | `grantwatch` | `GRANTWATCH_BASE_URL` *(url)*, `GRANTWATCH_TOKEN` |
| Granular (Corteva) farm-management REST API | `granular` | `GRANULAR_BASE_URL` *(url)*, `GRANULAR_TOKEN` |
| Grasshopper business phone | `grasshopper` | `GRASSHOPPER_BASE_URL` *(url)*, `GRASSHOPPER_TOKEN` |
| Grasshopper Bank business banking | `grasshopper_bank` | `GRASSHOPPER_BANK_BASE_URL` *(url)*, `GRASSHOPPER_BANK_TOKEN` |
| Gravity Forms (WordPress) | `gravity_forms` | `GRAVITY_FORMS_BASE_URL` *(url)*, `GRAVITY_FORMS_TOKEN` |
| Greater Giving events/auction | `greatergiving` | `GREATERGIVING_BASE_URL` *(url)*, `GREATERGIVING_TOKEN` |
| Greenbone Enterprise (OpenVAS) GMP/REST | `greenbone` | `GREENBONE_BASE_URL` *(url)*, `GREENBONE_TOKEN` |
| Greenhouse Harvest | `greenhouse` | `GREENHOUSE_BASE_URL` *(url)*, `GREENHOUSE_TOKEN` |
| Greenlight family debit card | `greenlight_card` | `GREENLIGHT_CARD_BASE_URL` *(url)*, `GREENLIGHT_CARD_TOKEN` |
| Greenplum Database REST/management API | `greenplum` | `GREENPLUM_BASE_URL` *(url)*, `GREENPLUM_TOKEN` |
| Greenway Health (Intergy) EHR REST API | `greenway_health` | `GREENWAY_HEALTH_BASE_URL` *(url)*, `GREENWAY_HEALTH_TOKEN` |
| greytHR HR/payroll REST API (India) | `greythr` | `GREYTHR_BASE_URL` *(url)*, `GREYTHR_TOKEN` |
| Groove.co (Clari) sales engagement | `groove` | `GROOVE_BASE_URL` *(url)*, `GROOVE_TOKEN` |
| Groq Cloud REST API | `groq_cloud` | `GROQ_CLOUD_BASE_URL` *(url)*, `GROQ_CLOUD_TOKEN` |
| GroupMe | `groupme` | `GROUPME_BASE_URL` *(url)*, `GROUPME_TOKEN` |
| Grow.com BI REST API | `grow` | `GROW_BASE_URL` *(url)*, `GROW_TOKEN` |
| Grubhub partner | `grubhub` | `GRUBHUB_BASE_URL` *(url)*, `GRUBHUB_TOKEN` |
| Guestline hotel PMS REST API | `guestline` | `GUESTLINE_BASE_URL` *(url)*, `GUESTLINE_TOKEN` |
| Guidewire InsuranceSuite REST API | `guidewire` | `GUIDEWIRE_BASE_URL` *(url)*, `GUIDEWIRE_TOKEN` |
| Guilded | `guilded` | `GUILDED_BASE_URL` *(url)*, `GUILDED_TOKEN` |
| Gumlet video hosting/transcoding | `gumlet` | `GUMLET_BASE_URL` *(url)*, `GUMLET_TOKEN` |
| Gumloop REST API (no-code AI automation builder) | `gumloop` | `GUMLOOP_BASE_URL` *(url)*, `GUMLOOP_TOKEN` |
| Gumroad REST API | `gumroad` | `GUMROAD_BASE_URL` *(url)*, `GUMROAD_TOKEN` |
| Gupshup messaging CPaaS REST API (India) | `gupshup` | `GUPSHUP_BASE_URL` *(url)*, `GUPSHUP_TOKEN` |
| Guru knowledge | `guru` | `GURU_BASE_URL` *(url)*, `GURU_TOKEN` |
| Gusto | `gusto` | `GUSTO_BASE_URL` *(url)*, `GUSTO_TOKEN` |
| GymCatch | `gymcatch` | `GYMCATCH_BASE_URL` *(url)*, `GYMCATCH_TOKEN` |
| Gymdesk | `gymdesk` | `GYMDESK_BASE_URL` *(url)*, `GYMDESK_TOKEN` |
| GymMaster | `gymmaster` | `GYMMASTER_BASE_URL` *(url)*, `GYMMASTER_TOKEN` |
| Haivision video streaming platform | `haivision` | `HAIVISION_BASE_URL` *(url)*, `HAIVISION_TOKEN` |
| Halo ITSM | `haloitsm` | `HALOITSM_BASE_URL` *(url)*, `HALOITSM_TOKEN` |
| Handbid auction/fundraising | `handbid` | `HANDBID_BASE_URL` *(url)*, `HANDBID_TOKEN` |
| Handshake career-services | `handshake` | `HANDSHAKE_BASE_URL` *(url)*, `HANDSHAKE_TOKEN` |
| Happeo intranet | `happeo` | `HAPPEO_BASE_URL` *(url)*, `HAPPEO_TOKEN` |
| Happy Returns (PayPal) REST API | `happy_returns` | `HAPPY_RETURNS_BASE_URL` *(url)*, `HAPPY_RETURNS_TOKEN` |
| HappyCo property inspection/operations | `happyco` | `HAPPYCO_BASE_URL` *(url)*, `HAPPYCO_TOKEN` |
| HappyFox helpdesk | `happyfox` | `HAPPYFOX_BASE_URL` *(url)*, `HAPPYFOX_TOKEN` |
| Happy Scribe transcription/subtitling | `happyscribe` | `HAPPYSCRIBE_BASE_URL` *(url)*, `HAPPYSCRIBE_TOKEN` |
| Haptik conversational AI REST API | `haptik` | `HAPTIK_BASE_URL` *(url)*, `HAPTIK_TOKEN` |
| Harness | `harness` | `HARNESS_BASE_URL` *(url)*, `HARNESS_TOKEN` |
| Harvest time tracking/invoicing | `harvest_time` | `HARVEST_TIME_BASE_URL` *(url)*, `HARVEST_TIME_TOKEN` |
| HawkSoft insurance agency management | `hawksoft` | `HAWKSOFT_BASE_URL` *(url)*, `HAWKSOFT_TOKEN` |
| HCSS heavy civil construction management | `hcss` | `HCSS_BASE_URL` *(url)*, `HCSS_TOKEN` |
| HealthSherpa ACA health plan enrollment | `health_sherpa` | `HEALTH_SHERPA_BASE_URL` *(url)*, `HEALTH_SHERPA_TOKEN` |
| Health Gorilla clinical data network REST/FHIR API | `healthgorilla` | `HEALTHGORILLA_BASE_URL` *(url)*, `HEALTHGORILLA_TOKEN` |
| Healthie EHR/practice management GraphQL API | `healthie` | `HEALTHIE_BASE_URL` *(url)*, `HEALTHIE_TOKEN` |
| Heap Analytics REST API | `heap` | `HEAP_BASE_URL` *(url)*, `HEAP_TOKEN` |
| Heartland (Global Payments) POS/payments REST API | `heartland_payment` | `HEARTLAND_PAYMENT_BASE_URL` *(url)*, `HEARTLAND_PAYMENT_TOKEN` |
| Height task management | `height_app` | `HEIGHT_APP_BASE_URL` *(url)*, `HEIGHT_APP_TOKEN` |
| HelloSign (Dropbox Sign) e-signature REST (distinct from docusign entry) | `hellosign` | `HELLOSIGN_BASE_URL` *(url)*, `HELLOSIGN_TOKEN` |
| HelpCrunch | `helpcrunch` | `HELPCRUNCH_BASE_URL` *(url)*, `HELPCRUNCH_TOKEN` |
| Help Scout | `helpscout` | `HELPSCOUT_BASE_URL` *(url)*, `HELPSCOUT_TOKEN` |
| Heroku Platform REST API | `heroku` | `HEROKU_BASE_URL` *(url)*, `HEROKU_TOKEN` |
| Hetzner Cloud REST API | `hetzner` | `HETZNER_BASE_URL` *(url)*, `HETZNER_TOKEN` |
| Hevo Data pipeline REST API | `hevo` | `HEVO_BASE_URL` *(url)*, `HEVO_TOKEN` |
| Hex REST API | `hex` | `HEX_BASE_URL` *(url)*, `HEX_TOKEN` |
| HeyGen AI video generation | `heygen` | `HEYGEN_BASE_URL` *(url)*, `HEYGEN_TOKEN` |
| HiBob (bob) HRIS | `hibob` | `HIBOB_BASE_URL` *(url)*, `HIBOB_TOKEN` |
| HighQ (Thomson Reuters) legal collaboration platform | `highq` | `HIGHQ_BASE_URL` *(url)*, `HIGHQ_TOKEN` |
| HighRadius order-to-cash/treasury | `highradius` | `HIGHRADIUS_BASE_URL` *(url)*, `HIGHRADIUS_TOKEN` |
| Highrise CRM REST/XML API | `highrise` | `HIGHRISE_BASE_URL` *(url)*, `HIGHRISE_TOKEN` |
| Highspot sales enablement | `highspot` | `HIGHSPOT_BASE_URL` *(url)*, `HIGHSPOT_TOKEN` |
| Hightail (formerly YouSendIt) | `hightail` | `HIGHTAIL_BASE_URL` *(url)*, `HIGHTAIL_TOKEN` |
| Hightouch (reverse ETL) REST API | `hightouch` | `HIGHTOUCH_BASE_URL` *(url)*, `HIGHTOUCH_TOKEN` |
| Hippo CMMS | `hippo_cmms` | `HIPPO_CMMS_BASE_URL` *(url)*, `HIPPO_CMMS_TOKEN` |
| Hireology hiring platform | `hireology` | `HIREOLOGY_BASE_URL` *(url)*, `HIREOLOGY_TOKEN` |
| HireRight background screening | `hireright` | `HIRERIGHT_BASE_URL` *(url)*, `HIRERIGHT_TOKEN` |
| HireVue video interviewing | `hirevue` | `HIREVUE_BASE_URL` *(url)*, `HIREVUE_TOKEN` |
| Hive project management | `hive_app` | `HIVE_APP_BASE_URL` *(url)*, `HIVE_APP_TOKEN` |
| Hologram IoT SIM connectivity REST API | `hologram` | `HOLOGRAM_BASE_URL` *(url)*, `HOLOGRAM_TOKEN` |
| Honeybadger REST API | `honeybadger` | `HONEYBADGER_BASE_URL` *(url)*, `HONEYBADGER_TOKEN` |
| Honeycomb.io observability REST API | `honeycomb` | `HONEYCOMB_BASE_URL` *(url)*, `HONEYCOMB_TOKEN` |
| Honeywell Forge industrial IoT | `honeywell_forge` | `HONEYWELL_FORGE_BASE_URL` *(url)*, `HONEYWELL_FORGE_TOKEN` |
| Hootsuite REST API | `hootsuite` | `HOOTSUITE_BASE_URL` *(url)*, `HOOTSUITE_TOKEN` |
| Hopin virtual events | `hopin` | `HOPIN_BASE_URL` *(url)*, `HOPIN_TOKEN` |
| Hopper travel booking partner REST API | `hopper` | `HOPPER_BASE_URL` *(url)*, `HOPPER_TOKEN` |
| Host Analytics (Planful legacy) CPM | `host_analytics` | `HOST_ANALYTICS_BASE_URL` *(url)*, `HOST_ANALYTICS_TOKEN` |
| HotDocs legal document automation | `hotdocs` | `HOTDOCS_BASE_URL` *(url)*, `HOTDOCS_TOKEN` |
| Hotelogix hotel PMS REST API | `hotelogix` | `HOTELOGIX_BASE_URL` *(url)*, `HOTELOGIX_TOKEN` |
| Hotjar REST API | `hotjar` | `HOTJAR_BASE_URL` *(url)*, `HOTJAR_TOKEN` |
| Housecall Pro | `housecall_pro` | `HOUSECALL_PRO_BASE_URL` *(url)*, `HOUSECALL_PRO_TOKEN` |
| HouseCanary property valuation/analytics | `housecanary` | `HOUSECANARY_BASE_URL` *(url)*, `HOUSECANARY_TOKEN` |
| Houzz Pro contractor/design project management | `houzz_pro` | `HOUZZ_PRO_BASE_URL` *(url)*, `HOUZZ_PRO_TOKEN` |
| Huawei Cloud REST API (China) | `huawei_cloud` | `HUAWEI_CLOUD_BASE_URL` *(url)*, `HUAWEI_CLOUD_TOKEN` |
| Hubdoc (Xero) document capture | `hubdoc` | `HUBDOC_BASE_URL` *(url)*, `HUBDOC_TOKEN` |
| HubSpot | `hubspot` | `HUBSPOT_TOKEN` |
| Hubstaff Tasks | `hubstaff_tasks` | `HUBSTAFF_TASKS_BASE_URL` *(url)*, `HUBSTAFF_TASKS_TOKEN` |
| Hudl | `hudl` | `HUDL_BASE_URL` *(url)*, `HUDL_TOKEN` |
| Hugging Face Inference API / Inference Endpoints | `huggingface_inference` | `HUGGINGFACE_INFERENCE_BASE_URL` *(url)*, `HUGGINGFACE_INFERENCE_TOKEN` |
| Humaans HR platform | `humaans` | `HUMAANS_BASE_URL` *(url)*, `HUMAANS_TOKEN` |
| Humanity (TCP Software) workforce scheduling | `humanity_app` | `HUMANITY_APP_BASE_URL` *(url)*, `HUMANITY_APP_TOKEN` |
| Humanloop REST API (LLM eval/prompt management) | `humanloop` | `HUMANLOOP_BASE_URL` *(url)*, `HUMANLOOP_TOKEN` |
| HungerRush POS | `hungerrush` | `HUNGERRUSH_BASE_URL` *(url)*, `HUNGERRUSH_TOKEN` |
| Hunter.io email-finder | `hunter` | `HUNTER_BASE_URL` *(url)*, `HUNTER_TOKEN` |
| Huntress Managed EDR | `huntress` | `HUNTRESS_BASE_URL` *(url)*, `HUNTRESS_TOKEN` |
| Huobi (HTX) exchange | `huobi` | `HUOBI_BASE_URL` *(url)*, `HUOBI_TOKEN` |
| Hygraph (GraphCMS) GraphQL/Management API | `hygraph` | `HYGRAPH_BASE_URL` *(url)*, `HYGRAPH_TOKEN` |
| HyperPay payments REST API | `hyperpay` | `HYPERPAY_BASE_URL` *(url)*, `HYPERPAY_TOKEN` |
| Hyperproof Compliance Operations | `hyperproof` | `HYPERPROOF_BASE_URL` *(url)*, `HYPERPROOF_TOKEN` |
| HYPR Control Center | `hypr` | `HYPR_BASE_URL` *(url)*, `HYPR_TOKEN` |
| Hyros REST API (ad tracking/attribution) | `hyros` | `HYROS_BASE_URL` *(url)*, `HYROS_TOKEN` |
| IBM Cloud | `ibm_cloud` | `IBM_CLOUD_BASE_URL` *(url)*, `IBM_CLOUD_TOKEN` |
| IBM watsonx.ai REST API | `ibm_watsonx` | `IBM_WATSONX_BASE_URL` *(url)*, `IBM_WATSONX_TOKEN` |
| Icertis contract intelligence | `icertis` | `ICERTIS_BASE_URL` *(url)*, `ICERTIS_TOKEN` |
| iCIMS REST (recruiting) | `icims` | `ICIMS_BASE_URL` *(url)*, `ICIMS_TOKEN` |
| Ideon (formerly Vericred) benefits data | `ideon_benefits` | `IDEON_BENEFITS_BASE_URL` *(url)*, `IDEON_BENEFITS_TOKEN` |
| IDX Broker MLS listing | `idxbroker` | `IDXBROKER_BASE_URL` *(url)*, `IDXBROKER_TOKEN` |
| IEX Cloud market-data | `iex_cloud` | `IEX_CLOUD_BASE_URL` *(url)*, `IEX_CLOUD_TOKEN` |
| iFood delivery partner REST API (Brazil) | `ifood` | `IFOOD_BASE_URL` *(url)*, `IFOOD_TOKEN` |
| IFS Cloud | `ifs` | `IFS_BASE_URL` *(url)*, `IFS_TOKEN` |
| IG trading platform | `ig_group` | `IG_GROUP_BASE_URL` *(url)*, `IG_GROUP_TOKEN` |
| IGDB (Internet Game Database, Twitch-owned) REST API | `igdb` | `IGDB_BASE_URL` *(url)*, `IGDB_TOKEN` |
| Igloo Software intranet | `igloo_software` | `IGLOO_SOFTWARE_BASE_URL` *(url)*, `IGLOO_SOFTWARE_TOKEN` |
| Inductive Automation Ignition SCADA | `ignition_scada` | `IGNITION_SCADA_BASE_URL` *(url)*, `IGNITION_SCADA_TOKEN` |
| ilert incident-management REST API | `ilert` | `ILERT_BASE_URL` *(url)*, `ILERT_TOKEN` |
| Illuminate Education (DnA) REST API for assessment data | `illuminate_education` | `ILLUMINATE_EDUCATION_BASE_URL` *(url)*, `ILLUMINATE_EDUCATION_TOKEN` |
| iLovePDF | `ilovepdf` | `ILOVEPDF_BASE_URL` *(url)*, `ILOVEPDF_TOKEN` |
| ImageKit.io image optimization/CDN | `imagekit_io` | `IMAGEKIT_IO_BASE_URL` *(url)*, `IMAGEKIT_IO_TOKEN` |
| Imagga image recognition/tagging | `imagga` | `IMAGGA_BASE_URL` *(url)*, `IMAGGA_TOKEN` |
| iManage document/matter management | `imanage` | `IMANAGE_BASE_URL` *(url)*, `IMANAGE_TOKEN` |
| imgix image-management REST API | `imgix` | `IMGIX_BASE_URL` *(url)*, `IMGIX_TOKEN` |
| Imgur REST API | `imgur` | `IMGUR_BASE_URL` *(url)*, `IMGUR_TOKEN` |
| Immuta Data Security Platform | `immuta` | `IMMUTA_BASE_URL` *(url)*, `IMMUTA_TOKEN` |
| Impact (impact.com) partnership REST API | `impactcom` | `IMPACTCOM_BASE_URL` *(url)*, `IMPACTCOM_TOKEN` |
| Imperva Cloud WAF/API Security | `imperva` | `IMPERVA_BASE_URL` *(url)*, `IMPERVA_TOKEN` |
| Imprivata OneSign/Enterprise | `imprivata` | `IMPRIVATA_BASE_URL` *(url)*, `IMPRIVATA_TOKEN` |
| Improvado marketing data pipeline REST API | `improvado` | `IMPROVADO_BASE_URL` *(url)*, `IMPROVADO_TOKEN` |
| Inbenta conversational AI REST API | `inbenta` | `INBENTA_BASE_URL` *(url)*, `INBENTA_TOKEN` |
| incident.io REST API | `incident_io` | `INCIDENT_IO_BASE_URL` *(url)*, `INCIDENT_IO_TOKEN` |
| Increase banking infrastructure | `increase` | `INCREASE_BASE_URL` *(url)*, `INCREASE_TOKEN` |
| Independent Reserve exchange | `independent_reserve` | `INDEPENDENT_RESERVE_BASE_URL` *(url)*, `INDEPENDENT_RESERVE_TOKEN` |
| InEight capital project management | `ineight` | `INEIGHT_BASE_URL` *(url)*, `INEIGHT_TOKEN` |
| Infinite Campus SIS REST API | `infinite_campus` | `INFINITE_CAMPUS_BASE_URL` *(url)*, `INFINITE_CAMPUS_TOKEN` |
| Infisical secrets-management REST API | `infisical` | `INFISICAL_BASE_URL` *(url)*, `INFISICAL_TOKEN` |
| InfluxDB REST API | `influxdb` | `INFLUXDB_BASE_URL` *(url)*, `INFLUXDB_TOKEN` |
| Infobip omnichannel messaging REST API | `infobip` | `INFOBIP_BASE_URL` *(url)*, `INFOBIP_TOKEN` |
| Infor CloudSuite (ION) | `infor` | `INFOR_BASE_URL` *(url)*, `INFOR_TOKEN` |
| Infor EAM asset management | `infor_eam` | `INFOR_EAM_BASE_URL` *(url)*, `INFOR_EAM_TOKEN` |
| Infor Nexus supply-chain network | `infor_nexus` | `INFOR_NEXUS_BASE_URL` *(url)*, `INFOR_NEXUS_TOKEN` |
| Infor VISUAL manufacturing ERP | `infor_visual` | `INFOR_VISUAL_BASE_URL` *(url)*, `INFOR_VISUAL_TOKEN` |
| Informatica IICS | `informatica` | `INFORMATICA_BASE_URL` *(url)*, `INFORMATICA_TOKEN` |
| Ingenico (Worldline Direct) payments REST API | `ingenico` | `INGENICO_BASE_URL` *(url)*, `INGENICO_TOKEN` |
| InitLive volunteer/event staffing | `initlive` | `INITLIVE_BASE_URL` *(url)*, `INITLIVE_TOKEN` |
| Innago property management | `innago` | `INNAGO_BASE_URL` *(url)*, `INNAGO_TOKEN` |
| InPost parcel locker logistics REST API (Poland) | `inpost` | `INPOST_BASE_URL` *(url)*, `INPOST_TOKEN` |
| Insightly CRM | `insightly` | `INSIGHTLY_BASE_URL` *(url)*, `INSIGHTLY_TOKEN` |
| InsightSquared (Mediafly) revenue analytics | `insightsquared` | `INSIGHTSQUARED_BASE_URL` *(url)*, `INSIGHTSQUARED_TOKEN` |
| Insly insurance policy administration | `insly` | `INSLY_BASE_URL` *(url)*, `INSLY_TOKEN` |
| Insperity HR/PEO | `insperity` | `INSPERITY_BASE_URL` *(url)*, `INSPERITY_TOKEN` |
| Instacart Connect | `instacart` | `INSTACART_BASE_URL` *(url)*, `INSTACART_TOKEN` |
| Instagantt | `instagantt` | `INSTAGANTT_BASE_URL` *(url)*, `INSTAGANTT_TOKEN` |
| Instagram Graph API | `instagram` | `INSTAGRAM_BASE_URL` *(url)*, `INSTAGRAM_TOKEN` |
| Instamojo payments REST API | `instamojo` | `INSTAMOJO_BASE_URL` *(url)*, `INSTAMOJO_TOKEN` |
| Instana observability REST API | `instana` | `INSTANA_BASE_URL` *(url)*, `INSTANA_TOKEN` |
| Instantly.ai cold-email sales engagement | `instantly` | `INSTANTLY_BASE_URL` *(url)*, `INSTANTLY_TOKEN` |
| Instapage REST API (landing pages) | `instapage` | `INSTAPAGE_BASE_URL` *(url)*, `INSTAPAGE_TOKEN` |
| Insureio insurance agency CRM | `insureio` | `INSUREIO_BASE_URL` *(url)*, `INSUREIO_TOKEN` |
| Insurity insurance core-platform REST API | `insurity` | `INSURITY_BASE_URL` *(url)*, `INSURITY_TOKEN` |
| INSZoom immigration case management | `inszoom` | `INSZOOM_BASE_URL` *(url)*, `INSZOOM_TOKEN` |
| Intapp legal/professional services | `intapp` | `INTAPP_BASE_URL` *(url)*, `INTAPP_TOKEN` |
| Intelex EHS/quality management | `intelex` | `INTELEX_BASE_URL` *(url)*, `INTELEX_TOKEN` |
| Interact intranet | `interact_intranet` | `INTERACT_INTRANET_BASE_URL` *(url)*, `INTERACT_INTRANET_TOKEN` |
| Interactive Brokers Web API | `interactive_brokers` | `INTERACTIVE_BROKERS_BASE_URL` *(url)*, `INTERACTIVE_BROKERS_TOKEN` |
| Interakt WhatsApp Business API platform REST API | `interakt` | `INTERAKT_BASE_URL` *(url)*, `INTERAKT_TOKEN` |
| Intercom | `intercom` | `INTERCOM_BASE_URL` *(url)*, `INTERCOM_TOKEN` |
| Internal.io REST API (low-code internal tools) | `internal_io` | `INTERNAL_IO_BASE_URL` *(url)*, `INTERNAL_IO_TOKEN` |
| Interswitch payments REST API (Nigeria) | `interswitch` | `INTERSWITCH_BASE_URL` *(url)*, `INTERSWITCH_TOKEN` |
| Intruder.io Vulnerability Scanning | `intruder` | `INTRUDER_BASE_URL` *(url)*, `INTRUDER_TOKEN` |
| Invicti (Netsparker) Enterprise | `invicti` | `INVICTI_BASE_URL` *(url)*, `INVICTI_TOKEN` |
| InVideo video creation | `invideo` | `INVIDEO_BASE_URL` *(url)*, `INVIDEO_TOKEN` |
| InVision REST API | `invision` | `INVISION_BASE_URL` *(url)*, `INVISION_TOKEN` |
| InVision Freehand | `invision_freehand` | `INVISION_FREEHAND_BASE_URL` *(url)*, `INVISION_FREEHAND_TOKEN` |
| Invoca call tracking/revenue attribution | `invoca` | `INVOCA_BASE_URL` *(url)*, `INVOCA_TOKEN` |
| IONOS Cloud REST API | `ionos` | `IONOS_BASE_URL` *(url)*, `IONOS_TOKEN` |
| iPay88 payment gateway REST API (Malaysia) | `ipay88` | `IPAY88_BASE_URL` *(url)*, `IPAY88_TOKEN` |
| iPipeline life insurance/annuity distribution | `ipipeline` | `IPIPELINE_BASE_URL` *(url)*, `IPIPELINE_TOKEN` |
| IQMS / DELMIAworks ERP-MES | `iqms` | `IQMS_BASE_URL` *(url)*, `IQMS_TOKEN` |
| Ironclad CLM | `ironclad` | `IRONCLAD_BASE_URL` *(url)*, `IRONCLAD_TOKEN` |
| IRONSCALES Email Security | `ironscales` | `IRONSCALES_BASE_URL` *(url)*, `IRONSCALES_TOKEN` |
| isolved HCM/payroll | `isolved` | `ISOLVED_BASE_URL` *(url)*, `ISOLVED_TOKEN` |
| Issuu digital publishing | `issuu` | `ISSUU_BASE_URL` *(url)*, `ISSUU_TOKEN` |
| iStock (Getty) stock media | `istock` | `ISTOCK_BASE_URL` *(url)*, `ISTOCK_TOKEN` |
| itch.io REST API | `itchio` | `ITCHIO_BASE_URL` *(url)*, `ITCHIO_TOKEN` |
| Iterable | `iterable` | `ITERABLE_BASE_URL` *(url)*, `ITERABLE_TOKEN` |
| Itron utility metering/analytics REST API | `itron` | `ITRON_BASE_URL` *(url)*, `ITRON_TOKEN` |
| Iugu payments/billing REST API (Brazil) | `iugu` | `IUGU_BASE_URL` *(url)*, `IUGU_TOKEN` |
| Ivanti Neurons / ITSM | `ivanti` | `IVANTI_BASE_URL` *(url)*, `IVANTI_TOKEN` |
| iWave prospect research | `iwave` | `IWAVE_BASE_URL` *(url)*, `IWAVE_TOKEN` |
| IXL Learning | `ixl` | `IXL_BASE_URL` *(url)*, `IXL_TOKEN` |
| iZettle (PayPal Zettle) REST API | `izettle` | `IZETTLE_BASE_URL` *(url)*, `IZETTLE_TOKEN` |
| Jack Henry banking/core processing | `jack_henry` | `JACK_HENRY_BASE_URL` *(url)*, `JACK_HENRY_TOKEN` |
| Jamf Pro | `jamf` | `JAMF_BASE_URL` *(url)*, `JAMF_TOKEN` |
| TIBCO JasperReports Server REST API | `jaspersoft` | `JASPERSOFT_BASE_URL` *(url)*, `JASPERSOFT_TOKEN` |
| JazzHR recruiting | `jazzhr` | `JAZZHR_BASE_URL` *(url)*, `JAZZHR_TOKEN` |
| JD.com Open Platform REST API | `jd_com` | `JD_COM_BASE_URL` *(url)*, `JD_COM_TOKEN` |
| Jenkins | `jenkins` | `JENKINS_BASE_URL` *(url)*, `JENKINS_TOKEN` |
| Jenzabar One higher-ed SIS | `jenzabar` | `JENZABAR_BASE_URL` *(url)*, `JENZABAR_TOKEN` |
| JFrog Artifactory | `jfrog` | `JFROG_BASE_URL` *(url)*, `JFROG_TOKEN` |
| Jimdo website builder REST API | `jimdo` | `JIMDO_BASE_URL` *(url)*, `JIMDO_TOKEN` |
| Jiminny conversation intelligence | `jiminny` | `JIMINNY_BASE_URL` *(url)*, `JIMINNY_TOKEN` |
| Jirav FP&A/budgeting | `jirav` | `JIRAV_BASE_URL` *(url)*, `JIRAV_TOKEN` |
| Jitbit Helpdesk | `jitbit` | `JITBIT_BASE_URL` *(url)*, `JITBIT_TOKEN` |
| Jitsi (JaaS) meetings | `jitsi` | `JITSI_BASE_URL` *(url)*, `JITSI_TOKEN` |
| Jitterbit Harmony REST API | `jitterbit` | `JITTERBIT_BASE_URL` *(url)*, `JITTERBIT_TOKEN` |
| Jobber GraphQL API | `jobber` | `JOBBER_BASE_URL` *(url)*, `JOBBER_TOKEN` |
| JobBOSS2 shop management | `jobboss` | `JOBBOSS_BASE_URL` *(url)*, `JOBBOSS_TOKEN` |
| JobDiva ATS/staffing | `jobdiva` | `JOBDIVA_BASE_URL` *(url)*, `JOBDIVA_TOKEN` |
| Joblogic field service management | `joblogic` | `JOBLOGIC_BASE_URL` *(url)*, `JOBLOGIC_TOKEN` |
| JobTread construction project management | `jobtread` | `JOBTREAD_BASE_URL` *(url)*, `JOBTREAD_TOKEN` |
| Jobvite recruiting | `jobvite` | `JOBVITE_BASE_URL` *(url)*, `JOBVITE_TOKEN` |
| John Deere Operations Center REST API for farm equipment | `johndeere_ops` | `JOHNDEERE_OPS_BASE_URL` *(url)*, `JOHNDEERE_OPS_TOKEN` |
| Joomla REST API (com_api) | `joomla` | `JOOMLA_BASE_URL` *(url)*, `JOOMLA_TOKEN` |
| Joplin (self-hosted sync server) | `joplin` | `JOPLIN_BASE_URL` *(url)*, `JOPLIN_TOKEN` |
| Jostle intranet | `jostle` | `JOSTLE_BASE_URL` *(url)*, `JOSTLE_TOKEN` |
| JotForm REST API | `jotform` | `JOTFORM_BASE_URL` *(url)*, `JOTFORM_TOKEN` |
| Jotform AI Agents REST API | `jotform_ai_agents` | `JOTFORM_AI_AGENTS_BASE_URL` *(url)*, `JOTFORM_AI_AGENTS_TOKEN` |
| JTL-Wawi ERP/warehouse REST API (Germany) | `jtl_wawi` | `JTL_WAWI_BASE_URL` *(url)*, `JTL_WAWI_TOKEN` |
| Judge.me REST API (reviews) | `judgeme` | `JUDGEME_BASE_URL` *(url)*, `JUDGEME_TOKEN` |
| Jumia marketplace seller REST API (Africa) | `jumia` | `JUMIA_BASE_URL` *(url)*, `JUMIA_TOKEN` |
| Jumio identity verification/KYC | `jumio` | `JUMIO_BASE_URL` *(url)*, `JUMIO_TOKEN` |
| JumpCloud directory REST API | `jumpcloud` | `JUMPCLOUD_BASE_URL` *(url)*, `JUMPCLOUD_TOKEN` |
| Juro contract lifecycle management | `juro` | `JURO_BASE_URL` *(url)*, `JURO_TOKEN` |
| Juspay payments REST API | `juspay` | `JUSPAY_BASE_URL` *(url)*, `JUSPAY_TOKEN` |
| JustCall contact center | `justcall` | `JUSTCALL_BASE_URL` *(url)*, `JUSTCALL_TOKEN` |
| Just Eat Takeaway | `justeat` | `JUSTEAT_BASE_URL` *(url)*, `JUSTEAT_TOKEN` |
| Just Eat Takeaway.com delivery partner REST API (Netherlands) | `justeat_takeaway` | `JUSTEAT_TAKEAWAY_BASE_URL` *(url)*, `JUSTEAT_TAKEAWAY_TOKEN` |
| Justworks PEO/HR | `justworks` | `JUSTWORKS_BASE_URL` *(url)*, `JUSTWORKS_TOKEN` |
| JW Player video REST API | `jwplayer` | `JWPLAYER_BASE_URL` *(url)*, `JWPLAYER_TOKEN` |
| Kabbage (Amex) business lending | `kabbage` | `KABBAGE_BASE_URL` *(url)*, `KABBAGE_TOKEN` |
| Kahoot! REST API for games/reports | `kahoot` | `KAHOOT_BASE_URL` *(url)*, `KAHOOT_TOKEN` |
| Kahua construction/capital program management | `kahua` | `KAHUA_BASE_URL` *(url)*, `KAHUA_TOKEN` |
| Kajabi creator/course platform | `kajabi` | `KAJABI_BASE_URL` *(url)*, `KAJABI_TOKEN` |
| Kakao (KakaoTalk) REST API | `kakao` | `KAKAO_BASE_URL` *(url)*, `KAKAO_TOKEN` |
| Kakao Pay REST API (South Korea) | `kakaopay` | `KAKAOPAY_BASE_URL` *(url)*, `KAKAOPAY_TOKEN` |
| Kaleyra CPaaS REST API (India) | `kaleyra` | `KALEYRA_BASE_URL` *(url)*, `KALEYRA_TOKEN` |
| Kaltura video platform REST API | `kaltura` | `KALTURA_BASE_URL` *(url)*, `KALTURA_TOKEN` |
| Kamatera Cloud REST API | `kamatera` | `KAMATERA_BASE_URL` *(url)*, `KAMATERA_TOKEN` |
| Kanbanize (Businessmap) | `kanbanize` | `KANBANIZE_BASE_URL` *(url)*, `KANBANIZE_TOKEN` |
| Kapwing video editing | `kapwing` | `KAPWING_BASE_URL` *(url)*, `KAPWING_TOKEN` |
| Kareo (Tebra) medical practice management REST API | `kareo` | `KAREO_BASE_URL` *(url)*, `KAREO_TOKEN` |
| Karix (Route Mobile) messaging REST API | `karix` | `KARIX_BASE_URL` *(url)*, `KARIX_TOKEN` |
| Kartra REST API | `kartra` | `KARTRA_BASE_URL` *(url)*, `KARTRA_TOKEN` |
| Kashoo accounting | `kashoo` | `KASHOO_BASE_URL` *(url)*, `KASHOO_TOKEN` |
| Kasisto KAI conversational banking AI REST API | `kasisto` | `KASISTO_BASE_URL` *(url)*, `KASISTO_TOKEN` |
| Katana Manufacturing ERP REST API | `katana_mrp` | `KATANA_MRP_BASE_URL` *(url)*, `KATANA_MRP_TOKEN` |
| KAYAK travel search partner REST API | `kayak` | `KAYAK_BASE_URL` *(url)*, `KAYAK_TOKEN` |
| Kayako helpdesk | `kayako` | `KAYAKO_BASE_URL` *(url)*, `KAYAKO_TOKEN` |
| Keap (Infusionsoft) CRM | `keap` | `KEAP_BASE_URL` *(url)*, `KEAP_TOKEN` |
| Keboola Connection REST API | `keboola` | `KEBOOLA_BASE_URL` *(url)*, `KEBOOLA_TOKEN` |
| Keela nonprofit CRM | `keela` | `KEELA_BASE_URL` *(url)*, `KEELA_TOKEN` |
| Keeper Secrets Manager REST API | `keeper` | `KEEPER_BASE_URL` *(url)*, `KEEPER_TOKEN` |
| Keka HR/payroll REST API (India) | `keka` | `KEKA_BASE_URL` *(url)*, `KEKA_TOKEN` |
| Cisco Kenna Security (Vulnerability Response) | `kenna_security` | `KENNA_SECURITY_BASE_URL` *(url)*, `KENNA_SECURITY_TOKEN` |
| Kentico Xperience REST API | `kentico` | `KENTICO_BASE_URL` *(url)*, `KENTICO_TOKEN` |
| PTC Kepware KEPServerEX industrial connectivity | `kepware` | `KEPWARE_BASE_URL` *(url)*, `KEPWARE_TOKEN` |
| KeyCDN REST API | `keycdn` | `KEYCDN_BASE_URL` *(url)*, `KEYCDN_TOKEN` |
| Khoros social/community customer engagement | `khoros` | `KHOROS_BASE_URL` *(url)*, `KHOROS_TOKEN` |
| Kick.com live streaming | `kick` | `KICK_BASE_URL` *(url)*, `KICK_TOKEN` |
| Kickserv field service/CRM | `kickserv` | `KICKSERV_BASE_URL` *(url)*, `KICKSERV_TOKEN` |
| Kinaxis RapidResponse supply-chain planning | `kinaxis` | `KINAXIS_BASE_URL` *(url)*, `KINAXIS_TOKEN` |
| Kinetica GPU database REST API | `kinetica` | `KINETICA_BASE_URL` *(url)*, `KINETICA_TOKEN` |
| kintone work platform REST API (Japan, Cybozu) | `kintone` | `KINTONE_BASE_URL` *(url)*, `KINTONE_TOKEN` |
| Kira Systems contract analysis | `kirasystems` | `KIRASYSTEMS_BASE_URL` *(url)*, `KIRASYSTEMS_TOKEN` |
| Kissmetrics REST API | `kissmetrics` | `KISSMETRICS_BASE_URL` *(url)*, `KISSMETRICS_TOKEN` |
| Kiva microloans | `kiva` | `KIVA_BASE_URL` *(url)*, `KIVA_TOKEN` |
| Kixie contact center/dialer | `kixie` | `KIXIE_BASE_URL` *(url)*, `KIXIE_TOKEN` |
| Klarna Payments/Checkout REST API | `klarna` | `KLARNA_BASE_URL` *(url)*, `KLARNA_TOKEN` |
| Klaviyo | `klaviyo` | `KLAVIYO_BASE_URL` *(url)*, `KLAVIYO_TOKEN` |
| Klenty sales engagement | `klenty` | `KLENTY_BASE_URL` *(url)*, `KLENTY_TOKEN` |
| Klipfolio REST API | `klipfolio` | `KLIPFOLIO_BASE_URL` *(url)*, `KLIPFOLIO_TOKEN` |
| Knack | `knack` | `KNACK_BASE_URL` *(url)*, `KNACK_TOKEN` |
| KNIME Business Hub REST API | `knime` | `KNIME_BASE_URL` *(url)*, `KNIME_TOKEN` |
| Knock.app notification infrastructure REST API | `knock_app` | `KNOCK_APP_BASE_URL` *(url)*, `KNOCK_APP_TOKEN` |
| KnowBe4 Security Awareness Training | `knowbe4` | `KNOWBE4_BASE_URL` *(url)*, `KNOWBE4_TOKEN` |
| Knowify job costing/project management | `knowify` | `KNOWIFY_BASE_URL` *(url)*, `KNOWIFY_TOKEN` |
| Knowlarity contact center | `knowlarity` | `KNOWLARITY_BASE_URL` *(url)*, `KNOWLARITY_TOKEN` |
| Kochava REST API | `kochava` | `KOCHAVA_BASE_URL` *(url)*, `KOCHAVA_TOKEN` |
| Koerber Supply Chain (HighJump) WMS | `koerber_wms` | `KOERBER_WMS_BASE_URL` *(url)*, `KOERBER_WMS_TOKEN` |
| Kommunicate chatbot/live-chat REST API | `kommunicate` | `KOMMUNICATE_BASE_URL` *(url)*, `KOMMUNICATE_TOKEN` |
| Kontent.ai (Kentico Cloud) Content Management API | `kontent` | `KONTENT_BASE_URL` *(url)*, `KONTENT_TOKEN` |
| Kore.ai conversational AI platform REST API | `kore_ai` | `KORE_AI_BASE_URL` *(url)*, `KORE_AI_TOKEN` |
| Kore Wireless IoT connectivity REST API | `kore_wireless` | `KORE_WIRELESS_BASE_URL` *(url)*, `KORE_WIRELESS_TOKEN` |
| KORONA POS REST API | `korona_pos` | `KORONA_POS_BASE_URL` *(url)*, `KORONA_POS_TOKEN` |
| Kount (Equifax) fraud prevention | `kount` | `KOUNT_BASE_URL` *(url)*, `KOUNT_TOKEN` |
| Koyeb Serverless Cloud REST API | `koyeb` | `KOYEB_BASE_URL` *(url)*, `KOYEB_TOKEN` |
| Kraken exchange | `kraken` | `KRAKEN_BASE_URL` *(url)*, `KRAKEN_TOKEN` |
| UKG Workforce Central (Kronos) REST (distinct from generic ukg entry) | `kronos_ukg_wfc` | `KRONOS_UKG_WFC_BASE_URL` *(url)*, `KRONOS_UKG_WFC_TOKEN` |
| Kubernetes API server | `kubernetes` | `KUBERNETES_BASE_URL` *(url)*, `KUBERNETES_TOKEN` |
| KuCoin exchange | `kucoin` | `KUCOIN_BASE_URL` *(url)*, `KUCOIN_TOKEN` |
| Kuebix (Trimble) transportation management REST API | `kuebix` | `KUEBIX_BASE_URL` *(url)*, `KUEBIX_TOKEN` |
| Kumulos push notification REST API | `kumulos` | `KUMULOS_BASE_URL` *(url)*, `KUMULOS_TOKEN` |
| Kushki payments REST API (Latin America) | `kushki` | `KUSHKI_BASE_URL` *(url)*, `KUSHKI_TOKEN` |
| Kustomer | `kustomer` | `KUSTOMER_BASE_URL` *(url)*, `KUSTOMER_TOKEN` |
| kvCORE (Inside Real Estate) CRM | `kvcore` | `KVCORE_BASE_URL` *(url)*, `KVCORE_TOKEN` |
| L2L connected worker/andon manufacturing platform | `l2l` | `L2L_BASE_URL` *(url)*, `L2L_TOKEN` |
| Lacework cloud-security REST API | `lacework` | `LACEWORK_BASE_URL` *(url)*, `LACEWORK_TOKEN` |
| Lambda Labs Cloud REST API (GPU instances) | `lambda_labs_cloud` | `LAMBDA_LABS_CLOUD_BASE_URL` *(url)*, `LAMBDA_LABS_CLOUD_TOKEN` |
| LambdaTest REST API | `lambdatest` | `LAMBDATEST_BASE_URL` *(url)*, `LAMBDATEST_TOKEN` |
| LanceDB Cloud REST API (vector database) | `lancedb_cloud` | `LANCEDB_CLOUD_BASE_URL` *(url)*, `LANCEDB_CLOUD_TOKEN` |
| Landbot REST API (no-code chatbot builder) | `landbot` | `LANDBOT_BASE_URL` *(url)*, `LANDBOT_TOKEN` |
| Landis+Gyr utility smart-metering REST API | `landis_gyr` | `LANDIS_GYR_BASE_URL` *(url)*, `LANDIS_GYR_TOKEN` |
| Langflow REST API (visual LLM flow builder) | `langflow` | `LANGFLOW_BASE_URL` *(url)*, `LANGFLOW_TOKEN` |
| LangSmith REST API (LLM tracing/eval platform) | `langsmith` | `LANGSMITH_BASE_URL` *(url)*, `LANGSMITH_TOKEN` |
| Laserfiche document management | `laserfiche` | `LASERFICHE_BASE_URL` *(url)*, `LASERFICHE_TOKEN` |
| LastPass Enterprise Admin | `lastpass` | `LASTPASS_BASE_URL` *(url)*, `LASTPASS_TOKEN` |
| Latchel property maintenance coordination | `latchel` | `LATCHEL_BASE_URL` *(url)*, `LATCHEL_TOKEN` |
| Lattice performance/engagement | `lattice` | `LATTICE_BASE_URL` *(url)*, `LATTICE_TOKEN` |
| LaunchDarkly feature-flag REST (v2) | `launchdarkly` | `LAUNCHDARKLY_BASE_URL` *(url)*, `LAUNCHDARKLY_TOKEN` |
| Poslavu (POS Lavu) | `lavu_pos` | `LAVU_POS_BASE_URL` *(url)*, `LAVU_POS_TOKEN` |
| Lawcus legal practice management | `lawcus` | `LAWCUS_BASE_URL` *(url)*, `LAWCUS_TOKEN` |
| LawDepot legal document generation | `lawdepot` | `LAWDEPOT_BASE_URL` *(url)*, `LAWDEPOT_TOKEN` |
| LawGeex contract review automation | `lawgeex` | `LAWGEEX_BASE_URL` *(url)*, `LAWGEEX_TOKEN` |
| Lawmatics legal CRM/intake automation | `lawmatics` | `LAWMATICS_BASE_URL` *(url)*, `LAWMATICS_TOKEN` |
| LawPay legal payment processing | `lawpay` | `LAWPAY_BASE_URL` *(url)*, `LAWPAY_TOKEN` |
| LawToolBox legal deadline/calendar | `lawtoolbox` | `LAWTOOLBOX_BASE_URL` *(url)*, `LAWTOOLBOX_TOKEN` |
| Laybuy installment-payments REST API | `laybuy` | `LAYBUY_BASE_URL` *(url)*, `LAYBUY_TOKEN` |
| Lazada Open Platform REST API | `lazada` | `LAZADA_BASE_URL` *(url)*, `LAZADA_TOKEN` |
| LeadIQ prospecting | `leadiq` | `LEADIQ_BASE_URL` *(url)*, `LEADIQ_TOKEN` |
| Leadpages REST API | `leadpages` | `LEADPAGES_BASE_URL` *(url)*, `LEADPAGES_TOKEN` |
| LeagueApps | `leagueapps` | `LEAGUEAPPS_BASE_URL` *(url)*, `LEAGUEAPPS_TOKEN` |
| LeanLaw legal billing | `leanlaw` | `LEANLAW_BASE_URL` *(url)*, `LEANLAW_TOKEN` |
| Leanplum REST API | `leanplum` | `LEANPLUM_BASE_URL` *(url)*, `LEANPLUM_TOKEN` |
| LEAP legal practice management | `leap_legal` | `LEAP_LEGAL_BASE_URL` *(url)*, `LEAP_LEGAL_TOKEN` |
| Leapsome performance/engagement | `leapsome` | `LEAPSOME_BASE_URL` *(url)*, `LEAPSOME_TOKEN` |
| Ledger Live wallet | `ledger_live` | `LEDGER_LIVE_BASE_URL` *(url)*, `LEDGER_LIVE_TOKEN` |
| LegalTrek legal spend/matter management | `legaltrek` | `LEGALTREK_BASE_URL` *(url)*, `LEGALTREK_TOKEN` |
| LegalZoom legal services | `legalzoom` | `LEGALZOOM_BASE_URL` *(url)*, `LEGALZOOM_TOKEN` |
| lemlist sales engagement | `lemlist` | `LEMLIST_BASE_URL` *(url)*, `LEMLIST_TOKEN` |
| Lemon Squeezy REST API | `lemonsqueezy` | `LEMONSQUEEZY_BASE_URL` *(url)*, `LEMONSQUEEZY_TOKEN` |
| LendingClub | `lendingclub` | `LENDINGCLUB_BASE_URL` *(url)*, `LENDINGCLUB_TOKEN` |
| Lessonly (Seismic) training | `lessonly` | `LESSONLY_BASE_URL` *(url)*, `LESSONLY_TOKEN` |
| Levelset (Procore Payments) construction lien/payment | `levelset` | `LEVELSET_BASE_URL` *(url)*, `LEVELSET_TOKEN` |
| Lever recruiting | `lever` | `LEVER_BASE_URL` *(url)*, `LEVER_TOKEN` |
| LexCheck contract review AI | `lexcheck` | `LEXCHECK_BASE_URL` *(url)*, `LEXCHECK_TOKEN` |
| Lexia Learning | `lexia` | `LEXIA_BASE_URL` *(url)*, `LEXIA_TOKEN` |
| Lexion CLM | `lexion` | `LEXION_BASE_URL` *(url)*, `LEXION_TOKEN` |
| LexisNexis legal research | `lexisnexis` | `LEXISNEXIS_BASE_URL` *(url)*, `LEXISNEXIS_TOKEN` |
| LexisNexis Risk Solutions | `lexisnexis_risk` | `LEXISNEXIS_RISK_BASE_URL` *(url)*, `LEXISNEXIS_RISK_TOKEN` |
| lexoffice accounting REST API (Germany, Haufe-Lexware) | `lexoffice` | `LEXOFFICE_BASE_URL` *(url)*, `LEXOFFICE_TOKEN` |
| Librato (SolarWinds) metrics REST API | `librato` | `LIBRATO_BASE_URL` *(url)*, `LIBRATO_TOKEN` |
| Libsyn podcast hosting | `libsyn` | `LIBSYN_BASE_URL` *(url)*, `LIBSYN_TOKEN` |
| Salesforce Lightning Platform (Force.com) REST API | `lightning_platform` | `LIGHTNING_PLATFORM_BASE_URL` *(url)*, `LIGHTNING_PLATFORM_TOKEN` |
| Lightspeed Retail/Restaurant POS REST API | `lightspeed` | `LIGHTSPEED_BASE_URL` *(url)*, `LIGHTSPEED_TOKEN` |
| Lightstep (ServiceNow Cloud Observability) REST API | `lightstep` | `LIGHTSTEP_BASE_URL` *(url)*, `LIGHTSTEP_TOKEN` |
| Lightyear AP automation | `lightyear_ap` | `LIGHTYEAR_AP_BASE_URL` *(url)*, `LIGHTYEAR_AP_TOKEN` |
| Lili small-business banking | `lili_bank` | `LILI_BANK_BASE_URL` *(url)*, `LILI_BANK_TOKEN` |
| Limble CMMS | `limble_cmms` | `LIMBLE_CMMS_BASE_URL` *(url)*, `LIMBLE_CMMS_TOKEN` |
| Limelight (Prophix) CPM | `limelight_cpm` | `LIMELIGHT_CPM_BASE_URL` *(url)*, `LIMELIGHT_CPM_TOKEN` |
| Limelight Health benefits underwriting/quoting | `limelight_health` | `LIMELIGHT_HEALTH_BASE_URL` *(url)*, `LIMELIGHT_HEALTH_TOKEN` |
| Limelight Networks (Edgio) video delivery | `limelight_networks` | `LIMELIGHT_NETWORKS_BASE_URL` *(url)*, `LIMELIGHT_NETWORKS_TOKEN` |
| Limnu whiteboard | `limnu` | `LIMNU_BASE_URL` *(url)*, `LIMNU_TOKEN` |
| Lindy AI REST API (no-code AI agent builder) | `lindy_ai` | `LINDY_AI_BASE_URL` *(url)*, `LINDY_AI_TOKEN` |
| LINE Messaging API | `line_messaging` | `LINE_MESSAGING_BASE_URL` *(url)*, `LINE_MESSAGING_TOKEN` |
| LINE WORKS | `line_works` | `LINE_WORKS_BASE_URL` *(url)*, `LINE_WORKS_TOKEN` |
| LinearB engineering-metrics REST API | `linearb` | `LINEARB_BASE_URL` *(url)*, `LINEARB_TOKEN` |
| LINK Mobility messaging REST API | `link_mobility` | `LINK_MOBILITY_BASE_URL` *(url)*, `LINK_MOBILITY_TOKEN` |
| LinkedIn REST API | `linkedin` | `LINKEDIN_BASE_URL` *(url)*, `LINKEDIN_TOKEN` |
| LinkedIn Marketing (Ads) API | `linkedinads` | `LINKEDINADS_BASE_URL` *(url)*, `LINKEDINADS_TOKEN` |
| LinkSquares CLM | `linksquares` | `LINKSQUARES_BASE_URL` *(url)*, `LINKSQUARES_TOKEN` |
| Linnworks inventory/order-management | `linnworks` | `LINNWORKS_BASE_URL` *(url)*, `LINNWORKS_TOKEN` |
| Linode (Akamai) Cloud REST API | `linode` | `LINODE_BASE_URL` *(url)*, `LINODE_TOKEN` |
| LionDesk (real estate CRM) | `liondesk` | `LIONDESK_BASE_URL` *(url)*, `LIONDESK_TOKEN` |
| LiquidPlanner | `liquidplanner` | `LIQUIDPLANNER_BASE_URL` *(url)*, `LIQUIDPLANNER_TOKEN` |
| Listrak REST API | `listrak` | `LISTRAK_BASE_URL` *(url)*, `LISTRAK_TOKEN` |
| Litera legal document workflow | `litera` | `LITERA_BASE_URL` *(url)*, `LITERA_TOKEN` |
| Litify (Salesforce-based) legal operations platform | `litify` | `LITIFY_BASE_URL` *(url)*, `LITIFY_TOKEN` |
| Litmos learning management | `litmos` | `LITMOS_BASE_URL` *(url)*, `LITMOS_TOKEN` |
| Little Green Light donor CRM | `littlegreenlight` | `LITTLEGREENLIGHT_BASE_URL` *(url)*, `LITTLEGREENLIGHT_TOKEN` |
| LiveAgent helpdesk | `liveagent` | `LIVEAGENT_BASE_URL` *(url)*, `LIVEAGENT_TOKEN` |
| LiveChat | `livechat` | `LIVECHAT_BASE_URL` *(url)*, `LIVECHAT_TOKEN` |
| LiveIntent REST API | `liveintent` | `LIVEINTENT_BASE_URL` *(url)*, `LIVEINTENT_TOKEN` |
| LivePerson Conversational Cloud REST API | `liveperson` | `LIVEPERSON_BASE_URL` *(url)*, `LIVEPERSON_TOKEN` |
| Livestorm webinar | `livestorm` | `LIVESTORM_BASE_URL` *(url)*, `LIVESTORM_TOKEN` |
| Loadsmart freight/logistics REST API | `loadsmart` | `LOADSMART_BASE_URL` *(url)*, `LOADSMART_TOKEN` |
| Loftware enterprise labeling | `loftware` | `LOFTWARE_BASE_URL` *(url)*, `LOFTWARE_TOKEN` |
| SolarWinds Loggly REST API | `loggly` | `LOGGLY_BASE_URL` *(url)*, `LOGGLY_TOKEN` |
| Logi Analytics (insightsoftware) REST API | `logianalytics` | `LOGIANALYTICS_BASE_URL` *(url)*, `LOGIANALYTICS_TOKEN` |
| LogicGate Risk Cloud | `logicgate` | `LOGICGATE_BASE_URL` *(url)*, `LOGICGATE_TOKEN` |
| LogicManager GRC/risk management | `logicmanager` | `LOGICMANAGER_BASE_URL` *(url)*, `LOGICMANAGER_TOKEN` |
| LogicMonitor | `logicmonitor` | `LOGICMONITOR_BASE_URL` *(url)*, `LOGICMONITOR_TOKEN` |
| Logikcull e-discovery | `logikcull` | `LOGIKCULL_BASE_URL` *(url)*, `LOGIKCULL_TOKEN` |
| Logility Digital Supply Chain | `logility` | `LOGILITY_BASE_URL` *(url)*, `LOGILITY_TOKEN` |
| Logiwa WMS | `logiwa` | `LOGIWA_BASE_URL` *(url)*, `LOGIWA_TOKEN` |
| LogRocket REST API | `logrocket` | `LOGROCKET_BASE_URL` *(url)*, `LOGROCKET_TOKEN` |
| Logseq local HTTP API | `logseq` | `LOGSEQ_BASE_URL` *(url)*, `LOGSEQ_TOKEN` |
| Logz.io REST API | `logz_io` | `LOGZ_IO_BASE_URL` *(url)*, `LOGZ_IO_TOKEN` |
| Looker | `looker` | `LOOKER_BASE_URL` *(url)*, `LOOKER_TOKEN` |
| Google Looker Studio (Data Studio) REST/reporting API | `looker_studio` | `LOOKER_STUDIO_BASE_URL` *(url)*, `LOOKER_STUDIO_TOKEN` |
| Lookout Mobile Endpoint Security | `lookout` | `LOOKOUT_BASE_URL` *(url)*, `LOOKOUT_TOKEN` |
| Loom video messaging | `loom` | `LOOM_BASE_URL` *(url)*, `LOOM_TOKEN` |
| Loomly REST API | `loomly` | `LOOMLY_BASE_URL` *(url)*, `LOOMLY_TOKEN` |
| Loop Returns REST API | `loop_returns` | `LOOP_RETURNS_BASE_URL` *(url)*, `LOOP_RETURNS_TOKEN` |
| LoopNet commercial real estate listings partner REST API | `loopnet` | `LOOPNET_BASE_URL` *(url)*, `LOOPNET_TOKEN` |
| Loris customer conversation intelligence | `loris` | `LORIS_BASE_URL` *(url)*, `LORIS_TOKEN` |
| Losant industrial IoT platform | `losant` | `LOSANT_BASE_URL` *(url)*, `LOSANT_TOKEN` |
| LottieFiles REST API | `lottiefiles` | `LOTTIEFILES_BASE_URL` *(url)*, `LOTTIEFILES_TOKEN` |
| Loxo recruiting CRM/ATS | `loxo` | `LOXO_BASE_URL` *(url)*, `LOXO_TOKEN` |
| Loyverse POS REST API | `loyverse` | `LOYVERSE_BASE_URL` *(url)*, `LOYVERSE_TOKEN` |
| Lucca HR suite REST API (France) | `lucca` | `LUCCA_BASE_URL` *(url)*, `LUCCA_TOKEN` |
| Lucid (Lucidchart) | `lucid` | `LUCID_BASE_URL` *(url)*, `LUCID_TOKEN` |
| Lucky Orange REST API | `luckyorange` | `LUCKYORANGE_BASE_URL` *(url)*, `LUCKYORANGE_TOKEN` |
| Luigi task pipeline visualizer/central scheduler REST API | `luigi` | `LUIGI_BASE_URL` *(url)*, `LUIGI_TOKEN` |
| Luminance legal AI document review | `luminance` | `LUMINANCE_BASE_URL` *(url)*, `LUMINANCE_TOKEN` |
| Luno exchange | `luno` | `LUNO_BASE_URL` *(url)*, `LUNO_TOKEN` |
| Lusha contact/prospecting | `lusha` | `LUSHA_BASE_URL` *(url)*, `LUSHA_TOKEN` |
| Lytics REST API (CDP) | `lytics` | `LYTICS_BASE_URL` *(url)*, `LYTICS_TOKEN` |
| M1 Finance brokerage | `m1_finance` | `M1_FINANCE_BASE_URL` *(url)*, `M1_FINANCE_TOKEN` |
| mabl test-automation REST API | `mabl` | `MABL_BASE_URL` *(url)*, `MABL_TOKEN` |
| Formstack Forms REST API | `mable_iot` | `MABLE_IOT_BASE_URL` *(url)*, `MABLE_IOT_TOKEN` |
| MachineMetrics manufacturing analytics | `machinemetrics` | `MACHINEMETRICS_BASE_URL` *(url)*, `MACHINEMETRICS_TOKEN` |
| Made4net WMS | `made4net` | `MADE4NET_BASE_URL` *(url)*, `MADE4NET_TOKEN` |
| MaestroQA contact-center QA | `maestroqa` | `MAESTROQA_BASE_URL` *(url)*, `MAESTROQA_TOKEN` |
| Adobe Commerce (Magento) | `magento` | `MAGENTO_BASE_URL` *(url)*, `MAGENTO_TOKEN` |
| MagicBell notification inbox REST API | `magicbell` | `MAGICBELL_BASE_URL` *(url)*, `MAGICBELL_TOKEN` |
| Mailchimp Marketing | `mailchimp` | `MAILCHIMP_BASE_URL` *(url)*, `MAILCHIMP_TOKEN` |
| MailerLite REST API | `mailerlite` | `MAILERLITE_BASE_URL` *(url)*, `MAILERLITE_TOKEN` |
| Mailgun REST API | `mailgun` | `MAILGUN_BASE_URL` *(url)*, `MAILGUN_TOKEN` |
| Mailjet REST API | `mailjet` | `MAILJET_BASE_URL` *(url)*, `MAILJET_TOKEN` |
| Majesco insurance core-platform REST API | `majesco` | `MAJESCO_BASE_URL` *(url)*, `MAJESCO_TOKEN` |
| Make (Integromat) | `make` | `MAKE_BASE_URL` *(url)*, `MAKE_TOKEN` |
| Malbek CLM | `malbek` | `MALBEK_BASE_URL` *(url)*, `MALBEK_TOKEN` |
| Malwarebytes Nebula/OneView | `malwarebytes` | `MALWAREBYTES_BASE_URL` *(url)*, `MALWAREBYTES_TOKEN` |
| ManageEngine ServiceDesk Plus | `manageengine` | `MANAGEENGINE_BASE_URL` *(url)*, `MANAGEENGINE_TOKEN` |
| Manatal recruiting/ATS | `manatal` | `MANATAL_BASE_URL` *(url)*, `MANATAL_TOKEN` |
| Mandiant Advantage Threat Intelligence | `mandiant` | `MANDIANT_BASE_URL` *(url)*, `MANDIANT_TOKEN` |
| Mangomint | `mangomint` | `MANGOMINT_BASE_URL` *(url)*, `MANGOMINT_TOKEN` |
| Manhattan Associates (Active Omni) REST API | `manhattan_associates` | `MANHATTAN_ASSOCIATES_BASE_URL` *(url)*, `MANHATTAN_ASSOCIATES_TOKEN` |
| ManyChat REST API (chatbot builder) | `manychat` | `MANYCHAT_BASE_URL` *(url)*, `MANYCHAT_TOKEN` |
| Marchex call analytics | `marchex` | `MARCHEX_BASE_URL` *(url)*, `MARCHEX_TOKEN` |
| Marcus by Goldman Sachs banking | `marcus_gs` | `MARCUS_GS_BASE_URL` *(url)*, `MARCUS_GS_TOKEN` |
| Mariana Tek | `mariana_tek` | `MARIANA_TEK_BASE_URL` *(url)*, `MARIANA_TEK_TOKEN` |
| Adobe Marketo Engage | `marketo` | `MARKETO_BASE_URL` *(url)*, `MARKETO_TOKEN` |
| Marketstack market-data | `marketstack` | `MARKETSTACK_BASE_URL` *(url)*, `MARKETSTACK_TOKEN` |
| Marq (Lucidpress) brand templating | `marq` | `MARQ_BASE_URL` *(url)*, `MARQ_TOKEN` |
| Marqeta card issuing | `marqeta` | `MARQETA_BASE_URL` *(url)*, `MARQETA_TOKEN` |
| Marqo REST API (vector search engine) | `marqo` | `MARQO_BASE_URL` *(url)*, `MARQO_TOKEN` |
| Marvel App prototyping REST API | `marvelapp` | `MARVELAPP_BASE_URL` *(url)*, `MARVELAPP_TOKEN` |
| MasterControl quality management | `mastercontrol` | `MASTERCONTROL_BASE_URL` *(url)*, `MASTERCONTROL_TOKEN` |
| Mastery Connect assessment | `masteryconnect` | `MASTERYCONNECT_BASE_URL` *(url)*, `MASTERYCONNECT_TOKEN` |
| Mastodon REST API (instance-hosted microblogging) | `mastodon` | `MASTODON_BASE_URL` *(url)*, `MASTODON_TOKEN` |
| Matillion | `matillion` | `MATILLION_BASE_URL` *(url)*, `MATILLION_TOKEN` |
| Matomo (Piwik) Analytics REST API | `matomo` | `MATOMO_BASE_URL` *(url)*, `MATOMO_TOKEN` |
| Matrix42 Service Management | `matrix42` | `MATRIX42_BASE_URL` *(url)*, `MATRIX42_TOKEN` |
| Mattermost | `mattermost` | `MATTERMOST_BASE_URL` *(url)*, `MATTERMOST_TOKEN` |
| Matterport Cloud REST/GraphQL API for 3D property tours | `matterport` | `MATTERPORT_BASE_URL` *(url)*, `MATTERPORT_TOKEN` |
| Mavenlink (Kantata) | `mavenlink` | `MAVENLINK_BASE_URL` *(url)*, `MAVENLINK_TOKEN` |
| Maximizer CRM | `maximizer` | `MAXIMIZER_BASE_URL` *(url)*, `MAXIMIZER_TOKEN` |
| IBM Maximo Application Suite (EAM) | `maximo` | `MAXIMO_BASE_URL` *(url)*, `MAXIMO_TOKEN` |
| Maxio (SaaSOptics/Chargify) billing REST API | `maxio` | `MAXIO_BASE_URL` *(url)*, `MAXIO_TOKEN` |
| McAfee (Trellix) ePO/MVISION | `mcafee` | `MCAFEE_BASE_URL` *(url)*, `MCAFEE_TOKEN` |
| Medallia Experience Cloud | `medallia` | `MEDALLIA_BASE_URL` *(url)*, `MEDALLIA_TOKEN` |
| Mediafly sales enablement | `mediafly` | `MEDIAFLY_BASE_URL` *(url)*, `MEDIAFLY_TOKEN` |
| MEDITECH Expanse EHR REST/FHIR API | `meditech` | `MEDITECH_BASE_URL` *(url)*, `MEDITECH_TOKEN` |
| Medium REST API for publishing | `medium` | `MEDIUM_BASE_URL` *(url)*, `MEDIUM_TOKEN` |
| Medusa (MedusaJS) headless commerce REST API | `medusajs` | `MEDUSAJS_BASE_URL` *(url)*, `MEDUSAJS_TOKEN` |
| Megaphone podcast hosting/ads | `megaphone` | `MEGAPHONE_BASE_URL` *(url)*, `MEGAPHONE_TOKEN` |
| Meilisearch REST API | `meilisearch` | `MEILISEARCH_BASE_URL` *(url)*, `MEILISEARCH_TOKEN` |
| Meilisearch Cloud REST API | `meilisearch_cloud` | `MEILISEARCH_CLOUD_BASE_URL` *(url)*, `MEILISEARCH_CLOUD_TOKEN` |
| MeisterTask | `meistertask` | `MEISTERTASK_BASE_URL` *(url)*, `MEISTERTASK_TOKEN` |
| Melio B2B payments | `melio` | `MELIO_BASE_URL` *(url)*, `MELIO_TOKEN` |
| Meltano REST API | `meltano` | `MELTANO_BASE_URL` *(url)*, `MELTANO_TOKEN` |
| MemberClicks association management | `memberclicks` | `MEMBERCLICKS_BASE_URL` *(url)*, `MEMBERCLICKS_TOKEN` |
| Memberstack REST API (no-code membership/auth) | `memberstack` | `MEMBERSTACK_BASE_URL` *(url)*, `MEMBERSTACK_TOKEN` |
| Membrain CRM | `membrain` | `MEMBRAIN_BASE_URL` *(url)*, `MEMBRAIN_TOKEN` |
| Mend.io (WhiteSource) SCA REST API | `mend` | `MEND_BASE_URL` *(url)*, `MEND_TOKEN` |
| Mendix REST (Runtime / Platform API) | `mendix` | `MENDIX_BASE_URL` *(url)*, `MENDIX_TOKEN` |
| Mercado Pago payments REST API | `mercado_pago` | `MERCADO_PAGO_BASE_URL` *(url)*, `MERCADO_PAGO_TOKEN` |
| Mercado Libre REST API | `mercadolibre` | `MERCADOLIBRE_BASE_URL` *(url)*, `MERCADOLIBRE_TOKEN` |
| Mercury banking REST (read balances/transactions; payments are confirm-gated) | `mercury` | `MERCURY_BASE_URL` *(url)*, `MERCURY_TOKEN` |
| Merge.dev unified HR/accounting API | `merge_dev` | `MERGE_DEV_BASE_URL` *(url)*, `MERGE_DEV_TOKEN` |
| MessageBird (Bird) messaging REST API | `messagebird` | `MESSAGEBIRD_BASE_URL` *(url)*, `MESSAGEBIRD_TOKEN` |
| MessageMedia messaging REST API | `messagemedia` | `MESSAGEMEDIA_BASE_URL` *(url)*, `MESSAGEMEDIA_TOKEN` |
| Messari crypto research | `messari` | `MESSARI_BASE_URL` *(url)*, `MESSARI_TOKEN` |
| Facebook Messenger Platform REST API | `messenger` | `MESSENGER_BASE_URL` *(url)*, `MESSENGER_TOKEN` |
| Meta (Facebook/Instagram) Marketing API | `metaads` | `METAADS_BASE_URL` *(url)*, `METAADS_TOKEN` |
| Metabase | `metabase` | `METABASE_BASE_URL` *(url)*, `METABASE_TOKEN` |
| MetaMask/Infura wallet RPC REST bridge | `metamask` | `METAMASK_BASE_URL` *(url)*, `METAMASK_TOKEN` |
| Method:CRM | `methodcrm` | `METHODCRM_BASE_URL` *(url)*, `METHODCRM_TOKEN` |
| MetricStream GRC platform | `metricstream` | `METRICSTREAM_BASE_URL` *(url)*, `METRICSTREAM_TOKEN` |
| MetroFax | `metrofax` | `METROFAX_BASE_URL` *(url)*, `METROFAX_TOKEN` |
| Mews hotel PMS REST API | `mews` | `MEWS_BASE_URL` *(url)*, `MEWS_TOKEN` |
| MEXC exchange | `mexc` | `MEXC_BASE_URL` *(url)*, `MEXC_TOKEN` |
| M-Files | `mfiles` | `MFILES_BASE_URL` *(url)*, `MFILES_TOKEN` |
| mHelpDesk field service management | `mhelpdesk` | `MHELPDESK_BASE_URL` *(url)*, `MHELPDESK_TOKEN` |
| MicroMain CMMS | `micromain` | `MICROMAIN_BASE_URL` *(url)*, `MICROMAIN_TOKEN` |
| Microsoft Forms REST (Graph) | `microsoft_forms` | `MICROSOFT_FORMS_BASE_URL` *(url)*, `MICROSOFT_FORMS_TOKEN` |
| Microsoft Planner REST (Graph) | `microsoft_planner` | `MICROSOFT_PLANNER_BASE_URL` *(url)*, `MICROSOFT_PLANNER_TOKEN` |
| MicroStrategy | `microstrategy` | `MICROSTRATEGY_BASE_URL` *(url)*, `MICROSTRATEGY_TOKEN` |
| Middesk business identity verification | `middesk` | `MIDDESK_BASE_URL` *(url)*, `MIDDESK_TOKEN` |
| Midtrans payment gateway REST API (Indonesia) | `midtrans` | `MIDTRANS_BASE_URL` *(url)*, `MIDTRANS_TOKEN` |
| Mightycause | `mightycause` | `MIGHTYCAUSE_BASE_URL` *(url)*, `MIGHTYCAUSE_TOKEN` |
| Zilliz Cloud (Milvus) REST API | `milvus_zilliz` | `MILVUS_ZILLIZ_BASE_URL` *(url)*, `MILVUS_ZILLIZ_TOKEN` |
| Mimecast Email Security | `mimecast` | `MIMECAST_BASE_URL` *(url)*, `MIMECAST_TOKEN` |
| Mindbody scheduling | `mindbody` | `MINDBODY_BASE_URL` *(url)*, `MINDBODY_TOKEN` |
| Siemens MindSphere industrial IoT | `mindsphere` | `MINDSPHERE_BASE_URL` *(url)*, `MINDSPHERE_TOKEN` |
| Abila MIP Fund Accounting (Community Brands) | `mip_fund_accounting` | `MIP_FUND_ACCOUNTING_BASE_URL` *(url)*, `MIP_FUND_ACCOUNTING_TOKEN` |
| Miro | `miro` | `MIRO_BASE_URL` *(url)*, `MIRO_TOKEN` |
| MISP Threat Sharing Platform | `misp` | `MISP_BASE_URL` *(url)*, `MISP_TOKEN` |
| Mistral AI REST API | `mistral_ai` | `MISTRAL_AI_BASE_URL` *(url)*, `MISTRAL_AI_TOKEN` |
| Mitchell International claims management | `mitchell_international` | `MITCHELL_INTERNATIONAL_BASE_URL` *(url)*, `MITCHELL_INTERNATIONAL_TOKEN` |
| Mitel CloudLink REST API | `mitel` | `MITEL_BASE_URL` *(url)*, `MITEL_TOKEN` |
| Mitratech legal operations (TAP) | `mitratech` | `MITRATECH_BASE_URL` *(url)*, `MITRATECH_TOKEN` |
| Mixmax sales engagement | `mixmax` | `MIXMAX_BASE_URL` *(url)*, `MIXMAX_TOKEN` |
| Mixpanel | `mixpanel` | `MIXPANEL_PROJECT_ID` *(url)*, `MIXPANEL_PROJECT_TOKEN`, `MIXPANEL_SERVICE_SECRET` |
| MLS Grid (RESO Web API aggregator) REST/OData | `mlsgrid` | `MLSGRID_BASE_URL` *(url)*, `MLSGRID_TOKEN` |
| MobileMonkey chatbot REST API | `mobilemonkey` | `MOBILEMONKEY_BASE_URL` *(url)*, `MOBILEMONKEY_TOKEN` |
| MobileServe volunteer hour tracking | `mobileserve` | `MOBILESERVE_BASE_URL` *(url)*, `MOBILESERVE_TOKEN` |
| Modal REST API (serverless functions/model deployments) | `modal_labs` | `MODAL_LABS_BASE_URL` *(url)*, `MODAL_LABS_TOKEN` |
| Mode Analytics | `mode` | `MODE_BASE_URL` *(url)*, `MODE_TOKEN` |
| Modern Hire (HireVue) assessment | `modern_hire` | `MODERN_HIRE_BASE_URL` *(url)*, `MODERN_HIRE_TOKEN` |
| Modern Treasury REST (payments/ledgers/reconciliation) | `modern_treasury` | `MODERN_TREASURY_BASE_URL` *(url)*, `MODERN_TREASURY_TOKEN` |
| ModMed (Modernizing Medicine) EHR REST/FHIR API | `modmed` | `MODMED_BASE_URL` *(url)*, `MODMED_TOKEN` |
| Modrinth REST API (game mod hosting) | `modrinth` | `MODRINTH_BASE_URL` *(url)*, `MODRINTH_TOKEN` |
| Modulr embedded banking REST API (UK) | `modulr` | `MODULR_BASE_URL` *(url)*, `MODULR_TOKEN` |
| MoEngage REST API | `moengage` | `MOENGAGE_BASE_URL` *(url)*, `MOENGAGE_TOKEN` |
| Mojang/Minecraft Services REST API | `mojang` | `MOJANG_BASE_URL` *(url)*, `MOJANG_TOKEN` |
| Mollie payments REST API | `mollie` | `MOLLIE_BASE_URL` *(url)*, `MOLLIE_TOKEN` |
| Momentum.io revenue workflow | `momentum` | `MOMENTUM_BASE_URL` *(url)*, `MOMENTUM_TOKEN` |
| Monarch Money personal finance | `monarch_money` | `MONARCH_MONEY_BASE_URL` *(url)*, `MONARCH_MONEY_TOKEN` |
| monday.com | `monday` | `MONDAY_BASE_URL` *(url)*, `MONDAY_TOKEN` |
| Moneris payments REST API | `moneris` | `MONERIS_BASE_URL` *(url)*, `MONERIS_TOKEN` |
| Monese banking | `monese` | `MONESE_BASE_URL` *(url)*, `MONESE_TOKEN` |
| Monetate REST API (personalization) | `monetate` | `MONETATE_BASE_URL` *(url)*, `MONETATE_TOKEN` |
| Moneybird accounting REST API (Netherlands) | `moneybird` | `MONEYBIRD_BASE_URL` *(url)*, `MONEYBIRD_TOKEN` |
| Money Forward accounting/finance REST API (Japan) | `moneyforward` | `MONEYFORWARD_BASE_URL` *(url)*, `MONEYFORWARD_TOKEN` |
| MoneyGram remittance | `moneygram` | `MONEYGRAM_BASE_URL` *(url)*, `MONEYGRAM_TOKEN` |
| Monograph architecture firm project management | `monograph` | `MONOGRAPH_BASE_URL` *(url)*, `MONOGRAPH_TOKEN` |
| Monzo open banking | `monzo` | `MONZO_BASE_URL` *(url)*, `MONZO_TOKEN` |
| Moodle LMS REST (webservice) API | `moodle` | `MOODLE_BASE_URL` *(url)*, `MOODLE_TOKEN` |
| MoonPay on/off-ramp | `moonpay` | `MOONPAY_BASE_URL` *(url)*, `MOONPAY_TOKEN` |
| Moosend REST API | `moosend` | `MOOSEND_BASE_URL` *(url)*, `MOOSEND_TOKEN` |
| Morningstar investment data | `morningstar` | `MORNINGSTAR_BASE_URL` *(url)*, `MORNINGSTAR_TOKEN` |
| Mosaic FP&A/strategic finance | `mosaic_tech` | `MOSAIC_TECH_BASE_URL` *(url)*, `MOSAIC_TECH_TOKEN` |
| MosaicML/Databricks Model Serving REST API | `mosaicml` | `MOSAICML_BASE_URL` *(url)*, `MOSAICML_TOKEN` |
| MotherDuck (cloud DuckDB) REST API | `motherduck` | `MOTHERDUCK_BASE_URL` *(url)*, `MOTHERDUCK_TOKEN` |
| Motion Array stock templates/media | `motion_array` | `MOTION_ARRAY_BASE_URL` *(url)*, `MOTION_ARRAY_TOKEN` |
| MotionElements stock video/motion graphics | `motionelements` | `MOTIONELEMENTS_BASE_URL` *(url)*, `MOTIONELEMENTS_TOKEN` |
| Motive (KeepTruckin) fleet-management REST API | `motive_fleet` | `MOTIVE_FLEET_BASE_URL` *(url)*, `MOTIVE_FLEET_TOKEN` |
| Movable Ink REST API | `movableink` | `MOVABLEINK_BASE_URL` *(url)*, `MOVABLEINK_TOKEN` |
| Moveworks AI support/service desk | `moveworks` | `MOVEWORKS_BASE_URL` *(url)*, `MOVEWORKS_TOKEN` |
| mParticle CDP REST API | `mparticle` | `MPARTICLE_BASE_URL` *(url)*, `MPARTICLE_TOKEN` |
| MRI Software property management REST API | `mrisoftware` | `MRISOFTWARE_BASE_URL` *(url)*, `MRISOFTWARE_TOKEN` |
| MRPeasy manufacturing/MRP | `mrpeasy` | `MRPEASY_BASE_URL` *(url)*, `MRPEASY_TOKEN` |
| MSG91 SMS/communication REST API (India) | `msg91` | `MSG91_BASE_URL` *(url)*, `MSG91_TOKEN` |
| MuleSoft Anypoint | `mulesoft` | `MULESOFT_BASE_URL` *(url)*, `MULESOFT_TOKEN` |
| Multiplier global payroll/EOR | `multiplier_hr` | `MULTIPLIER_HR_BASE_URL` *(url)*, `MULTIPLIER_HR_TOKEN` |
| Mural whiteboard | `mural` | `MURAL_BASE_URL` *(url)*, `MURAL_TOKEN` |
| Musicbed music licensing | `musicbed` | `MUSICBED_BASE_URL` *(url)*, `MUSICBED_TOKEN` |
| Muvi OTT/streaming platform builder | `muvi` | `MUVI_BASE_URL` *(url)*, `MUVI_TOKEN` |
| Mux video streaming REST API | `mux` | `MUX_BASE_URL` *(url)*, `MUX_TOKEN` |
| MX financial data platform | `mx_platform` | `MX_PLATFORM_BASE_URL` *(url)*, `MX_PLATFORM_TOKEN` |
| MyCase legal practice management | `mycase` | `MYCASE_BASE_URL` *(url)*, `MYCASE_TOKEN` |
| MyFitnessPal partner | `myfitnesspal` | `MYFITNESSPAL_BASE_URL` *(url)*, `MYFITNESSPAL_TOKEN` |
| MYOB accounting | `myob` | `MYOB_BASE_URL` *(url)*, `MYOB_TOKEN` |
| myON reading platform | `myon` | `MYON_BASE_URL` *(url)*, `MYON_TOKEN` |
| myPOS payments REST API | `mypos` | `MYPOS_BASE_URL` *(url)*, `MYPOS_TOKEN` |
| MySchoolBucks school payments | `myschoolbucks` | `MYSCHOOLBUCKS_BASE_URL` *(url)*, `MYSCHOOLBUCKS_TOKEN` |
| MyTime scheduling | `mytime` | `MYTIME_BASE_URL` *(url)*, `MYTIME_TOKEN` |
| MyZone | `myzone` | `MYZONE_BASE_URL` *(url)*, `MYZONE_TOKEN` |
| N26 neobank | `n26` | `N26_BASE_URL` *(url)*, `N26_TOKEN` |
| n8n workflow-automation | `n8n` | `N8N_BASE_URL` *(url)*, `N8N_TOKEN` |
| Namely HR platform | `namely` | `NAMELY_BASE_URL` *(url)*, `NAMELY_TOKEN` |
| Narvar post-purchase/returns REST API | `narvar` | `NARVAR_BASE_URL` *(url)*, `NARVAR_TOKEN` |
| NationBuilder | `nationbuilder` | `NATIONBUILDER_BASE_URL` *(url)*, `NATIONBUILDER_TOKEN` |
| Navan (TripActions) travel & expense | `navan` | `NAVAN_BASE_URL` *(url)*, `NAVAN_TOKEN` |
| Naver Cloud Platform REST API (South Korea) | `naver` | `NAVER_BASE_URL` *(url)*, `NAVER_TOKEN` |
| NAVEX Global (IntegrityPoint/RiskRate) | `navex` | `NAVEX_BASE_URL` *(url)*, `NAVEX_TOKEN` |
| NAVEX (ethics/compliance) | `navex_global` | `NAVEX_GLOBAL_BASE_URL` *(url)*, `NAVEX_GLOBAL_TOKEN` |
| Ncontracts bank compliance/risk management | `ncontracts` | `NCONTRACTS_BASE_URL` *(url)*, `NCONTRACTS_TOKEN` |
| NCR Aloha POS | `ncr_aloha` | `NCR_ALOHA_BASE_URL` *(url)*, `NCR_ALOHA_TOKEN` |
| NCR Voyix retail/POS REST API | `ncr_voyix` | `NCR_VOYIX_BASE_URL` *(url)*, `NCR_VOYIX_TOKEN` |
| Nearpod | `nearpod` | `NEARPOD_BASE_URL` *(url)*, `NEARPOD_TOKEN` |
| Nelnet Campus Commerce (tuition payments) | `nelnet_campus_commerce` | `NELNET_CAMPUS_COMMERCE_BASE_URL` *(url)*, `NELNET_CAMPUS_COMMERCE_TOKEN` |
| Neo4j HTTP API (Cypher) | `neo4j` | `NEO4J_BASE_URL` *(url)*, `NEO4J_TOKEN` |
| NEOGOV public-sector HR/talent | `neogov` | `NEOGOV_BASE_URL` *(url)*, `NEOGOV_TOKEN` |
| Neon Postgres management REST API | `neon` | `NEON_BASE_URL` *(url)*, `NEON_TOKEN` |
| Neon CRM (Neon One) | `neoncrm` | `NEONCRM_BASE_URL` *(url)*, `NEONCRM_TOKEN` |
| Neptune.ai REST API (ML experiment tracking) | `neptune_ai` | `NEPTUNE_AI_BASE_URL` *(url)*, `NEPTUNE_AI_TOKEN` |
| Netcore Cloud customer engagement/push REST API | `netcore_cloud` | `NETCORE_CLOUD_BASE_URL` *(url)*, `NETCORE_CLOUD_TOKEN` |
| NetDocuments legal document management | `netdocuments` | `NETDOCUMENTS_BASE_URL` *(url)*, `NETDOCUMENTS_TOKEN` |
| NetHunt CRM | `nethunt` | `NETHUNT_BASE_URL` *(url)*, `NETHUNT_TOKEN` |
| Netlify REST API | `netlify` | `NETLIFY_BASE_URL` *(url)*, `NETLIFY_TOKEN` |
| Netomi conversational AI REST API | `netomi` | `NETOMI_BASE_URL` *(url)*, `NETOMI_TOKEN` |
| Netskope | `netskope` | `NETSKOPE_BASE_URL` *(url)*, `NETSKOPE_TOKEN` |
| Oracle NetSuite SuiteTalk | `netsuite` | `NETSUITE_BASE_URL` *(url)*, `NETSUITE_TOKEN` |
| Network International payments REST API (MENA) | `network_international` | `NETWORK_INTERNATIONAL_BASE_URL` *(url)*, `NETWORK_INTERNATIONAL_TOKEN` |
| Network for Good | `networkforgood` | `NETWORKFORGOOD_BASE_URL` *(url)*, `NETWORKFORGOOD_TOKEN` |
| Newegg Marketplace REST API | `newegg` | `NEWEGG_BASE_URL` *(url)*, `NEWEGG_TOKEN` |
| Newforma project information management (AEC) | `newforma` | `NEWFORMA_BASE_URL` *(url)*, `NEWFORMA_TOKEN` |
| New Relic | `newrelic` | `NEWRELIC_BASE_URL` *(url)*, `NEWRELIC_TOKEN` |
| Newsela | `newsela` | `NEWSELA_BASE_URL` *(url)*, `NEWSELA_TOKEN` |
| Newspack (WordPress VIP publishing) | `newspack` | `NEWSPACK_BASE_URL` *(url)*, `NEWSPACK_TOKEN` |
| Nexi (XPay) payments REST API | `nexi` | `NEXI_BASE_URL` *(url)*, `NEXI_TOKEN` |
| Nextdoor Business Partner REST API | `nextdoor` | `NEXTDOOR_BASE_URL` *(url)*, `NEXTDOOR_TOKEN` |
| NextGen Healthcare EHR REST API | `nextgen_healthcare` | `NEXTGEN_HEALTHCARE_BASE_URL` *(url)*, `NEXTGEN_HEALTHCARE_TOKEN` |
| Nextiva business phone/UCaaS REST API | `nextiva` | `NEXTIVA_BASE_URL` *(url)*, `NEXTIVA_TOKEN` |
| NICE Actimize financial crime compliance | `nice_actimize` | `NICE_ACTIMIZE_BASE_URL` *(url)*, `NICE_ACTIMIZE_TOKEN` |
| NICE CXone | `nice_cxone` | `NICE_CXONE_BASE_URL` *(url)*, `NICE_CXONE_TOKEN` |
| NiceLabel Cloud label management | `nicelabel` | `NICELABEL_BASE_URL` *(url)*, `NICELABEL_TOKEN` |
| Nicereply | `nicereply` | `NICEREPLY_BASE_URL` *(url)*, `NICEREPLY_TOKEN` |
| Apache NiFi REST API | `nifi` | `NIFI_BASE_URL` *(url)*, `NIFI_TOKEN` |
| Nimble CRM | `nimble` | `NIMBLE_BASE_URL` *(url)*, `NIMBLE_TOKEN` |
| Nimbus Note | `nimbus_note` | `NIMBUS_NOTE_BASE_URL` *(url)*, `NIMBUS_NOTE_TOKEN` |
| Ninja Forms (WordPress) | `ninja_forms` | `NINJA_FORMS_BASE_URL` *(url)*, `NINJA_FORMS_TOKEN` |
| NinjaTrader brokerage | `ninjatrader` | `NINJATRADER_BASE_URL` *(url)*, `NINJATRADER_TOKEN` |
| Ninox REST API (no-code database) | `ninox` | `NINOX_BASE_URL` *(url)*, `NINOX_TOKEN` |
| Nitro PDF | `nitro_pdf` | `NITRO_PDF_BASE_URL` *(url)*, `NITRO_PDF_TOKEN` |
| Nitro Sign | `nitro_sign` | `NITRO_SIGN_BASE_URL` *(url)*, `NITRO_SIGN_TOKEN` |
| Nium cross-border payments REST API (Singapore) | `nium` | `NIUM_BASE_URL` *(url)*, `NIUM_TOKEN` |
| NLP Cloud REST API | `nlp_cloud` | `NLP_CLOUD_BASE_URL` *(url)*, `NLP_CLOUD_TOKEN` |
| NocoDB | `nocodb` | `NOCODB_BASE_URL` *(url)*, `NOCODB_TOKEN` |
| Noname Security API Security Platform | `noname_security` | `NONAME_SECURITY_BASE_URL` *(url)*, `NONAME_SECURITY_TOKEN` |
| nopCommerce REST API (plugin-based) | `nopcommerce` | `NOPCOMMERCE_BASE_URL` *(url)*, `NOPCOMMERCE_TOKEN` |
| Normalyze Data Security Posture Management | `normalyze` | `NORMALYZE_BASE_URL` *(url)*, `NORMALYZE_TOKEN` |
| Northbeam REST API (marketing attribution) | `northbeam` | `NORTHBEAM_BASE_URL` *(url)*, `NORTHBEAM_TOKEN` |
| Northflank REST API (cloud PaaS) | `northflank` | `NORTHFLANK_BASE_URL` *(url)*, `NORTHFLANK_TOKEN` |
| Nosto REST API (personalization) | `nosto` | `NOSTO_BASE_URL` *(url)*, `NOSTO_TOKEN` |
| The Noun Project REST API | `noun_project` | `NOUN_PROJECT_BASE_URL` *(url)*, `NOUN_PROJECT_TOKEN` |
| Novidea insurance distribution management | `novidea` | `NOVIDEA_BASE_URL` *(url)*, `NOVIDEA_TOKEN` |
| Novo small-business banking | `novo_bank` | `NOVO_BANK_BASE_URL` *(url)*, `NOVO_BANK_TOKEN` |
| Novu open-source notification infrastructure REST API | `novu` | `NOVU_BASE_URL` *(url)*, `NOVU_TOKEN` |
| NOWPayments crypto payments | `nowpayments` | `NOWPAYMENTS_BASE_URL` *(url)*, `NOWPAYMENTS_TOKEN` |
| Noyo benefits data connectivity | `noyo` | `NOYO_BASE_URL` *(url)*, `NOYO_TOKEN` |
| npm registry REST API | `npm_registry` | `NPM_REGISTRY_BASE_URL` *(url)*, `NPM_REGISTRY_TOKEN` |
| nTask project management | `ntask` | `NTASK_BASE_URL` *(url)*, `NTASK_TOKEN` |
| Nubank open finance REST API (Brazil) | `nubank` | `NUBANK_BASE_URL` *(url)*, `NUBANK_TOKEN` |
| Nucleus Security | `nucleus_security` | `NUCLEUS_SECURITY_BASE_URL` *(url)*, `NUCLEUS_SECURITY_TOKEN` |
| Nuclino | `nuclino` | `NUCLINO_BASE_URL` *(url)*, `NUCLINO_TOKEN` |
| Nuix e-discovery/investigation | `nuix` | `NUIX_BASE_URL` *(url)*, `NUIX_TOKEN` |
| Backlog (Nulab) | `nulab_backlog` | `NULAB_BACKLOG_BASE_URL` *(url)*, `NULAB_BACKLOG_TOKEN` |
| numverify phone number validation REST API | `numverify` | `NUMVERIFY_BASE_URL` *(url)*, `NUMVERIFY_TOKEN` |
| Nutshell CRM REST/JSON-RPC | `nutshell` | `NUTSHELL_BASE_URL` *(url)*, `NUTSHELL_TOKEN` |
| NVIDIA NIM/NGC REST API (model inference) | `nvidia_nim` | `NVIDIA_NIM_BASE_URL` *(url)*, `NVIDIA_NIM_TOKEN` |
| o9 Solutions integrated planning | `o9_solutions` | `O9_SOLUTIONS_BASE_URL` *(url)*, `O9_SOLUTIONS_TOKEN` |
| OANDA forex trading | `oanda` | `OANDA_BASE_URL` *(url)*, `OANDA_TOKEN` |
| Observable (Framework/Cloud) REST API | `observable` | `OBSERVABLE_BASE_URL` *(url)*, `OBSERVABLE_TOKEN` |
| Observe.AI contact-center conversation intelligence | `observeai` | `OBSERVEAI_BASE_URL` *(url)*, `OBSERVEAI_TOKEN` |
| Obsidian Security SaaS Security Posture | `obsidian_security` | `OBSIDIAN_SECURITY_BASE_URL` *(url)*, `OBSIDIAN_SECURITY_TOKEN` |
| OctoAI REST API (model inference) | `octoai` | `OCTOAI_BASE_URL` *(url)*, `OCTOAI_TOKEN` |
| Octopus Deploy | `octopus_deploy` | `OCTOPUS_BASE_URL` *(url)*, `OCTOPUS_TOKEN` |
| Odoo CRM REST/JSON-RPC (self-hosted) | `odoo` | `ODOO_BASE_URL` *(url)*, `ODOO_TOKEN` |
| Odysee (LBRY) video platform | `odysee` | `ODYSEE_BASE_URL` *(url)*, `ODYSEE_TOKEN` |
| Officevibe (Workleap) engagement | `officevibe` | `OFFICEVIBE_BASE_URL` *(url)*, `OFFICEVIBE_TOKEN` |
| Okendo REST API (reviews & loyalty) | `okendo` | `OKENDO_BASE_URL` *(url)*, `OKENDO_TOKEN` |
| Okta management | `okta` | `OKTA_BASE_URL` *(url)*, `OKTA_TOKEN` |
| OKX exchange | `okx` | `OKX_BASE_URL` *(url)*, `OKX_TOKEN` |
| Olark live chat | `olark` | `OLARK_BASE_URL` *(url)*, `OLARK_TOKEN` |
| Ollama Cloud REST API (self-hosted LLM inference) | `ollama_cloud` | `OLLAMA_CLOUD_BASE_URL` *(url)*, `OLLAMA_CLOUD_TOKEN` |
| Olo ordering | `olo` | `OLO_BASE_URL` *(url)*, `OLO_TOKEN` |
| Omie ERP REST API (Brazil) | `omie` | `OMIE_BASE_URL` *(url)*, `OMIE_TOKEN` |
| Omnify booking | `omnify` | `OMNIFY_BASE_URL` *(url)*, `OMNIFY_TOKEN` |
| Omnipresent global employment | `omnipresent` | `OMNIPRESENT_BASE_URL` *(url)*, `OMNIPRESENT_TOKEN` |
| Omnisend REST API | `omnisend` | `OMNISEND_BASE_URL` *(url)*, `OMNISEND_TOKEN` |
| Omnitracs fleet-management REST API | `omnitracs` | `OMNITRACS_BASE_URL` *(url)*, `OMNITRACS_TOKEN` |
| Omny Studio podcast hosting | `omny_studio` | `OMNY_STUDIO_BASE_URL` *(url)*, `OMNY_STUDIO_TOKEN` |
| OMP Plus supply-chain planning | `omp_plus` | `OMP_PLUS_BASE_URL` *(url)*, `OMP_PLUS_TOKEN` |
| ON24 webcast | `on24` | `ON24_BASE_URL` *(url)*, `ON24_TOKEN` |
| Hyland OnBase content management | `onbase` | `ONBASE_BASE_URL` *(url)*, `ONBASE_TOKEN` |
| OnceHub (ScheduleOnce) | `oncehub` | `ONCEHUB_BASE_URL` *(url)*, `ONCEHUB_TOKEN` |
| OnDeck small-business lending | `ondeck` | `ONDECK_BASE_URL` *(url)*, `ONDECK_TOKEN` |
| One (Walmart) fintech app | `one_finance` | `ONE_FINANCE_BASE_URL` *(url)*, `ONE_FINANCE_TOKEN` |
| One Inc insurance payments | `one_inc` | `ONE_INC_BASE_URL` *(url)*, `ONE_INC_TOKEN` |
| OneCause fundraising/auctions | `onecause` | `ONECAUSE_BASE_URL` *(url)*, `ONECAUSE_TOKEN` |
| Microsoft OneDrive REST (Graph) | `onedrive` | `ONEDRIVE_BASE_URL` *(url)*, `ONEDRIVE_TOKEN` |
| Oneflow contract/e-signature | `oneflow` | `ONEFLOW_BASE_URL` *(url)*, `ONEFLOW_TOKEN` |
| Onehub | `onehub` | `ONEHUB_BASE_URL` *(url)*, `ONEHUB_TOKEN` |
| OneLogin | `onelogin` | `ONELOGIN_BASE_URL` *(url)*, `ONELOGIN_TOKEN` |
| Microsoft OneNote REST (Graph) | `onenote` | `ONENOTE_BASE_URL` *(url)*, `ONENOTE_TOKEN` |
| OnePageCRM | `onepagecrm` | `ONEPAGECRM_BASE_URL` *(url)*, `ONEPAGECRM_TOKEN` |
| 1Password Connect/Business | `onepassword` | `ONEPASSWORD_BASE_URL` *(url)*, `ONEPASSWORD_TOKEN` |
| Oneserve field service management | `oneserve` | `ONESERVE_BASE_URL` *(url)*, `ONESERVE_TOKEN` |
| OneSignal REST API (push notifications) | `onesignal` | `ONESIGNAL_BASE_URL` *(url)*, `ONESIGNAL_TOKEN` |
| OneStream CPM/consolidation | `onestream` | `ONESTREAM_BASE_URL` *(url)*, `ONESTREAM_TOKEN` |
| OneTrust | `onetrust` | `ONETRUST_HOSTNAME` *(url)*, `ONETRUST_TOKEN` |
| OneTrust GRC/privacy platform REST (distinct from generic onetrust entry) | `onetrust_privacy` | `ONETRUST_PRIVACY_BASE_URL` *(url)*, `ONETRUST_PRIVACY_TOKEN` |
| Onfido identity verification/KYC | `onfido` | `ONFIDO_BASE_URL` *(url)*, `ONFIDO_TOKEN` |
| Onfleet last-mile delivery | `onfleet` | `ONFLEET_BASE_URL` *(url)*, `ONFLEET_TOKEN` |
| Onit legal operations/CLM | `onit_clm` | `ONIT_CLM_BASE_URL` *(url)*, `ONIT_CLM_TOKEN` |
| Onna e-discovery/knowledge integration | `onna` | `ONNA_BASE_URL` *(url)*, `ONNA_TOKEN` |
| Onomondo IoT SIM connectivity REST API | `onomondo` | `ONOMONDO_BASE_URL` *(url)*, `ONOMONDO_TOKEN` |
| OnPay payroll | `onpay` | `ONPAY_BASE_URL` *(url)*, `ONPAY_TOKEN` |
| Onshape (PTC) cloud CAD/PLM | `onshape` | `ONSHAPE_BASE_URL` *(url)*, `ONSHAPE_TOKEN` |
| Onspring GRC Platform | `onspring` | `ONSPRING_BASE_URL` *(url)*, `ONSPRING_TOKEN` |
| Ontraport CRM | `ontraport` | `ONTRAPORT_BASE_URL` *(url)*, `ONTRAPORT_TOKEN` |
| Ooma Office business phone REST API | `ooma` | `OOMA_BASE_URL` *(url)*, `OOMA_TOKEN` |
| Opal Security Access Management | `opal_security` | `OPAL_SECURITY_BASE_URL` *(url)*, `OPAL_SECURITY_TOKEN` |
| Siemens Opcenter MES | `opcenter` | `OPCENTER_BASE_URL` *(url)*, `OPCENTER_TOKEN` |
| OpenAI Platform REST API | `openai_platform` | `OPENAI_PLATFORM_BASE_URL` *(url)*, `OPENAI_PLATFORM_TOKEN` |
| OpenBOM bill-of-materials | `openbom` | `OPENBOM_BASE_URL` *(url)*, `OPENBOM_TOKEN` |
| OpenCart REST API (extension-based) | `opencart` | `OPENCART_BASE_URL` *(url)*, `OPENCART_TOKEN` |
| OpenDota REST API (Dota 2 stats) | `opendota` | `OPENDOTA_BASE_URL` *(url)*, `OPENDOTA_TOKEN` |
| OpenGov public-sector budgeting/permitting | `opengov` | `OPENGOV_BASE_URL` *(url)*, `OPENGOV_TOKEN` |
| OpenNode Bitcoin/Lightning payments | `opennode` | `OPENNODE_BASE_URL` *(url)*, `OPENNODE_TOKEN` |
| Openpay payments REST API (Mexico, BBVA) | `openpay_mx` | `OPENPAY_MX_BASE_URL` *(url)*, `OPENPAY_MX_TOKEN` |
| OpenPhone business phone | `openphone` | `OPENPHONE_BASE_URL` *(url)*, `OPENPHONE_TOKEN` |
| OpenSearch k-NN vector search REST API | `opensearch_vector` | `OPENSEARCH_VECTOR_BASE_URL` *(url)*, `OPENSEARCH_VECTOR_TOKEN` |
| Red Hat OpenShift API | `openshift` | `OPENSHIFT_BASE_URL` *(url)*, `OPENSHIFT_TOKEN` |
| OpenTable restaurant reservations REST API | `opentable` | `OPENTABLE_BASE_URL` *(url)*, `OPENTABLE_TOKEN` |
| OpenText content management | `opentext` | `OPENTEXT_BASE_URL` *(url)*, `OPENTEXT_TOKEN` |
| Oracle Hospitality OPERA Cloud PMS REST API | `opera_pms` | `OPERA_PMS_BASE_URL` *(url)*, `OPERA_PMS_TOKEN` |
| Oracle Opower utility customer-engagement REST API | `opower` | `OPOWER_BASE_URL` *(url)*, `OPOWER_TOKEN` |
| Opsgenie REST (incident mgmt) | `opsgenie` | `OPSGENIE_BASE_URL` *(url)*, `OPSGENIE_TOKEN` |
| Optimizely Content Cloud / Experimentation REST API | `optimizely` | `OPTIMIZELY_BASE_URL` *(url)*, `OPTIMIZELY_TOKEN` |
| Opus Clip AI video clipping | `opus_clip` | `OPUS_CLIP_BASE_URL` *(url)*, `OPUS_CLIP_TOKEN` |
| Oracle (ORDS) | `oracle` | `ORACLE_ORDS_URL` *(url)*, `ORACLE_ORDS_TOKEN` |
| Oracle Analytics Cloud REST API | `oracle_analytics` | `ORACLE_ANALYTICS_BASE_URL` *(url)*, `ORACLE_ANALYTICS_TOKEN` |
| Oracle HCM Cloud | `oracle_hcm_cloud` | `ORACLE_HCM_CLOUD_BASE_URL` *(url)*, `ORACLE_HCM_CLOUD_TOKEN` |
| Oracle Manufacturing Cloud | `oracle_mfg_cloud` | `ORACLE_MFG_CLOUD_BASE_URL` *(url)*, `ORACLE_MFG_CLOUD_TOKEN` |
| Oracle MICROS Simphony | `oracle_micros` | `ORACLE_MICROS_BASE_URL` *(url)*, `ORACLE_MICROS_TOKEN` |
| Oracle SCM Cloud | `oracle_scm_cloud` | `ORACLE_SCM_CLOUD_BASE_URL` *(url)*, `ORACLE_SCM_CLOUD_TOKEN` |
| Oracle WMS Cloud | `oracle_wms_cloud` | `ORACLE_WMS_CLOUD_BASE_URL` *(url)*, `ORACLE_WMS_CLOUD_TOKEN` |
| AppOmni SaaS Security Posture Management | `orca_iam` | `ORCA_IAM_BASE_URL` *(url)*, `ORCA_IAM_TOKEN` |
| Orca Security REST API | `orca_security` | `ORCA_SECURITY_BASE_URL` *(url)*, `ORCA_SECURITY_TOKEN` |
| Ordergroove subscription/retention REST API | `ordergroove` | `ORDERGROOVE_BASE_URL` *(url)*, `ORDERGROOVE_TOKEN` |
| Ordermark (Nextbite) order aggregation | `ordermark` | `ORDERMARK_BASE_URL` *(url)*, `ORDERMARK_TOKEN` |
| Ordoro shipping/inventory REST API | `ordoro` | `ORDORO_BASE_URL` *(url)*, `ORDORO_TOKEN` |
| Ordway subscription billing REST API | `ordway` | `ORDWAY_BASE_URL` *(url)*, `ORDWAY_TOKEN` |
| Origami Risk insurance/risk-management REST API | `origami_risk` | `ORIGAMI_RISK_BASE_URL` *(url)*, `ORIGAMI_RISK_TOKEN` |
| OroCommerce REST API | `oro_commerce` | `ORO_COMMERCE_BASE_URL` *(url)*, `ORO_COMMERCE_TOKEN` |
| OSIsoft PI System (AVEVA) REST API for industrial time-series data | `osisoft_pi` | `OSISOFT_PI_BASE_URL` *(url)*, `OSISOFT_PI_TOKEN` |
| osTicket REST (self-hosted) | `osticket` | `OSTICKET_BASE_URL` *(url)*, `OSTICKET_TOKEN` |
| Otter.ai transcription | `otter_ai` | `OTTER_AI_BASE_URL` *(url)*, `OTTER_AI_TOKEN` |
| OTTO Market ecommerce REST API (Germany) | `otto` | `OTTO_BASE_URL` *(url)*, `OTTO_TOKEN` |
| Otus K-12 assessment/gradebook | `otus` | `OTUS_BASE_URL` *(url)*, `OTUS_TOKEN` |
| Oura Ring | `oura` | `OURA_BASE_URL` *(url)*, `OURA_TOKEN` |
| Outbrain Amplify REST API | `outbrain` | `OUTBRAIN_BASE_URL` *(url)*, `OUTBRAIN_TOKEN` |
| Outplay sales engagement | `outplay` | `OUTPLAY_BASE_URL` *(url)*, `OUTPLAY_TOKEN` |
| Outreach | `outreach` | `OUTREACH_BASE_URL` *(url)*, `OUTREACH_TOKEN` |
| OutSystems REST (Integration Studio / Forge APIs) | `outsystems` | `OUTSYSTEMS_BASE_URL` *(url)*, `OUTSYSTEMS_TOKEN` |
| Ovatu scheduling | `ovatu` | `OVATU_BASE_URL` *(url)*, `OVATU_TOKEN` |
| Overloop (Prospect.io) sales engagement | `overloop` | `OVERLOOP_BASE_URL` *(url)*, `OVERLOOP_TOKEN` |
| Overstock (Bed Bath & Beyond) marketplace REST API | `overstock` | `OVERSTOCK_BASE_URL` *(url)*, `OVERSTOCK_TOKEN` |
| OVHcloud REST API | `ovhcloud` | `OVHCLOUD_BASE_URL` *(url)*, `OVHCLOUD_TOKEN` |
| Oyster HR global employment | `oyster_hr` | `OYSTER_HR_BASE_URL` *(url)*, `OYSTER_HR_TOKEN` |
| Ozonetel contact center | `ozonetel` | `OZONETEL_BASE_URL` *(url)*, `OZONETEL_TOKEN` |
| P0 Security Just-in-Time Access | `p0_security` | `P0_SECURITY_BASE_URL` *(url)*, `P0_SECURITY_TOKEN` |
| PACER federal court records | `pacer` | `PACER_BASE_URL` *(url)*, `PACER_TOKEN` |
| packagecloud.io REST API | `packagecloud` | `PACKAGECLOUD_BASE_URL` *(url)*, `PACKAGECLOUD_TOKEN` |
| HCP Packer REST API | `packer` | `PACKER_BASE_URL` *(url)*, `PACKER_TOKEN` |
| Paddle billing/payments REST API | `paddle` | `PADDLE_BASE_URL` *(url)*, `PADDLE_TOKEN` |
| PagerDuty | `pagerduty` | `PAGERDUTY_API_TOKEN`, `PAGERDUTY_EVENTS_KEY` |
| PagSeguro payments REST API (Brazil) | `pagseguro` | `PAGSEGURO_BASE_URL` *(url)*, `PAGSEGURO_TOKEN` |
| Palo Alto Networks (Cortex/Prisma) | `palo_alto` | `PALO_ALTO_BASE_URL` *(url)*, `PALO_ALTO_TOKEN` |
| PandaDoc document/e-signature | `pandadoc` | `PANDADOC_BASE_URL` *(url)*, `PANDADOC_TOKEN` |
| eversign e-signature | `pandasign_esign` | `PANDASIGN_ESIGN_BASE_URL` *(url)*, `PANDASIGN_ESIGN_TOKEN` |
| Pandle accounting | `pandle` | `PANDLE_BASE_URL` *(url)*, `PANDLE_TOKEN` |
| Pandorabots AIML chatbot REST API | `pandorabots` | `PANDORABOTS_BASE_URL` *(url)*, `PANDORABOTS_TOKEN` |
| Panoply (SQream) data platform REST API | `panoply` | `PANOPLY_BASE_URL` *(url)*, `PANOPLY_TOKEN` |
| Panopto video platform REST API | `panopto` | `PANOPTO_BASE_URL` *(url)*, `PANOPTO_TOKEN` |
| Panorama Education survey/analytics | `panorama_education` | `PANORAMA_EDUCATION_BASE_URL` *(url)*, `PANORAMA_EDUCATION_TOKEN` |
| Panorays Third-Party Risk | `panorays` | `PANORAYS_BASE_URL` *(url)*, `PANORAYS_TOKEN` |
| Panzura data management | `panzura` | `PANZURA_BASE_URL` *(url)*, `PANZURA_TOKEN` |
| Papaya Global payroll/EOR | `papaya_global` | `PAPAYA_GLOBAL_BASE_URL` *(url)*, `PAPAYA_GLOBAL_TOKEN` |
| Paperform | `paperform` | `PAPERFORM_BASE_URL` *(url)*, `PAPERFORM_TOKEN` |
| Paperspace Gradient REST API (ML model training/deployment) | `paperspace_gradient` | `PAPERSPACE_GRADIENT_BASE_URL` *(url)*, `PAPERSPACE_GRADIENT_TOKEN` |
| SolarWinds Papertrail log-management REST API | `papertrail` | `PAPERTRAIL_BASE_URL` *(url)*, `PAPERTRAIL_TOKEN` |
| PAR Brink POS | `par_brink` | `PAR_BRINK_BASE_URL` *(url)*, `PAR_BRINK_TOKEN` |
| Paradox (Olivia) conversational recruiting | `paradox_olivia` | `PARADOX_OLIVIA_BASE_URL` *(url)*, `PARADOX_OLIVIA_TOKEN` |
| Parchment transcript-exchange REST API | `parchment` | `PARCHMENT_BASE_URL` *(url)*, `PARCHMENT_TOKEN` |
| ParentSquare school-family communication | `parentsquare` | `PARENTSQUARE_BASE_URL` *(url)*, `PARENTSQUARE_TOKEN` |
| Particle Health clinical data REST/FHIR API | `particle_health` | `PARTICLE_HEALTH_BASE_URL` *(url)*, `PARTICLE_HEALTH_TOKEN` |
| Particle IoT device cloud | `particle_iot` | `PARTICLE_IOT_BASE_URL` *(url)*, `PARTICLE_IOT_TOKEN` |
| PartnerStack REST API | `partnerstack` | `PARTNERSTACK_BASE_URL` *(url)*, `PARTNERSTACK_TOKEN` |
| Patreon creator membership | `patreon` | `PATREON_BASE_URL` *(url)*, `PATREON_TOKEN` |
| Patriot Software payroll | `patriot_payroll` | `PATRIOT_PAYROLL_BASE_URL` *(url)*, `PATRIOT_PAYROLL_TOKEN` |
| Paxos | `paxos` | `PAXOS_BASE_URL` *(url)*, `PAXOS_TOKEN` |
| Paychex Flex | `paychex` | `PAYCHEX_BASE_URL` *(url)*, `PAYCHEX_TOKEN` |
| PayFit European payroll | `payfit` | `PAYFIT_BASE_URL` *(url)*, `PAYFIT_TOKEN` |
| Payhip REST API | `payhip` | `PAYHIP_BASE_URL` *(url)*, `PAYHIP_TOKEN` |
| PayHOA community association management | `payhoa` | `PAYHOA_BASE_URL` *(url)*, `PAYHOA_TOKEN` |
| PayIt government digital services/payments | `payit_gov` | `PAYIT_GOV_BASE_URL` *(url)*, `PAYIT_GOV_TOKEN` |
| Paylocity | `paylocity` | `PAYLOCITY_BASE_URL` *(url)*, `PAYLOCITY_TOKEN` |
| Paymo | `paymo` | `PAYMO_BASE_URL` *(url)*, `PAYMO_TOKEN` |
| Payoneer payouts REST API | `payoneer` | `PAYONEER_BASE_URL` *(url)*, `PAYONEER_TOKEN` |
| PayPal | `paypal` | `PAYPAL_BASE_URL` *(url)*, `PAYPAL_TOKEN` |
| Paysafe payments REST API | `paysafe` | `PAYSAFE_BASE_URL` *(url)*, `PAYSAFE_TOKEN` |
| Paystack payments REST API | `paystack` | `PAYSTACK_BASE_URL` *(url)*, `PAYSTACK_TOKEN` |
| PayTabs payments REST API | `paytabs` | `PAYTABS_BASE_URL` *(url)*, `PAYTABS_TOKEN` |
| Paytm payments REST API | `paytm` | `PAYTM_BASE_URL` *(url)*, `PAYTM_TOKEN` |
| Paytronix loyalty/gift | `paytronix` | `PAYTRONIX_BASE_URL` *(url)*, `PAYTRONIX_TOKEN` |
| PayU payments REST API | `payu` | `PAYU_BASE_URL` *(url)*, `PAYU_TOKEN` |
| PDF.co | `pdfco` | `PDFCO_BASE_URL` *(url)*, `PDFCO_TOKEN` |
| pdfFiller | `pdffiller` | `PDFFILLER_BASE_URL` *(url)*, `PDFFILLER_TOKEN` |
| Workday Peakon employee listening | `peakon` | `PEAKON_BASE_URL` *(url)*, `PEAKON_TOKEN` |
| Peek Pro booking | `peekpro` | `PEEKPRO_BASE_URL` *(url)*, `PEEKPRO_TOKEN` |
| Pega | `pega` | `PEGA_BASE_URL` *(url)*, `PEGA_TOKEN` |
| Pendo | `pendo` | `PENDO_BASE_URL` *(url)*, `PENDO_TOKEN` |
| Pennylane accounting REST API (France) | `pennylane` | `PENNYLANE_BASE_URL` *(url)*, `PENNYLANE_TOKEN` |
| Pentaho BI/BA Server | `pentaho` | `PENTAHO_BASE_URL` *(url)*, `PENTAHO_TOKEN` |
| Pentera Automated Security Validation | `pentera` | `PENTERA_BASE_URL` *(url)*, `PENTERA_TOKEN` |
| People.ai revenue intelligence | `peopleai` | `PEOPLEAI_BASE_URL` *(url)*, `PEOPLEAI_TOKEN` |
| Peoplebox OKR/performance | `peoplebox` | `PEOPLEBOX_BASE_URL` *(url)*, `PEOPLEBOX_TOKEN` |
| Percy (BrowserStack) visual-testing REST API | `percy` | `PERCY_BASE_URL` *(url)*, `PERCY_TOKEN` |
| PerfectGym | `perfectgym` | `PERFECTGYM_BASE_URL` *(url)*, `PERFECTGYM_TOKEN` |
| Perplexity AI REST API | `perplexity_ai` | `PERPLEXITY_AI_BASE_URL` *(url)*, `PERPLEXITY_AI_TOKEN` |
| PersistIQ sales engagement | `persistiq` | `PERSISTIQ_BASE_URL` *(url)*, `PERSISTIQ_TOKEN` |
| Persona identity verification/KYC | `persona_kyc` | `PERSONA_KYC_BASE_URL` *(url)*, `PERSONA_KYC_TOKEN` |
| Personio HR management | `personio` | `PERSONIO_BASE_URL` *(url)*, `PERSONIO_TOKEN` |
| Pexels REST API | `pexels` | `PEXELS_BASE_URL` *(url)*, `PEXELS_TOKEN` |
| Neon serverless Postgres vector REST gateway | `pgvecto_serverless` | `PGVECTO_SERVERLESS_BASE_URL` *(url)*, `PGVECTO_SERVERLESS_TOKEN` |
| Vector-enabled Postgres (pgvector-as-a-service) REST gateway | `pgvector_cloud` | `PGVECTOR_CLOUD_BASE_URL` *(url)*, `PGVECTOR_CLOUD_TOKEN` |
| Phemex exchange | `phemex` | `PHEMEX_BASE_URL` *(url)*, `PHEMEX_TOKEN` |
| Phocas Software BI REST API | `phocas` | `PHOCAS_BASE_URL` *(url)*, `PHOCAS_TOKEN` |
| PhonePe business payments REST API (India) | `phonepe` | `PHONEPE_BASE_URL` *(url)*, `PHONEPE_TOKEN` |
| Photobucket image hosting | `photobucket` | `PHOTOBUCKET_BASE_URL` *(url)*, `PHOTOBUCKET_TOKEN` |
| Photon Engine REST/Webhook API (realtime game multiplayer) | `photonengine` | `PHOTONENGINE_BASE_URL` *(url)*, `PHOTONENGINE_TOKEN` |
| Picktime scheduling | `picktime` | `PICKTIME_BASE_URL` *(url)*, `PICKTIME_TOKEN` |
| PicMonkey photo/graphic editor | `picmonkey` | `PICMONKEY_BASE_URL` *(url)*, `PICMONKEY_TOKEN` |
| Picsart REST API | `picsart` | `PICSART_BASE_URL` *(url)*, `PICSART_TOKEN` |
| Pictory AI video creation | `pictory` | `PICTORY_BASE_URL` *(url)*, `PICTORY_TOKEN` |
| Pigment EPM / planning | `pigment` | `PIGMENT_BASE_URL` *(url)*, `PIGMENT_TOKEN` |
| Pike13 | `pike13` | `PIKE13_BASE_URL` *(url)*, `PIKE13_TOKEN` |
| Pimcore PIM/DXP REST API | `pimcore` | `PIMCORE_BASE_URL` *(url)*, `PIMCORE_TOKEN` |
| Pine Labs payments REST API (India) | `pine_labs` | `PINE_LABS_BASE_URL` *(url)*, `PINE_LABS_TOKEN` |
| Pinecast podcast hosting | `pinecast` | `PINECAST_BASE_URL` *(url)*, `PINECAST_TOKEN` |
| Pinecone vector database REST API | `pinecone` | `PINECONE_BASE_URL` *(url)*, `PINECONE_TOKEN` |
| Pingdom REST API | `pingdom` | `PINGDOM_BASE_URL` *(url)*, `PINGDOM_TOKEN` |
| Ping Identity (PingOne) | `pingone` | `PINGONE_BASE_URL` *(url)*, `PINGONE_TOKEN` |
| Pinterest REST API | `pinterest` | `PINTEREST_BASE_URL` *(url)*, `PINTEREST_TOKEN` |
| Pinterest Ads API (Pinterest API v5) | `pinterestads` | `PINTERESTADS_BASE_URL` *(url)*, `PINTERESTADS_TOKEN` |
| Pipedream REST API (workflows/sources) | `pipedream` | `PIPEDREAM_BASE_URL` *(url)*, `PIPEDREAM_TOKEN` |
| Pipedrive | `pipedrive` | `PIPEDRIVE_BASE_URL` *(url)*, `PIPEDRIVE_TOKEN` |
| Pipeline CRM (formerly PipelineDeals) | `pipelinecrm` | `PIPELINECRM_BASE_URL` *(url)*, `PIPELINECRM_TOKEN` |
| Pipeliner CRM | `pipeliner` | `PIPELINER_BASE_URL` *(url)*, `PIPELINER_TOKEN` |
| Pivotal Tracker | `pivotal_tracker` | `PIVOTAL_TRACKER_BASE_URL` *(url)*, `PIVOTAL_TRACKER_TOKEN` |
| Pixabay REST API | `pixabay` | `PIXABAY_BASE_URL` *(url)*, `PIXABAY_TOKEN` |
| Pixieset photography gallery/CRM | `pixieset` | `PIXIESET_BASE_URL` *(url)*, `PIXIESET_TOKEN` |
| Pixlr photo editing | `pixlr` | `PIXLR_BASE_URL` *(url)*, `PIXLR_TOKEN` |
| Placester real estate website/IDX | `placester` | `PLACESTER_BASE_URL` *(url)*, `PLACESTER_TOKEN` |
| Plaid | `plaid` | `PLAID_CLIENT_ID` *(url)*, `PLAID_SECRET` |
| Plaid Transfer (ACH) REST (distinct from generic plaid entry) | `plaid_transfer` | `PLAID_TRANSFER_BASE_URL` *(url)*, `PLAID_TRANSFER_TOKEN` |
| Planday scheduling | `planday` | `PLANDAY_BASE_URL` *(url)*, `PLANDAY_TOKEN` |
| PlanetScale REST API | `planetscale` | `PLANETSCALE_BASE_URL` *(url)*, `PLANETSCALE_TOKEN` |
| Planful EPM | `planful` | `PLANFUL_BASE_URL` *(url)*, `PLANFUL_TOKEN` |
| PlanGrid (Autodesk) construction field collaboration | `plangrid` | `PLANGRID_BASE_URL` *(url)*, `PLANGRID_TOKEN` |
| Planhat customer success | `planhat` | `PLANHAT_BASE_URL` *(url)*, `PLANHAT_TOKEN` |
| PlanSource benefits administration | `plansource` | `PLANSOURCE_BASE_URL` *(url)*, `PLANSOURCE_TOKEN` |
| Planview | `planview` | `PLANVIEW_BASE_URL` *(url)*, `PLANVIEW_TOKEN` |
| Plataine industrial IoT optimization | `plataine` | `PLATAINE_BASE_URL` *(url)*, `PLATAINE_TOKEN` |
| Plausible | `plausible` | `PLAUSIBLE_HOST` *(url)*, `PLAUSIBLE_SITE_ID` *(url)*, `PLAUSIBLE_API_KEY` |
| Microsoft Azure PlayFab REST API (game backend) | `playfab` | `PLAYFAB_BASE_URL` *(url)*, `PLAYFAB_TOKEN` |
| PlayMetrics | `playmetrics` | `PLAYMETRICS_BASE_URL` *(url)*, `PLAYMETRICS_TOKEN` |
| PlayStation Network REST API | `playstation` | `PLAYSTATION_BASE_URL` *(url)*, `PLAYSTATION_TOKEN` |
| Playvox contact-center QA/workforce | `playvox` | `PLAYVOX_BASE_URL` *(url)*, `PLAYVOX_TOKEN` |
| Pleo spend-management | `pleo` | `PLEO_BASE_URL` *(url)*, `PLEO_TOKEN` |
| Plex Manufacturing Cloud (Rockwell) | `plex_systems` | `PLEX_SYSTEMS_BASE_URL` *(url)*, `PLEX_SYSTEMS_TOKEN` |
| Plivo REST API | `plivo` | `PLIVO_BASE_URL` *(url)*, `PLIVO_TOKEN` |
| Plooto payments automation | `plooto` | `PLOOTO_BASE_URL` *(url)*, `PLOOTO_TOKEN` |
| Plum Voice IVR/voice REST API | `plum_voice` | `PLUM_VOICE_BASE_URL` *(url)*, `PLUM_VOICE_TOKEN` |
| Plus500 trading | `plus500` | `PLUS500_BASE_URL` *(url)*, `PLUS500_TOKEN` |
| PocketGuard budgeting | `pocketguard` | `POCKETGUARD_BASE_URL` *(url)*, `POCKETGUARD_TOKEN` |
| Podbean podcast hosting | `podbean` | `PODBEAN_BASE_URL` *(url)*, `PODBEAN_TOKEN` |
| Podchaser podcast database | `podchaser` | `PODCHASER_BASE_URL` *(url)*, `PODCHASER_TOKEN` |
| Podia creator platform (courses, podcasts, digital products) | `podia` | `PODIA_BASE_URL` *(url)*, `PODIA_TOKEN` |
| Podigee podcast hosting | `podigee` | `PODIGEE_BASE_URL` *(url)*, `PODIGEE_TOKEN` |
| Podio | `podio` | `PODIO_BASE_URL` *(url)*, `PODIO_TOKEN` |
| Podium REST API (customer messaging/engagement) | `podium` | `PODIUM_BASE_URL` *(url)*, `PODIUM_TOKEN` |
| Point App (Points of Light) volunteer | `pointapp` | `POINTAPP_BASE_URL` *(url)*, `POINTAPP_TOKEN` |
| Polar Flow/AccessLink | `polar_flow` | `POLAR_FLOW_BASE_URL` *(url)*, `POLAR_FLOW_TOKEN` |
| Pollfish | `pollfish` | `POLLFISH_BASE_URL` *(url)*, `POLLFISH_TOKEN` |
| Poloniex exchange | `poloniex` | `POLONIEX_BASE_URL` *(url)*, `POLONIEX_TOKEN` |
| Polytomic (reverse ETL / sync) REST API | `polytomic` | `POLYTOMIC_BASE_URL` *(url)*, `POLYTOMIC_TOKEN` |
| Pond5 stock video/audio | `pond5` | `POND5_BASE_URL` *(url)*, `POND5_TOKEN` |
| Popmenu | `popmenu` | `POPMENU_BASE_URL` *(url)*, `POPMENU_TOKEN` |
| Populi small-college SIS | `populi` | `POPULI_BASE_URL` *(url)*, `POPULI_TOKEN` |
| Portable.io ETL REST API | `portable` | `PORTABLE_BASE_URL` *(url)*, `PORTABLE_TOKEN` |
| Portainer container-management REST API | `portainer` | `PORTAINER_BASE_URL` *(url)*, `PORTAINER_TOKEN` |
| Pory REST API (no-code website builder from data) | `pory` | `PORY_BASE_URL` *(url)*, `PORY_TOKEN` |
| PostHog | `posthog` | `POSTHOG_HOST` *(url)*, `POSTHOG_PROJECT_ID` *(url)*, `POSTHOG_API_KEY`, `POSTHOG_PERSONAL_API_KEY` |
| Postmark REST API | `postmark` | `POSTMARK_BASE_URL` *(url)*, `POSTMARK_TOKEN` |
| Postmates (Uber) delivery | `postmates` | `POSTMATES_BASE_URL` *(url)*, `POSTMATES_TOKEN` |
| PostNord logistics REST API (Nordics) | `postnord` | `POSTNORD_BASE_URL` *(url)*, `POSTNORD_TOKEN` |
| Postscript REST API (SMS marketing) | `postscript` | `POSTSCRIPT_BASE_URL` *(url)*, `POSTSCRIPT_TOKEN` |
| Microsoft Power Automate management | `power_automate` | `POWER_AUTOMATE_BASE_URL` *(url)*, `POWER_AUTOMATE_TOKEN` |
| Microsoft Power Apps / Dataverse | `powerapps` | `POWERAPPS_BASE_URL` *(url)*, `POWERAPPS_TOKEN` |
| Microsoft Power BI | `powerbi` | `POWERBI_BASE_URL` *(url)*, `POWERBI_TOKEN` |
| PowerReviews REST API | `powerreviews` | `POWERREVIEWS_BASE_URL` *(url)*, `POWERREVIEWS_TOKEN` |
| PowerSchool SIS REST API | `powerschool` | `POWERSCHOOL_BASE_URL` *(url)*, `POWERSCHOOL_TOKEN` |
| Poynt (GoDaddy) POS/payments REST API | `poynt` | `POYNT_BASE_URL` *(url)*, `POYNT_TOKEN` |
| Practice Fusion EHR REST API | `practice_fusion` | `PRACTICE_FUSION_BASE_URL` *(url)*, `PRACTICE_FUSION_TOKEN` |
| PracticePanther legal practice management | `practicepanther` | `PRACTICEPANTHER_BASE_URL` *(url)*, `PRACTICEPANTHER_TOKEN` |
| Praxedo field service management | `praxedo` | `PRAXEDO_BASE_URL` *(url)*, `PRAXEDO_TOKEN` |
| Predibase REST API (LLM fine-tuning/serving) | `predibase` | `PREDIBASE_BASE_URL` *(url)*, `PREDIBASE_TOKEN` |
| Prefect Cloud/Server REST API | `prefect` | `PREFECT_BASE_URL` *(url)*, `PREFECT_TOKEN` |
| Preset (hosted Superset) REST API | `preset` | `PRESET_BASE_URL` *(url)*, `PRESET_TOKEN` |
| PrestaShop Webservice | `prestashop` | `PRESTASHOP_BASE_URL` *(url)*, `PRESTASHOP_TOKEN` |
| Presto (PrestoDB) REST API | `presto` | `PRESTO_BASE_URL` *(url)*, `PRESTO_TOKEN` |
| Prevalent Third-Party Risk Management | `prevalent` | `PREVALENT_BASE_URL` *(url)*, `PREVALENT_TOKEN` |
| Prezi presentation platform | `prezi` | `PREZI_BASE_URL` *(url)*, `PREZI_TOKEN` |
| Oracle Primavera P6 project scheduling | `primavera_p6` | `PRIMAVERA_P6_BASE_URL` *(url)*, `PRIMAVERA_P6_TOKEN` |
| Palo Alto Networks Prisma Cloud REST API | `prisma_cloud` | `PRISMA_CLOUD_BASE_URL` *(url)*, `PRISMA_CLOUD_TOKEN` |
| Prismic headless CMS REST API | `prismic` | `PRISMIC_BASE_URL` *(url)*, `PRISMIC_TOKEN` |
| Probely Web/API Vulnerability Scanning | `probely` | `PROBELY_BASE_URL` *(url)*, `PROBELY_TOKEN` |
| Procore construction project management | `procore` | `PROCORE_BASE_URL` *(url)*, `PROCORE_TOKEN` |
| Prodsmart (Autodesk) shop-floor MES | `prodsmart` | `PRODSMART_BASE_URL` *(url)*, `PRODSMART_TOKEN` |
| Productboard | `productboard` | `PRODUCTBOARD_BASE_URL` *(url)*, `PRODUCTBOARD_TOKEN` |
| GE Digital Proficy (historian/MES) | `proficy` | `PROFICY_BASE_URL` *(url)*, `PROFICY_TOKEN` |
| project44 supply-chain visibility REST API | `project44` | `PROJECT44_BASE_URL` *(url)*, `PROJECT44_TOKEN` |
| ProLaw (Thomson Reuters) legal practice management | `prolaw` | `PROLAW_BASE_URL` *(url)*, `PROLAW_TOKEN` |
| ProofHub | `proofhub` | `PROOFHUB_BASE_URL` *(url)*, `PROOFHUB_TOKEN` |
| Proofpoint | `proofpoint` | `PROOFPOINT_BASE_URL` *(url)*, `PROOFPOINT_TOKEN` |
| Propel PLM (built on Salesforce) | `propel_plm` | `PROPEL_PLM_BASE_URL` *(url)*, `PROPEL_PLM_TOKEN` |
| Property Matrix property management | `propertymatrix` | `PROPERTYMATRIX_BASE_URL` *(url)*, `PROPERTYMATRIX_TOKEN` |
| Propertyware (RealPage) property management REST/XML API | `propertyware` | `PROPERTYWARE_BASE_URL` *(url)*, `PROPERTYWARE_TOKEN` |
| Prophix FP&A/CPM | `prophix` | `PROPHIX_BASE_URL` *(url)*, `PROPHIX_TOKEN` |
| Proposify | `proposify` | `PROPOSIFY_BASE_URL` *(url)*, `PROPOSIFY_TOKEN` |
| Prosper peer-to-peer lending | `prosper` | `PROSPER_BASE_URL` *(url)*, `PROSPER_TOKEN` |
| Prove Identity phone verification REST API | `prove_identity` | `PROVE_IDENTITY_BASE_URL` *(url)*, `PROVE_IDENTITY_TOKEN` |
| Przelewy24 (P24) payments REST API (Poland) | `przelewy24` | `PRZELEWY24_BASE_URL` *(url)*, `PRZELEWY24_TOKEN` |
| Public.com brokerage | `public_com` | `PUBLIC_COM_BASE_URL` *(url)*, `PUBLIC_COM_TOKEN` |
| Publitas digital publishing (catalogs) | `publitas` | `PUBLITAS_BASE_URL` *(url)*, `PUBLITAS_TOKEN` |
| PubNub realtime pub/sub REST API | `pubnub` | `PUBNUB_BASE_URL` *(url)*, `PUBNUB_TOKEN` |
| Punchh loyalty | `punchh` | `PUNCHH_BASE_URL` *(url)*, `PUNCHH_TOKEN` |
| Punchpass | `punchpass` | `PUNCHPASS_BASE_URL` *(url)*, `PUNCHPASS_TOKEN` |
| Puppet Enterprise REST API | `puppet` | `PUPPET_BASE_URL` *(url)*, `PUPPET_TOKEN` |
| PushEngage REST API | `pushengage` | `PUSHENGAGE_BASE_URL` *(url)*, `PUSHENGAGE_TOKEN` |
| Pusher Channels REST API | `pusher` | `PUSHER_BASE_URL` *(url)*, `PUSHER_TOKEN` |
| PushPress | `pushpress` | `PUSHPRESS_BASE_URL` *(url)*, `PUSHPRESS_TOKEN` |
| Pushwoosh REST API | `pushwoosh` | `PUSHWOOSH_BASE_URL` *(url)*, `PUSHWOOSH_TOKEN` |
| 500px photo community | `px500` | `PX500_BASE_URL` *(url)*, `PX500_TOKEN` |
| PyPI/Warehouse REST + upload API | `pypi` | `PYPI_BASE_URL` *(url)*, `PYPI_TOKEN` |
| Pyramid Analytics REST API | `pyramid_analytics` | `PYRAMID_ANALYTICS_BASE_URL` *(url)*, `PYRAMID_ANALYTICS_TOKEN` |
| Q2 digital banking | `q2_banking` | `Q2_BANKING_BASE_URL` *(url)*, `Q2_BANKING_TOKEN` |
| QAD Adaptive ERP | `qad` | `QAD_BASE_URL` *(url)*, `QAD_TOKEN` |
| Qase test-management REST API | `qase` | `QASE_BASE_URL` *(url)*, `QASE_TOKEN` |
| Qdrant vector database REST API | `qdrant` | `QDRANT_BASE_URL` *(url)*, `QDRANT_TOKEN` |
| Qgiv | `qgiv` | `QGIV_BASE_URL` *(url)*, `QGIV_TOKEN` |
| Qlik Cloud | `qlik` | `QLIK_BASE_URL` *(url)*, `QLIK_TOKEN` |
| Qonto business banking REST API (France) | `qonto` | `QONTO_BASE_URL` *(url)*, `QONTO_TOKEN` |
| Qovery REST API (cloud deployment platform) | `qovery` | `QOVERY_BASE_URL` *(url)*, `QOVERY_TOKEN` |
| IBM QRadar | `qradar` | `QRADAR_BASE_URL` *(url)*, `QRADAR_TOKEN` |
| Quaderno tax/invoicing REST API | `quaderno` | `QUADERNO_BASE_URL` *(url)*, `QUADERNO_TOKEN` |
| Qualaroo | `qualaroo` | `QUALAROO_BASE_URL` *(url)*, `QUALAROO_TOKEN` |
| Qualtrics XM Platform | `qualtrics` | `QUALTRICS_BASE_URL` *(url)*, `QUALTRICS_TOKEN` |
| Qualys | `qualys` | `QUALYS_BASE_URL` *(url)*, `QUALYS_TOKEN` |
| Nasdaq Data Link (Quandl) | `quandl` | `QUANDL_BASE_URL` *(url)*, `QUANDL_TOKEN` |
| Quantcast Platform REST API | `quantcast` | `QUANTCAST_BASE_URL` *(url)*, `QUANTCAST_TOKEN` |
| Quantexa financial crime/risk analytics | `quantexa` | `QUANTEXA_BASE_URL` *(url)*, `QUANTEXA_TOKEN` |
| Quantum Metric REST API | `quantum_metric` | `QUANTUM_METRIC_BASE_URL` *(url)*, `QUANTUM_METRIC_TOKEN` |
| Questrade brokerage | `questrade` | `QUESTRADE_BASE_URL` *(url)*, `QUESTRADE_TOKEN` |
| Quickbase | `quickbase` | `QUICKBASE_BASE_URL` *(url)*, `QUICKBASE_TOKEN` |
| QuickBooks Online | `quickbooks` | `QUICKBOOKS_BASE_URL` *(url)*, `QUICKBOOKS_TOKEN` |
| Quicken personal finance | `quicken` | `QUICKEN_BASE_URL` *(url)*, `QUICKEN_TOKEN` |
| Amazon QuickSight REST API | `quicksight` | `QUICKSIGHT_BASE_URL` *(url)*, `QUICKSIGHT_TOKEN` |
| Quinyx workforce scheduling | `quinyx` | `QUINYX_BASE_URL` *(url)*, `QUINYX_TOKEN` |
| Quip (Salesforce) | `quip` | `QUIP_BASE_URL` *(url)*, `QUIP_TOKEN` |
| Quire task management | `quire` | `QUIRE_BASE_URL` *(url)*, `QUIRE_TOKEN` |
| Qwilr | `qwilr` | `QWILR_BASE_URL` *(url)*, `QWILR_TOKEN` |
| RabbitMQ management REST API | `rabbitmq` | `RABBITMQ_BASE_URL` *(url)*, `RABBITMQ_TOKEN` |
| Race Roster | `race_roster` | `RACE_ROSTER_BASE_URL` *(url)*, `RACE_ROSTER_TOKEN` |
| Rackspace Cloud REST API | `rackspace` | `RACKSPACE_BASE_URL` *(url)*, `RACKSPACE_TOKEN` |
| Railway Cloud GraphQL API | `railway` | `RAILWAY_BASE_URL` *(url)*, `RAILWAY_TOKEN` |
| Blackbaud Raiser's Edge NXT REST (SKY API) | `raisers_edge` | `RAISERS_EDGE_BASE_URL` *(url)*, `RAISERS_EDGE_TOKEN` |
| Raken construction daily reporting | `raken` | `RAKEN_BASE_URL` *(url)*, `RAKEN_TOKEN` |
| Rakuten marketplace REST API | `rakuten` | `RAKUTEN_BASE_URL` *(url)*, `RAKUTEN_TOKEN` |
| Rakuten Advertising REST API (affiliate marketing) | `rakutenadvertising` | `RAKUTENADVERTISING_BASE_URL` *(url)*, `RAKUTENADVERTISING_TOKEN` |
| Ramp REST (spend) | `ramp` | `RAMP_BASE_URL` *(url)*, `RAMP_TOKEN` |
| Rancher REST API | `rancher` | `RANCHER_BASE_URL` *(url)*, `RANCHER_TOKEN` |
| Rapid7 InsightVM/IDR | `rapid7` | `RAPID7_BASE_URL` *(url)*, `RAPID7_TOKEN` |
| RapidMiner (Altair AI Hub) REST API | `rapidminer` | `RAPIDMINER_BASE_URL` *(url)*, `RAPIDMINER_TOKEN` |
| Rappi | `rappi` | `RAPPI_BASE_URL` *(url)*, `RAPPI_TOKEN` |
| Rapyd payments/fintech REST API | `rapyd` | `RAPYD_BASE_URL` *(url)*, `RAPYD_TOKEN` |
| Rasa Open Source assistant REST API | `rasa` | `RASA_BASE_URL` *(url)*, `RASA_TOKEN` |
| RAWG Video Games Database REST API | `rawg` | `RAWG_BASE_URL` *(url)*, `RAWG_TOKEN` |
| Rawpixel stock media | `rawpixel` | `RAWPIXEL_BASE_URL` *(url)*, `RAWPIXEL_TOKEN` |
| Raygun error/crash reporting REST API | `raygun` | `RAYGUN_BASE_URL` *(url)*, `RAYGUN_TOKEN` |
| Razorpay payments REST API | `razorpay` | `RAZORPAY_BASE_URL` *(url)*, `RAZORPAY_TOKEN` |
| RD Station marketing automation REST API (Brazil) | `rd_station` | `RD_STATION_BASE_URL` *(url)*, `RD_STATION_TOKEN` |
| Readymag web publishing | `readymag` | `READYMAG_BASE_URL` *(url)*, `READYMAG_TOKEN` |
| Real Geeks real estate CRM | `realgeeks` | `REALGEEKS_BASE_URL` *(url)*, `REALGEEKS_TOKEN` |
| Really Simple Systems CRM | `reallysimplesystems` | `REALLYSIMPLESYSTEMS_BASE_URL` *(url)*, `REALLYSIMPLESYSTEMS_TOKEN` |
| RealPage OneSite property management | `realpage` | `REALPAGE_BASE_URL` *(url)*, `REALPAGE_TOKEN` |
| Realtor.com / Move Inc partner | `realtor_com` | `REALTOR_COM_BASE_URL` *(url)*, `REALTOR_COM_TOKEN` |
| Realtyna MLS/IDX | `realtyna` | `REALTYNA_BASE_URL` *(url)*, `REALTYNA_TOKEN` |
| Realvolve real estate CRM | `realvolve` | `REALVOLVE_BASE_URL` *(url)*, `REALVOLVE_TOKEN` |
| Re:amaze helpdesk | `reamaze` | `REAMAZE_BASE_URL` *(url)*, `REAMAZE_TOKEN` |
| Receipt Bank (Dext) legacy receipt capture | `receipt_bank` | `RECEIPT_BANK_BASE_URL` *(url)*, `RECEIPT_BANK_TOKEN` |
| Recharge Payments subscription REST API | `recharge` | `RECHARGE_BASE_URL` *(url)*, `RECHARGE_TOKEN` |
| Reckon accounting REST API (Australia) | `reckon` | `RECKON_BASE_URL` *(url)*, `RECKON_TOKEN` |
| Recorded Future Threat Intelligence | `recordedfuture` | `RECORDEDFUTURE_BASE_URL` *(url)*, `RECORDEDFUTURE_TOKEN` |
| Recruitee recruiting | `recruitee` | `RECRUITEE_BASE_URL` *(url)*, `RECRUITEE_TOKEN` |
| Recruiterflow ATS/CRM | `recruiterflow` | `RECRUITERFLOW_BASE_URL` *(url)*, `RECRUITERFLOW_TOKEN` |
| Recurly subscription-billing REST (v3) | `recurly` | `RECURLY_BASE_URL` *(url)*, `RECURLY_TOKEN` |
| Redash REST API | `redash` | `REDASH_BASE_URL` *(url)*, `REDASH_TOKEN` |
| RedCircle podcast hosting | `redcircle` | `REDCIRCLE_BASE_URL` *(url)*, `REDCIRCLE_TOKEN` |
| Reddit Ads API | `redditads` | `REDDITADS_BASE_URL` *(url)*, `REDDITADS_TOKEN` |
| Redmine | `redmine` | `REDMINE_BASE_URL` *(url)*, `REDMINE_TOKEN` |
| Redox healthcare data integration REST API | `redoxengine` | `REDOXENGINE_BASE_URL` *(url)*, `REDOXENGINE_TOKEN` |
| Amazon Redshift Data API | `redshift` | `REDSHIFT_BASE_URL` *(url)*, `REDSHIFT_TOKEN` |
| RedTeam construction project management | `redteam` | `REDTEAM_BASE_URL` *(url)*, `REDTEAM_TOKEN` |
| ReferralCandy REST API | `referralcandy` | `REFERRALCANDY_BASE_URL` *(url)*, `REFERRALCANDY_TOKEN` |
| Refinitiv World-Check sanctions screening | `refinitiv_worldcheck` | `REFINITIV_WORLDCHECK_BASE_URL` *(url)*, `REFINITIV_WORLDCHECK_TOKEN` |
| Relativity e-discovery platform | `relativity_ediscovery` | `RELATIVITY_EDISCOVERY_BASE_URL` *(url)*, `RELATIVITY_EDISCOVERY_TOKEN` |
| Relay restaurant delivery | `relay_delivery` | `RELAY_DELIVERY_BASE_URL` *(url)*, `RELAY_DELIVERY_TOKEN` |
| Relay small-business banking | `relay_financial` | `RELAY_FINANCIAL_BASE_URL` *(url)*, `RELAY_FINANCIAL_TOKEN` |
| Relevance AI REST API (no-code AI agent/workflow builder) | `relevance_ai` | `RELEVANCE_AI_BASE_URL` *(url)*, `RELEVANCE_AI_TOKEN` |
| Remind school messaging REST API | `remind` | `REMIND_BASE_URL` *(url)*, `REMIND_TOKEN` |
| Remind (school comms) | `remind_app` | `REMIND_APP_BASE_URL` *(url)*, `REMIND_APP_TOKEN` |
| Remitly remittance | `remitly` | `REMITLY_BASE_URL` *(url)*, `REMITLY_TOKEN` |
| RemNote | `remnote` | `REMNOTE_BASE_URL` *(url)*, `REMNOTE_TOKEN` |
| Remo virtual events | `remo_co` | `REMO_CO_BASE_URL` *(url)*, `REMO_CO_TOKEN` |
| Remote.com global employment/payroll | `remote_com` | `REMOTE_COM_BASE_URL` *(url)*, `REMOTE_COM_TOKEN` |
| remove.bg image background removal | `remove_bg` | `REMOVE_BG_BASE_URL` *(url)*, `REMOVE_BG_TOKEN` |
| remove.bg REST API | `removebg` | `REMOVEBG_BASE_URL` *(url)*, `REMOVEBG_TOKEN` |
| Renaissance Learning (Accelerated Reader/STAR) | `renaissance_learning` | `RENAISSANCE_LEARNING_BASE_URL` *(url)*, `RENAISSANCE_LEARNING_TOKEN` |
| Render.com Cloud REST API | `render` | `RENDER_BASE_URL` *(url)*, `RENDER_TOKEN` |
| Mend Renovate Bot dashboard REST API | `renovate` | `RENOVATE_BASE_URL` *(url)*, `RENOVATE_TOKEN` |
| Rentberry rental platform | `rentberry` | `RENTBERRY_BASE_URL` *(url)*, `RENTBERRY_TOKEN` |
| Rentec Direct property management | `rentecdirect` | `RENTECDIRECT_BASE_URL` *(url)*, `RENTECDIRECT_TOKEN` |
| Rent Manager property management | `rentmanager` | `RENTMANAGER_BASE_URL` *(url)*, `RENTMANAGER_TOKEN` |
| RentRedi property management REST API | `rentredi` | `RENTREDI_BASE_URL` *(url)*, `RENTREDI_TOKEN` |
| RentSpree rental application/screening | `rentspree` | `RENTSPREE_BASE_URL` *(url)*, `RENTSPREE_TOKEN` |
| Rentvine property management | `rentvine` | `RENTVINE_BASE_URL` *(url)*, `RENTVINE_TOKEN` |
| Reonomy commercial property data | `reonomy` | `REONOMY_BASE_URL` *(url)*, `REONOMY_TOKEN` |
| Replicant AI contact center | `replicant` | `REPLICANT_BASE_URL` *(url)*, `REPLICANT_TOKEN` |
| Replicate | `replicate` | `REPLICATE_API_TOKEN` |
| Replicate REST API | `replicate_ai` | `REPLICATE_AI_BASE_URL` *(url)*, `REPLICATE_AI_TOKEN` |
| Replicon time/expense tracking | `replicon` | `REPLICON_BASE_URL` *(url)*, `REPLICON_TOKEN` |
| Replit REST/GraphQL API | `replit` | `REPLIT_BASE_URL` *(url)*, `REPLIT_TOKEN` |
| Reply.io sales engagement | `reply_io` | `REPLY_IO_BASE_URL` *(url)*, `REPLY_IO_TOKEN` |
| Reply.io REST API (sales/marketing engagement) | `replyio` | `REPLYIO_BASE_URL` *(url)*, `REPLYIO_TOKEN` |
| ResDiary restaurant booking | `resdiary` | `RESDIARY_BASE_URL` *(url)*, `RESDIARY_TOKEN` |
| ResMan property management | `resman` | `RESMAN_BASE_URL` *(url)*, `RESMAN_TOKEN` |
| Resolver GRC/Risk Management | `resolver` | `RESOLVER_BASE_URL` *(url)*, `RESOLVER_TOKEN` |
| Resolver GRC/risk management | `resolver_grc` | `RESOLVER_GRC_BASE_URL` *(url)*, `RESOLVER_GRC_TOKEN` |
| respond.io omnichannel messaging/chatbot REST API | `respond_io` | `RESPOND_IO_BASE_URL` *(url)*, `RESPOND_IO_TOKEN` |
| Oracle Responsys REST API | `responsys` | `RESPONSYS_BASE_URL` *(url)*, `RESPONSYS_TOKEN` |
| Restream multistreaming | `restream` | `RESTREAM_BASE_URL` *(url)*, `RESTREAM_TOKEN` |
| Resy restaurant reservations REST API | `resy` | `RESY_BASE_URL` *(url)*, `RESY_TOKEN` |
| Retool REST (Workflows / Resources API) | `retool` | `RETOOL_BASE_URL` *(url)*, `RETOOL_TOKEN` |
| Rev.com transcription/captioning | `rev_com` | `REV_COM_BASE_URL` *(url)*, `REV_COM_TOKEN` |
| Reveal e-discovery platform | `reveal_ediscovery` | `REVEAL_EDISCOVERY_BASE_URL` *(url)*, `REVEAL_EDISCOVERY_TOKEN` |
| REVE Chat live-chat/chatbot REST API | `revechat` | `REVECHAT_BASE_URL` *(url)*, `REVECHAT_TOKEN` |
| Revel Systems POS REST API | `revel_systems` | `REVEL_SYSTEMS_BASE_URL` *(url)*, `REVEL_SYSTEMS_TOKEN` |
| Revenue Grid revenue-intelligence | `revenuegrid` | `REVENUEGRID_BASE_URL` *(url)*, `REVENUEGRID_TOKEN` |
| Revenue.io sales engagement/call intelligence | `revenueio` | `REVENUEIO_BASE_URL` *(url)*, `REVENUEIO_TOKEN` |
| Revizto BIM collaboration/issue tracking | `revizto` | `REVIZTO_BASE_URL` *(url)*, `REVIZTO_TOKEN` |
| Revolut Business (Merchant) REST API | `revolut_business` | `REVOLUT_BUSINESS_BASE_URL` *(url)*, `REVOLUT_BUSINESS_TOKEN` |
| Reynolds and Reynolds dealer-management REST API | `reynolds_reynolds` | `REYNOLDS_REYNOLDS_BASE_URL` *(url)*, `REYNOLDS_REYNOLDS_TOKEN` |
| Rezku POS | `rezku` | `REZKU_BASE_URL` *(url)*, `REZKU_TOKEN` |
| Rho business banking/spend | `rho` | `RHO_BASE_URL` *(url)*, `RHO_TOKEN` |
| Rhumbix construction field data collection | `rhumbix` | `RHUMBIX_BASE_URL` *(url)*, `RHUMBIX_TOKEN` |
| Richpanel helpdesk | `richpanel` | `RICHPANEL_BASE_URL` *(url)*, `RICHPANEL_TOKEN` |
| RightSignature | `rightsignature` | `RIGHTSIGNATURE_BASE_URL` *(url)*, `RIGHTSIGNATURE_TOKEN` |
| RingCentral | `ringcentral` | `RINGCENTRAL_BASE_URL` *(url)*, `RINGCENTRAL_TOKEN` |
| Ringover cloud phone system REST API | `ringover` | `RINGOVER_BASE_URL` *(url)*, `RINGOVER_TOKEN` |
| Riot Games REST API (League of Legends/Valorant) | `riotgames` | `RIOTGAMES_BASE_URL` *(url)*, `RIOTGAMES_TOKEN` |
| Rippling | `rippling` | `RIPPLING_BASE_URL` *(url)*, `RIPPLING_TOKEN` |
| Riskified e-commerce fraud prevention | `riskified` | `RISKIFIED_BASE_URL` *(url)*, `RISKIFIED_TOKEN` |
| Riskonnect integrated risk management | `riskonnect` | `RISKONNECT_BASE_URL` *(url)*, `RISKONNECT_TOKEN` |
| Ritual ordering | `ritual` | `RITUAL_BASE_URL` *(url)*, `RITUAL_TOKEN` |
| Rivery data pipeline REST API | `rivery` | `RIVERY_BASE_URL` *(url)*, `RIVERY_TOKEN` |
| Roadmunk | `roadmunk` | `ROADMUNK_BASE_URL` *(url)*, `ROADMUNK_TOKEN` |
| Roam Research REST (Backend API) | `roam_research` | `ROAM_RESEARCH_BASE_URL` *(url)*, `ROAM_RESEARCH_TOKEN` |
| Robinhood trading | `robinhood` | `ROBINHOOD_BASE_URL` *(url)*, `ROBINHOOD_TOKEN` |
| Roblox Open Cloud REST API | `roblox` | `ROBLOX_BASE_URL` *(url)*, `ROBLOX_TOKEN` |
| Rockerbox REST API (marketing attribution) | `rockerbox` | `ROCKERBOX_BASE_URL` *(url)*, `ROCKERBOX_TOKEN` |
| Rocket Lawyer legal document/services | `rocket_lawyer` | `ROCKET_LAWYER_BASE_URL` *(url)*, `ROCKET_LAWYER_TOKEN` |
| Rocket.Chat | `rocketchat` | `ROCKETCHAT_BASE_URL` *(url)*, `ROCKETCHAT_TOKEN` |
| Rocket Matter legal practice management | `rocketmatter` | `ROCKETMATTER_BASE_URL` *(url)*, `ROCKETMATTER_TOKEN` |
| RocketReach prospecting | `rocketreach` | `ROCKETREACH_BASE_URL` *(url)*, `ROCKETREACH_TOKEN` |
| Rockset REST API | `rockset` | `ROCKSET_BASE_URL` *(url)*, `ROCKSET_TOKEN` |
| Rockset REST API (real-time search/analytics) | `rockset_search` | `ROCKSET_SEARCH_BASE_URL` *(url)*, `ROCKSET_SEARCH_TOKEN` |
| Rollbar REST API | `rollbar` | `ROLLBAR_BASE_URL` *(url)*, `ROLLBAR_TOKEN` |
| Rootly incident-management REST API | `rootly` | `ROOTLY_BASE_URL` *(url)*, `ROOTLY_TOKEN` |
| Rosterfy volunteer management | `rosterfy` | `ROSTERFY_BASE_URL` *(url)*, `ROSTERFY_TOKEN` |
| Routable AP/AR automation | `routable` | `ROUTABLE_BASE_URL` *(url)*, `ROUTABLE_TOKEN` |
| Route4Me route planning | `route4me` | `ROUTE4ME_BASE_URL` *(url)*, `ROUTE4ME_TOKEN` |
| Route Mobile SMS/voice REST API | `route_mobile` | `ROUTE_MOBILE_BASE_URL` *(url)*, `ROUTE_MOBILE_TOKEN` |
| Rows.com REST API | `rows_com` | `ROWS_COM_BASE_URL` *(url)*, `ROWS_COM_TOKEN` |
| RPOWER POS | `rpower_pos` | `RPOWER_POS_BASE_URL` *(url)*, `RPOWER_POS_TOKEN` |
| RSS.com podcast hosting | `rss_com` | `RSS_COM_BASE_URL` *(url)*, `RSS_COM_TOKEN` |
| RudderStack REST/HTTP source API | `rudderstack` | `RUDDERSTACK_BASE_URL` *(url)*, `RUDDERSTACK_TOKEN` |
| Rumble creator REST API | `rumble` | `RUMBLE_BASE_URL` *(url)*, `RUMBLE_TOKEN` |
| RunPod REST/GraphQL API (GPU inference endpoints) | `runpod` | `RUNPOD_BASE_URL` *(url)*, `RUNPOD_TOKEN` |
| RunSignup | `runsignup` | `RUNSIGNUP_BASE_URL` *(url)*, `RUNSIGNUP_TOKEN` |
| Runway ML REST API | `runwayml` | `RUNWAYML_BASE_URL` *(url)*, `RUNWAYML_TOKEN` |
| Rutter commerce/accounting unified | `rutter` | `RUTTER_BASE_URL` *(url)*, `RUTTER_TOKEN` |
| Sabre travel/airline REST API | `sabre` | `SABRE_BASE_URL` *(url)*, `SABRE_TOKEN` |
| SafeBreach Breach and Attack Simulation | `safebreach` | `SAFEBREACH_BASE_URL` *(url)*, `SAFEBREACH_TOKEN` |
| SafetyCulture (iAuditor) inspections REST API (Australia) | `safetyculture` | `SAFETYCULTURE_BASE_URL` *(url)*, `SAFETYCULTURE_TOKEN` |
| Sage 300 Construction and Real Estate | `sage_construction` | `SAGE_CONSTRUCTION_BASE_URL` *(url)*, `SAGE_CONSTRUCTION_TOKEN` |
| Sage HR REST API (UK, formerly CakeHR) | `sage_hr` | `SAGE_HR_BASE_URL` *(url)*, `SAGE_HR_TOKEN` |
| Sage Intacct | `sage_intacct` | `SAGE_INTACCT_BASE_URL` *(url)*, `SAGE_INTACCT_TOKEN` |
| Sage Payroll | `sage_payroll` | `SAGE_PAYROLL_BASE_URL` *(url)*, `SAGE_PAYROLL_TOKEN` |
| SailPoint IdentityNow | `sailpoint` | `SAILPOINT_BASE_URL` *(url)*, `SAILPOINT_TOKEN` |
| Saleor headless commerce GraphQL API | `saleor` | `SALEOR_BASE_URL` *(url)*, `SALEOR_TOKEN` |
| Salesflare CRM | `salesflare` | `SALESFLARE_BASE_URL` *(url)*, `SALESFLARE_TOKEN` |
| Salesforce | `salesforce` | `SALESFORCE_INSTANCE_URL` *(url)*, `SALESFORCE_ACCESS_TOKEN` |
| Salesforce Commerce Cloud (SCAPI/OCAPI) | `salesforce_commerce` | `SFCC_BASE_URL` *(url)*, `SFCC_TOKEN` |
| Salesforce Nonprofit Success Pack (NPSP) REST, on Salesforce REST API | `salesforce_npsp` | `SALESFORCE_NPSP_BASE_URL` *(url)*, `SALESFORCE_NPSP_TOKEN` |
| SalesIntel sales intelligence | `salesintel` | `SALESINTEL_BASE_URL` *(url)*, `SALESINTEL_TOKEN` |
| Salesken conversation intelligence | `salesken` | `SALESKEN_BASE_URL` *(url)*, `SALESKEN_TOKEN` |
| Salesloft | `salesloft` | `SALESLOFT_BASE_URL` *(url)*, `SALESLOFT_TOKEN` |
| Salesmate CRM | `salesmate` | `SALESMATE_BASE_URL` *(url)*, `SALESMATE_TOKEN` |
| SalesRabbit (field sales CRM) | `salesrabbit` | `SALESRABBIT_BASE_URL` *(url)*, `SALESRABBIT_TOKEN` |
| Salsa Labs / SalsaEngage | `salsalabs` | `SALSALABS_BASE_URL` *(url)*, `SALSALABS_TOKEN` |
| Salt Edge open-banking | `salt_edge` | `SALT_EDGE_BASE_URL` *(url)*, `SALT_EDGE_TOKEN` |
| Salt Security API Protection | `salt_security` | `SALT_SECURITY_BASE_URL` *(url)*, `SALT_SECURITY_TOKEN` |
| SamCart REST API | `samcart` | `SAMCART_BASE_URL` *(url)*, `SAMCART_TOKEN` |
| Samsara fleet / IoT | `samsara` | `SAMSARA_BASE_URL` *(url)*, `SAMSARA_TOKEN` |
| Sanity.io Content API | `sanity` | `SANITY_BASE_URL` *(url)*, `SANITY_TOKEN` |
| Sansan business card/CRM REST API (Japan) | `sansan` | `SANSAN_BASE_URL` *(url)*, `SANSAN_TOKEN` |
| SAP (OData) | `sap` | `SAP_BASE_URL` *(url)*, `SAP_TOKEN` |
| SAP Ariba Network procurement REST (distinct from Ariba buyer API) | `sap_ariba_network` | `SAP_ARIBA_NETWORK_BASE_URL` *(url)*, `SAP_ARIBA_NETWORK_TOKEN` |
| SAP BusinessObjects BI Platform REST API | `sap_businessobjects` | `SAP_BUSINESSOBJECTS_BASE_URL` *(url)*, `SAP_BUSINESSOBJECTS_TOKEN` |
| SAP Commerce Cloud (Hybris) OCC | `sap_commerce` | `SAP_COMMERCE_BASE_URL` *(url)*, `SAP_COMMERCE_TOKEN` |
| SAP Digital Manufacturing Cloud | `sap_dmc` | `SAP_DMC_BASE_URL` *(url)*, `SAP_DMC_TOKEN` |
| SAP Extended Warehouse Management | `sap_ewm` | `SAP_EWM_BASE_URL` *(url)*, `SAP_EWM_TOKEN` |
| SAP Integrated Business Planning | `sap_ibp` | `SAP_IBP_BASE_URL` *(url)*, `SAP_IBP_TOKEN` |
| SAP SuccessFactors Employee Central OData REST (distinct from generic successfactors entry) | `sap_successfactors_ec` | `SAP_SUCCESSFACTORS_EC_BASE_URL` *(url)*, `SAP_SUCCESSFACTORS_EC_TOKEN` |
| Sapiens insurance core-platform REST API | `sapiens` | `SAPIENS_BASE_URL` *(url)*, `SAPIENS_TOKEN` |
| Satori Data Security Platform | `satori_cyber` | `SATORI_CYBER_BASE_URL` *(url)*, `SATORI_CYBER_TOKEN` |
| Sauce Labs REST API | `saucelabs` | `SAUCELABS_BASE_URL` *(url)*, `SAUCELABS_TOKEN` |
| Saviynt Identity Cloud | `saviynt` | `SAVIYNT_BASE_URL` *(url)*, `SAVIYNT_TOKEN` |
| SavvyCal scheduling | `savvycal` | `SAVVYCAL_BASE_URL` *(url)*, `SAVVYCAL_TOKEN` |
| Saxo Bank OpenAPI | `saxo_bank` | `SAXO_BANK_BASE_URL` *(url)*, `SAXO_BANK_TOKEN` |
| Scale AI REST API (data/model platform) | `scale_ai` | `SCALE_AI_BASE_URL` *(url)*, `SCALE_AI_TOKEN` |
| Scaleway Cloud REST API | `scaleway` | `SCALEWAY_BASE_URL` *(url)*, `SCALEWAY_TOKEN` |
| Schedulicity | `schedulicity` | `SCHEDULICITY_BASE_URL` *(url)*, `SCHEDULICITY_TOKEN` |
| Schedulista | `schedulista` | `SCHEDULISTA_BASE_URL` *(url)*, `SCHEDULISTA_TOKEN` |
| SchoolCafe (Heartland) school nutrition/payments | `schoolcafe` | `SCHOOLCAFE_BASE_URL` *(url)*, `SCHOOLCAFE_TOKEN` |
| Schoology LMS REST API | `schoology` | `SCHOOLOGY_BASE_URL` *(url)*, `SCHOOLOGY_TOKEN` |
| SchoolStatus family engagement/analytics | `schoolstatus` | `SCHOOLSTATUS_BASE_URL` *(url)*, `SCHOOLSTATUS_TOKEN` |
| Charles Schwab trading | `schwab` | `SCHWAB_BASE_URL` *(url)*, `SCHWAB_TOKEN` |
| Scoro | `scoro` | `SCORO_BASE_URL` *(url)*, `SCORO_TOKEN` |
| Screencastify | `screencastify` | `SCREENCASTIFY_BASE_URL` *(url)*, `SCREENCASTIFY_TOKEN` |
| Scrut Automation GRC | `scrut` | `SCRUT_BASE_URL` *(url)*, `SCRUT_TOKEN` |
| Seamless.AI prospecting | `seamlessai` | `SEAMLESSAI_BASE_URL` *(url)*, `SEAMLESSAI_TOKEN` |
| SeaTable REST API | `seatable` | `SEATABLE_BASE_URL` *(url)*, `SEATABLE_TOKEN` |
| Secured Signing | `securedsigning` | `SECUREDSIGNING_BASE_URL` *(url)*, `SECUREDSIGNING_TOKEN` |
| Secureframe compliance-automation | `secureframe` | `SECUREFRAME_BASE_URL` *(url)*, `SECUREFRAME_TOKEN` |
| SecurityScorecard Ratings | `securityscorecard` | `SECURITYSCORECARD_BASE_URL` *(url)*, `SECURITYSCORECARD_TOKEN` |
| Securonix Unified Defense SIEM | `securonix` | `SECURONIX_BASE_URL` *(url)*, `SECURONIX_TOKEN` |
| SeeClickFix (CivicPlus) 311/citizen engagement | `seeclickfix` | `SEECLICKFIX_BASE_URL` *(url)*, `SEECLICKFIX_TOKEN` |
| Seeq industrial process data analytics | `seeq` | `SEEQ_BASE_URL` *(url)*, `SEEQ_TOKEN` |
| Seesaw learning journal REST API | `seesaw` | `SEESAW_BASE_URL` *(url)*, `SEESAW_TOKEN` |
| Twilio Segment Public API | `segment` | `SEGMENT_BASE_URL` *(url)*, `SEGMENT_TOKEN` |
| Seismic sales enablement | `seismic` | `SEISMIC_BASE_URL` *(url)*, `SEISMIC_TOKEN` |
| Sellfy REST API | `sellfy` | `SELLFY_BASE_URL` *(url)*, `SELLFY_TOKEN` |
| Sellsy CRM/invoicing REST API (France) | `sellsy` | `SELLSY_BASE_URL` *(url)*, `SELLSY_TOKEN` |
| Semaphore CI REST API | `semaphoreci` | `SEMAPHORECI_BASE_URL` *(url)*, `SEMAPHORECI_TOKEN` |
| Semgrep AppSec Platform REST API | `semgrep` | `SEMGREP_BASE_URL` *(url)*, `SEMGREP_TOKEN` |
| Semrush REST API | `semrush` | `SEMRUSH_BASE_URL` *(url)*, `SEMRUSH_TOKEN` |
| Sendbird chat platform REST API | `sendbird` | `SENDBIRD_BASE_URL` *(url)*, `SENDBIRD_TOKEN` |
| Twilio SendGrid | `sendgrid` | `SENDGRID_BASE_URL` *(url)*, `SENDGRID_TOKEN` |
| Microsoft Sentinel REST (Azure) | `sentinel` | `SENTINEL_BASE_URL` *(url)*, `SENTINEL_TOKEN` |
| SentinelOne | `sentinelone` | `SENTINELONE_BASE_URL` *(url)*, `SENTINELONE_TOKEN` |
| Sentry | `sentry` | `SENTRY_HOST` *(url)*, `SENTRY_AUTH_TOKEN` |
| Sequoia One HR/benefits | `sequoia_hr` | `SEQUOIA_HR_BASE_URL` *(url)*, `SEQUOIA_HR_TOKEN` |
| Service Fusion field service management | `service_fusion` | `SERVICE_FUSION_BASE_URL` *(url)*, `SERVICE_FUSION_TOKEN` |
| ServiceM8 field service management REST API (Australia) | `servicem8` | `SERVICEM8_BASE_URL` *(url)*, `SERVICEM8_TOKEN` |
| ServiceMax field service management | `servicemax` | `SERVICEMAX_BASE_URL` *(url)*, `SERVICEMAX_TOKEN` |
| ServiceNow | `servicenow` | `SERVICENOW_INSTANCE_URL` *(url)*, `SERVICENOW_TOKEN` |
| ServiceTitan | `servicetitan` | `SERVICETITAN_BASE_URL` *(url)*, `SERVICETITAN_TOKEN` |
| Sesame HR | `sesame_hr` | `SESAME_HR_BASE_URL` *(url)*, `SESAME_HR_TOKEN` |
| Setmore scheduling | `setmore` | `SETMORE_BASE_URL` *(url)*, `SETMORE_TOKEN` |
| sevDesk accounting REST API (Germany) | `sevdesk` | `SEVDESK_BASE_URL` *(url)*, `SEVDESK_TOKEN` |
| seven.io SMS/voice gateway REST API | `seven_io` | `SEVEN_IO_BASE_URL` *(url)*, `SEVEN_IO_TOKEN` |
| SevenRooms | `sevenrooms` | `SEVENROOMS_BASE_URL` *(url)*, `SEVENROOMS_TOKEN` |
| Sezzle payments REST API | `sezzle` | `SEZZLE_BASE_URL` *(url)*, `SEZZLE_TOKEN` |
| sFax | `sfax` | `SFAX_BASE_URL` *(url)*, `SFAX_TOKEN` |
| Salesforce Marketing Cloud | `sfmc` | `SFMC_BASE_URL` *(url)*, `SFMC_TOKEN` |
| ShareASale REST API (affiliate marketing) | `shareasale` | `SHAREASALE_BASE_URL` *(url)*, `SHAREASALE_TOKEN` |
| Citrix ShareFile | `sharefile` | `SHAREFILE_BASE_URL` *(url)*, `SHAREFILE_TOKEN` |
| Microsoft SharePoint | `sharepoint` | `SHAREPOINT_BASE_URL` *(url)*, `SHAREPOINT_TOKEN` |
| ShareThis REST API (social sharing analytics) | `sharethis` | `SHARETHIS_BASE_URL` *(url)*, `SHARETHIS_TOKEN` |
| SharpSpring CRM/marketing REST (JSON-RPC) | `sharpspring` | `SHARPSPRING_BASE_URL` *(url)*, `SHARPSPRING_TOKEN` |
| Shift4Shop (3dcart) REST API | `shift4shop` | `SHIFT4SHOP_BASE_URL` *(url)*, `SHIFT4SHOP_TOKEN` |
| Shiftboard scheduling | `shiftboard` | `SHIFTBOARD_BASE_URL` *(url)*, `SHIFTBOARD_TOKEN` |
| Shiji hospitality platform REST API | `shiji` | `SHIJI_BASE_URL` *(url)*, `SHIJI_TOKEN` |
| ShipBob fulfillment REST API | `shipbob` | `SHIPBOB_BASE_URL` *(url)*, `SHIPBOB_TOKEN` |
| Shipday delivery management | `shipday` | `SHIPDAY_BASE_URL` *(url)*, `SHIPDAY_TOKEN` |
| ShipEngine shipping REST API | `shipengine` | `SHIPENGINE_BASE_URL` *(url)*, `SHIPENGINE_TOKEN` |
| ShipHero WMS | `shiphero` | `SHIPHERO_BASE_URL` *(url)*, `SHIPHERO_TOKEN` |
| Shippo multi-carrier shipping | `shippo` | `SHIPPO_BASE_URL` *(url)*, `SHIPPO_TOKEN` |
| Shiprocket logistics aggregator REST API (India) | `shiprocket` | `SHIPROCKET_BASE_URL` *(url)*, `SHIPROCKET_TOKEN` |
| ShipStation shipping/fulfillment REST API | `shipstation` | `SHIPSTATION_BASE_URL` *(url)*, `SHIPSTATION_TOKEN` |
| Shodan Internet Intelligence | `shodan` | `SHODAN_BASE_URL` *(url)*, `SHODAN_TOKEN` |
| ShootProof photography client galleries | `shootproof` | `SHOOTPROOF_BASE_URL` *(url)*, `SHOOTPROOF_TOKEN` |
| Shopee Open Platform REST API | `shopee` | `SHOPEE_BASE_URL` *(url)*, `SHOPEE_TOKEN` |
| Shopify | `shopify` | `SHOPIFY_STORE` *(url)*, `SHOPIFY_ACCESS_TOKEN` |
| ShopKeep (Lightspeed) POS REST API | `shopkeep` | `SHOPKEEP_BASE_URL` *(url)*, `SHOPKEEP_TOKEN` |
| Shopware Admin/Store REST API | `shopware` | `SHOPWARE_BASE_URL` *(url)*, `SHOPWARE_TOKEN` |
| Shortcut (formerly Clubhouse) | `shortcut` | `SHORTCUT_BASE_URL` *(url)*, `SHORTCUT_TOKEN` |
| ShowingTime real estate showing-scheduling REST partner API | `showingtime` | `SHOWINGTIME_BASE_URL` *(url)*, `SHOWINGTIME_TOKEN` |
| Showpad sales enablement | `showpad` | `SHOWPAD_BASE_URL` *(url)*, `SHOWPAD_TOKEN` |
| Shutterstock REST API | `shutterstock` | `SHUTTERSTOCK_BASE_URL` *(url)*, `SHUTTERSTOCK_TOKEN` |
| Sift fraud detection | `sift_fraud` | `SIFT_FRAUD_BASE_URL` *(url)*, `SIFT_FRAUD_TOKEN` |
| Sight Machine manufacturing analytics | `sight_machine` | `SIGHT_MACHINE_BASE_URL` *(url)*, `SIGHT_MACHINE_TOKEN` |
| Sigma Computing REST API | `sigma_computing` | `SIGMA_COMPUTING_BASE_URL` *(url)*, `SIGMA_COMPUTING_TOKEN` |
| Signable e-signature | `signable` | `SIGNABLE_BASE_URL` *(url)*, `SIGNABLE_TOKEN` |
| Signal messaging REST (signal-cli REST API) | `signal` | `SIGNAL_BASE_URL` *(url)*, `SIGNAL_TOKEN` |
| Signaturely e-signature | `signaturely` | `SIGNATURELY_BASE_URL` *(url)*, `SIGNATURELY_TOKEN` |
| Signaturit e-signature | `signaturit` | `SIGNATURIT_BASE_URL` *(url)*, `SIGNATURIT_TOKEN` |
| SignEasy | `signeasy` | `SIGNEASY_BASE_URL` *(url)*, `SIGNEASY_TOKEN` |
| SignNow e-signature | `signnow` | `SIGNNOW_BASE_URL` *(url)*, `SIGNNOW_TOKEN` |
| SignRequest | `signrequest` | `SIGNREQUEST_BASE_URL` *(url)*, `SIGNREQUEST_TOKEN` |
| SignUpGenius | `signupgenius` | `SIGNUPGENIUS_BASE_URL` *(url)*, `SIGNUPGENIUS_TOKEN` |
| Siigo accounting REST API (Colombia) | `siigo` | `SIIGO_BASE_URL` *(url)*, `SIIGO_TOKEN` |
| Silicon Valley Bank (SVB) business banking | `silicon_valley_bridge` | `SILICON_VALLEY_BRIDGE_BASE_URL` *(url)*, `SILICON_VALLEY_BRIDGE_TOKEN` |
| Silverfin accounting collaboration REST API (Belgium/UK) | `silverfin` | `SILVERFIN_BASE_URL` *(url)*, `SILVERFIN_TOKEN` |
| Simplecast podcast hosting | `simplecast` | `SIMPLECAST_BASE_URL` *(url)*, `SIMPLECAST_TOKEN` |
| SimpleLegal (Onit) legal operations/e-billing | `simplelegal` | `SIMPLELEGAL_BASE_URL` *(url)*, `SIMPLELEGAL_TOKEN` |
| Simplenote | `simplenote` | `SIMPLENOTE_BASE_URL` *(url)*, `SIMPLENOTE_TOKEN` |
| SimplePractice practice management REST API | `simplepractice` | `SIMPLEPRACTICE_BASE_URL` *(url)*, `SIMPLEPRACTICE_TOKEN` |
| SimpleTexting REST API (SMS marketing) | `simpletexting` | `SIMPLETEXTING_BASE_URL` *(url)*, `SIMPLETEXTING_TOKEN` |
| Simplex crypto payments | `simplex_crypto` | `SIMPLEX_CRYPTO_BASE_URL` *(url)*, `SIMPLEX_CRYPTO_TOKEN` |
| Simplifi by Quicken budgeting | `simplifi` | `SIMPLIFI_BASE_URL` *(url)*, `SIMPLIFI_TOKEN` |
| SimplifyEm property management | `simplifyem` | `SIMPLIFYEM_BASE_URL` *(url)*, `SIMPLIFYEM_TOKEN` |
| SimplyBook.me scheduling | `simplybookme` | `SIMPLYBOOKME_BASE_URL` *(url)*, `SIMPLYBOOKME_TOKEN` |
| Simpplr intranet | `simpplr` | `SIMPPLR_BASE_URL` *(url)*, `SIMPPLR_TOKEN` |
| simPRO field service/job management | `simpro` | `SIMPRO_BASE_URL` *(url)*, `SIMPRO_TOKEN` |
| Sinch SMS/voice/conversation REST API | `sinch` | `SINCH_BASE_URL` *(url)*, `SINCH_TOKEN` |
| Singer.io tap/target orchestration REST API (e.g | `singer` | `SINGER_BASE_URL` *(url)*, `SINGER_TOKEN` |
| SingleStore (MemSQL) Data API | `singlestore` | `SINGLESTORE_BASE_URL` *(url)*, `SINGLESTORE_TOKEN` |
| Singular REST API | `singular` | `SINGULAR_BASE_URL` *(url)*, `SINGULAR_TOKEN` |
| SirionLabs contract lifecycle management | `sirion_clm` | `SIRION_CLM_BASE_URL` *(url)*, `SIRION_CLM_TOKEN` |
| Sisense | `sisense` | `SISENSE_BASE_URL` *(url)*, `SISENSE_TOKEN` |
| Site24x7 monitoring REST API | `site24x7` | `SITE24X7_BASE_URL` *(url)*, `SITE24X7_TOKEN` |
| Sitecore Content Hub / Experience Management REST API | `sitecore` | `SITECORE_BASE_URL` *(url)*, `SITECORE_TOKEN` |
| SiteMinder hotel channel-manager REST API | `siteminder` | `SITEMINDER_BASE_URL` *(url)*, `SITEMINDER_TOKEN` |
| Sixt car rental partner REST API (Germany) | `sixt` | `SIXT_BASE_URL` *(url)*, `SIXT_TOKEN` |
| Skai (formerly Kenshoo) REST API (ad management) | `skai` | `SKAI_BASE_URL` *(url)*, `SKAI_TOKEN` |
| Sketch Cloud REST API | `sketch` | `SKETCH_BASE_URL` *(url)*, `SKETCH_TOKEN` |
| Skribble e-signature | `skribble` | `SKRIBBLE_BASE_URL` *(url)*, `SKRIBBLE_TOKEN` |
| Skrill digital wallet/payments | `skrill` | `SKRILL_BASE_URL` *(url)*, `SKRILL_TOKEN` |
| Skubana (Extensiv) multichannel order-management | `skubana` | `SKUBANA_BASE_URL` *(url)*, `SKUBANA_TOKEN` |
| Skype (Microsoft Bot/Graph) | `skype` | `SKYPE_BASE_URL` *(url)*, `SKYPE_TOKEN` |
| Skype for Business REST (Graph/legacy UCWA) | `skype_for_business` | `SKYPE_FOR_BUSINESS_BASE_URL` *(url)*, `SKYPE_FOR_BUSINESS_TOKEN` |
| Skyscanner travel search REST API | `skyscanner` | `SKYSCANNER_BASE_URL` *(url)*, `SKYSCANNER_TOKEN` |
| SkySlope real estate transaction management | `skyslope` | `SKYSLOPE_BASE_URL` *(url)*, `SKYSLOPE_TOKEN` |
| Skyvia data integration REST API | `skyvia` | `SKYVIA_BASE_URL` *(url)*, `SKYVIA_TOKEN` |
| Skyward SIS | `skyward` | `SKYWARD_BASE_URL` *(url)*, `SKYWARD_TOKEN` |
| Slack Web API | `slack_api` | `SLACK_API_BASE_URL` *(url)*, `SLACK_API_TOKEN` |
| Slate (Technolutions) admissions CRM | `slate_technolutions` | `SLATE_TECHNOLUTIONS_BASE_URL` *(url)*, `SLATE_TECHNOLUTIONS_TOKEN` |
| Slice (slicelife.com) pizzeria ordering | `slicelife` | `SLICELIFE_BASE_URL` *(url)*, `SLICELIFE_TOKEN` |
| SlickText REST API (SMS marketing) | `slicktext` | `SLICKTEXT_BASE_URL` *(url)*, `SLICKTEXT_TOKEN` |
| SlideRoom applications/admissions | `slideroom` | `SLIDEROOM_BASE_URL` *(url)*, `SLIDEROOM_TOKEN` |
| Slimstock (Slim4) inventory optimization | `slimstock` | `SLIMSTOCK_BASE_URL` *(url)*, `SLIMSTOCK_TOKEN` |
| Sling (workforce scheduling) | `sling` | `SLING_BASE_URL` *(url)*, `SLING_TOKEN` |
| Slite wiki | `slite` | `SLITE_BASE_URL` *(url)*, `SLITE_TOKEN` |
| Smallpdf | `smallpdf` | `SMALLPDF_BASE_URL` *(url)*, `SMALLPDF_TOKEN` |
| Smaregi POS REST API (Japan) | `smaregi` | `SMAREGI_BASE_URL` *(url)*, `SMAREGI_TOKEN` |
| SmartBid construction bid management | `smartbid` | `SMARTBID_BASE_URL` *(url)*, `SMARTBID_TOKEN` |
| SmartDraw diagramming | `smartdraw` | `SMARTDRAW_BASE_URL` *(url)*, `SMARTDRAW_TOKEN` |
| Smartlead cold-email sales engagement | `smartlead` | `SMARTLEAD_BASE_URL` *(url)*, `SMARTLEAD_TOKEN` |
| Smartly.io REST API (social ad management) | `smartlyio` | `SMARTLYIO_BASE_URL` *(url)*, `SMARTLYIO_TOKEN` |
| SmartRecruiters | `smartrecruiters` | `SMARTRECRUITERS_BASE_URL` *(url)*, `SMARTRECRUITERS_TOKEN` |
| Smartsheet | `smartsheet` | `SMARTSHEET_BASE_URL` *(url)*, `SMARTSHEET_TOKEN` |
| SmartSimple grants management | `smartsimple` | `SMARTSIMPLE_BASE_URL` *(url)*, `SMARTSIMPLE_TOKEN` |
| SmartSuite REST API (no-code work management/database) | `smartsuite` | `SMARTSUITE_BASE_URL` *(url)*, `SMARTSUITE_TOKEN` |
| Smartsupp live-chat REST API | `smartsupp` | `SMARTSUPP_BASE_URL` *(url)*, `SMARTSUPP_TOKEN` |
| Smokeball legal practice management | `smokeball` | `SMOKEBALL_BASE_URL` *(url)*, `SMOKEBALL_TOKEN` |
| Smooch / Sunshine Conversations REST API | `smooch` | `SMOOCH_BASE_URL` *(url)*, `SMOOCH_TOKEN` |
| SMSAPI.com SMS gateway REST API | `smsapi_com` | `SMSAPI_COM_BASE_URL` *(url)*, `SMSAPI_COM_TOKEN` |
| SMSGlobal messaging REST API | `smsglobal` | `SMSGLOBAL_BASE_URL` *(url)*, `SMSGLOBAL_TOKEN` |
| SmugMug photo hosting | `smugmug` | `SMUGMUG_BASE_URL` *(url)*, `SMUGMUG_TOKEN` |
| Snap Surveys | `snap_surveys` | `SNAP_SURVEYS_BASE_URL` *(url)*, `SNAP_SURVEYS_TOKEN` |
| Snapchat Marketing/Ads REST API | `snapchat` | `SNAPCHAT_BASE_URL` *(url)*, `SNAPCHAT_TOKEN` |
| Snapchat Marketing API | `snapchatads` | `SNAPCHATADS_BASE_URL` *(url)*, `SNAPCHATADS_TOKEN` |
| SnapFulfil WMS | `snapfulfil` | `SNAPFULFIL_BASE_URL` *(url)*, `SNAPFULFIL_TOKEN` |
| SnapLogic REST API | `snaplogic` | `SNAPLOGIC_BASE_URL` *(url)*, `SNAPLOGIC_TOKEN` |
| Snappa graphic design | `snappa` | `SNAPPA_BASE_URL` *(url)*, `SNAPPA_TOKEN` |
| Snowflake | `snowflake` | `SNOWFLAKE_ACCOUNT` *(url)*, `SNOWFLAKE_TOKEN` |
| Snowplow Analytics REST/collector API | `snowplow` | `SNOWPLOW_BASE_URL` *(url)*, `SNOWPLOW_TOKEN` |
| Snyk | `snyk` | `SNYK_BASE_URL` *(url)*, `SNYK_TOKEN` |
| SocialPilot REST API | `socialpilot` | `SOCIALPILOT_BASE_URL` *(url)*, `SOCIALPILOT_TOKEN` |
| Socotra cloud insurance-core-platform REST API | `socotra` | `SOCOTRA_BASE_URL` *(url)*, `SOCOTRA_TOKEN` |
| Socrata (Tyler Data & Insights) open data | `socrata` | `SOCRATA_BASE_URL` *(url)*, `SOCRATA_TOKEN` |
| Socure identity verification | `socure` | `SOCURE_BASE_URL` *(url)*, `SOCURE_TOKEN` |
| Soda PDF | `soda_pdf` | `SODA_PDF_BASE_URL` *(url)*, `SODA_PDF_TOKEN` |
| SoFi money/invest | `sofi` | `SOFI_BASE_URL` *(url)*, `SOFI_TOKEN` |
| Softeon WMS | `softeon` | `SOFTEON_BASE_URL` *(url)*, `SOFTEON_TOKEN` |
| Softr | `softr` | `SOFTR_BASE_URL` *(url)*, `SOFTR_TOKEN` |
| SolarEdge solar-monitoring REST API | `solaredge` | `SOLAREDGE_BASE_URL` *(url)*, `SOLAREDGE_TOKEN` |
| SolarWinds Service Desk | `solarwinds` | `SOLARWINDS_BASE_URL` *(url)*, `SOLARWINDS_TOKEN` |
| iBase-t Solumina MES | `solumina` | `SOLUMINA_BASE_URL` *(url)*, `SOLUMINA_TOKEN` |
| Solvvy (Zoom Virtual Agent) support automation | `solvvy` | `SOLVVY_BASE_URL` *(url)*, `SOLVVY_TOKEN` |
| SonarQube | `sonarqube` | `SONARQUBE_BASE_URL` *(url)*, `SONARQUBE_TOKEN` |
| Sonatype Nexus Repository REST API | `sonatype_nexus` | `SONATYPE_NEXUS_BASE_URL` *(url)*, `SONATYPE_NEXUS_TOKEN` |
| Sophos Central | `sophos` | `SOPHOS_BASE_URL` *(url)*, `SOPHOS_TOKEN` |
| Soprano Design enterprise messaging REST API | `soprano_design` | `SOPRANO_DESIGN_BASE_URL` *(url)*, `SOPRANO_DESIGN_TOKEN` |
| Soul Machines digital human REST API | `soul_machines` | `SOUL_MACHINES_BASE_URL` *(url)*, `SOUL_MACHINES_TOKEN` |
| SoundCloud REST API | `soundcloud` | `SOUNDCLOUD_BASE_URL` *(url)*, `SOUNDCLOUD_TOKEN` |
| Soundstripe music licensing | `soundstripe` | `SOUNDSTRIPE_BASE_URL` *(url)*, `SOUNDSTRIPE_TOKEN` |
| Sourcegraph GraphQL API | `sourcegraph` | `SOURCEGRAPH_BASE_URL` *(url)*, `SOURCEGRAPH_TOKEN` |
| Sovos tax-compliance REST API | `sovos` | `SOVOS_BASE_URL` *(url)*, `SOVOS_TOKEN` |
| Spark API (FBS) MLS data platform | `sparkapi` | `SPARKAPI_BASE_URL` *(url)*, `SPARKAPI_TOKEN` |
| SparkPost REST API | `sparkpost` | `SPARKPOST_BASE_URL` *(url)*, `SPARKPOST_TOKEN` |
| Speakap employee comms | `speakap` | `SPEAKAP_BASE_URL` *(url)*, `SPEAKAP_TOKEN` |
| speedrun.com REST API | `speedrun` | `SPEEDRUN_BASE_URL` *(url)*, `SPEEDRUN_TOKEN` |
| Spendesk expense management REST API (France) | `spendesk` | `SPENDESK_BASE_URL` *(url)*, `SPENDESK_TOKEN` |
| Spiceworks Cloud Help Desk | `spiceworks` | `SPICEWORKS_BASE_URL` *(url)*, `SPICEWORKS_TOKEN` |
| Spinnaker (Gate) REST API | `spinnaker` | `SPINNAKER_BASE_URL` *(url)*, `SPINNAKER_TOKEN` |
| Split feature-flag / experimentation | `split` | `SPLIT_BASE_URL` *(url)*, `SPLIT_TOKEN` |
| Splitit installment-payments REST API | `splitit` | `SPLITIT_BASE_URL` *(url)*, `SPLITIT_TOKEN` |
| Splunk | `splunk` | `SPLUNK_BASE_URL` *(url)*, `SPLUNK_TOKEN` |
| Spond | `spond` | `SPOND_BASE_URL` *(url)*, `SPOND_TOKEN` |
| SportsEngine | `sportsengine` | `SPORTSENGINE_BASE_URL` *(url)*, `SPORTSENGINE_TOKEN` |
| SpotDraft CLM | `spotdraft` | `SPOTDRAFT_BASE_URL` *(url)*, `SPOTDRAFT_TOKEN` |
| TIBCO Spotfire REST API | `spotfire` | `SPOTFIRE_BASE_URL` *(url)*, `SPOTFIRE_TOKEN` |
| SPOTIO (field sales CRM) | `spotio` | `SPOTIO_BASE_URL` *(url)*, `SPOTIO_TOKEN` |
| Spotlight Reporting financial reporting | `spotlight_reporting` | `SPOTLIGHT_REPORTING_BASE_URL` *(url)*, `SPOTLIGHT_REPORTING_TOKEN` |
| SpotOn Restaurant POS | `spoton_pos` | `SPOTON_POS_BASE_URL` *(url)*, `SPOTON_POS_TOKEN` |
| Spreaker podcast hosting | `spreaker` | `SPREAKER_BASE_URL` *(url)*, `SPREAKER_TOKEN` |
| Spree Commerce REST API | `spree_commerce` | `SPREE_COMMERCE_BASE_URL` *(url)*, `SPREE_COMMERCE_TOKEN` |
| Springboard Retail POS REST API | `springboard_retail` | `SPRINGBOARD_RETAIL_BASE_URL` *(url)*, `SPRINGBOARD_RETAIL_TOKEN` |
| Sprinklr | `sprinklr` | `SPRINKLR_BASE_URL` *(url)*, `SPRINKLR_TOKEN` |
| Sprinto Compliance Automation | `sprinto` | `SPRINTO_BASE_URL` *(url)*, `SPRINTO_TOKEN` |
| Sprout Social REST API | `sproutsocial` | `SPROUTSOCIAL_BASE_URL` *(url)*, `SPROUTSOCIAL_TOKEN` |
| Squadcast incident-response REST API | `squadcast` | `SQUADCAST_BASE_URL` *(url)*, `SQUADCAST_TOKEN` |
| Square | `square` | `SQUARE_BASE_URL` *(url)*, `SQUARE_TOKEN` |
| Squarespace Commerce/Content REST API | `squarespace` | `SQUARESPACE_BASE_URL` *(url)*, `SQUARESPACE_TOKEN` |
| Squirrel POS | `squirrel_systems` | `SQUIRREL_SYSTEMS_BASE_URL` *(url)*, `SQUIRREL_SYSTEMS_TOKEN` |
| SRFax | `srfax` | `SRFAX_BASE_URL` *(url)*, `SRFAX_TOKEN` |
| Stability AI REST API | `stability_ai` | `STABILITY_AI_BASE_URL` *(url)*, `STABILITY_AI_TOKEN` |
| Stack AI REST API (no-code AI workflow builder) | `stack_ai` | `STACK_AI_BASE_URL` *(url)*, `STACK_AI_TOKEN` |
| STACK Construction Technologies takeoff/estimating | `stack_construction` | `STACK_CONSTRUCTION_BASE_URL` *(url)*, `STACK_CONSTRUCTION_TOKEN` |
| Stack Sports | `stack_sports` | `STACK_SPORTS_BASE_URL` *(url)*, `STACK_SPORTS_TOKEN` |
| Stacker | `stacker` | `STACKER_BASE_URL` *(url)*, `STACKER_TOKEN` |
| StackPath Edge/CDN REST API | `stackpath` | `STACKPATH_BASE_URL` *(url)*, `STACKPATH_TOKEN` |
| Staffbase intranet | `staffbase` | `STAFFBASE_BASE_URL` *(url)*, `STAFFBASE_TOKEN` |
| Stampli AP automation | `stampli` | `STAMPLI_BASE_URL` *(url)*, `STAMPLI_TOKEN` |
| Standard Notes sync | `standardnotes` | `STANDARDNOTES_BASE_URL` *(url)*, `STANDARDNOTES_TOKEN` |
| Starburst (Trino enterprise) REST API | `starburst` | `STARBURST_BASE_URL` *(url)*, `STARBURST_TOKEN` |
| Starfish Retention Solutions (Hobsons) | `starfish_retention` | `STARFISH_RETENTION_BASE_URL` *(url)*, `STARFISH_RETENTION_TOKEN` |
| Starling Bank business banking | `starling_bank` | `STARLING_BANK_BASE_URL` *(url)*, `STARLING_BANK_TOKEN` |
| Stash investing | `stash_invest` | `STASH_INVEST_BASE_URL` *(url)*, `STASH_INVEST_TOKEN` |
| Statsig feature-flag/experimentation REST API | `statsig` | `STATSIG_BASE_URL` *(url)*, `STATSIG_TOKEN` |
| StatusCake REST API | `statuscake` | `STATUSCAKE_BASE_URL` *(url)*, `STATUSCAKE_TOKEN` |
| Atlassian Statuspage REST API | `statuspage` | `STATUSPAGE_BASE_URL` *(url)*, `STATUSPAGE_TOKEN` |
| Steam Web REST API | `steam` | `STEAM_BASE_URL` *(url)*, `STEAM_TOKEN` |
| Stellar Cyber Open XDR | `stellar_cyber` | `STELLAR_CYBER_BASE_URL` *(url)*, `STELLAR_CYBER_TOKEN` |
| Step teen banking | `step_banking` | `STEP_BANKING_BASE_URL` *(url)*, `STEP_BANKING_TOKEN` |
| Sterling background check | `sterling_check` | `STERLING_CHECK_BASE_URL` *(url)*, `STERLING_CHECK_TOKEN` |
| Stitch (Talend) data pipeline REST API | `stitchdata` | `STITCHDATA_BASE_URL` *(url)*, `STITCHDATA_TOKEN` |
| 123RF stock media | `stock123rf` | `STOCK123RF_BASE_URL` *(url)*, `STOCK123RF_TOKEN` |
| Stocksy United stock imagery | `stocksy` | `STOCKSY_BASE_URL` *(url)*, `STOCKSY_TOKEN` |
| Stone payments REST API (Brazil) | `stone_pagamentos` | `STONE_PAGAMENTOS_BASE_URL` *(url)*, `STONE_PAGAMENTOS_TOKEN` |
| Stord supply-chain/warehousing REST API | `stord` | `STORD_BASE_URL` *(url)*, `STORD_TOKEN` |
| Storenvy REST API | `storenvy` | `STORENVY_BASE_URL` *(url)*, `STORENVY_TOKEN` |
| Stormboard whiteboard | `stormboard` | `STORMBOARD_BASE_URL` *(url)*, `STORMBOARD_TOKEN` |
| Storyblocks stock media | `storyblocks` | `STORYBLOCKS_BASE_URL` *(url)*, `STORYBLOCKS_TOKEN` |
| Storyblok headless CMS REST API | `storyblok` | `STORYBLOK_BASE_URL` *(url)*, `STORYBLOK_TOKEN` |
| Strapi headless CMS REST API | `strapi` | `STRAPI_BASE_URL` *(url)*, `STRAPI_TOKEN` |
| Strava | `strava` | `STRAVA_BASE_URL` *(url)*, `STRAVA_TOKEN` |
| Streak CRM REST (Gmail add-on) | `streak` | `STREAK_BASE_URL` *(url)*, `STREAK_TOKEN` |
| Streamlabs streaming tools | `streamlabs` | `STREAMLABS_BASE_URL` *(url)*, `STREAMLABS_TOKEN` |
| StreamSets (DataOps) REST API | `streamsets` | `STREAMSETS_BASE_URL` *(url)*, `STREAMSETS_TOKEN` |
| StreamYard live streaming | `streamyard` | `STREAMYARD_BASE_URL` *(url)*, `STREAMYARD_TOKEN` |
| Stripe | `stripe` | `STRIPE_SECRET_KEY` |
| Submittable grants/applications | `submittable` | `SUBMITTABLE_BASE_URL` *(url)*, `SUBMITTABLE_TOKEN` |
| Substack newsletter publishing | `substack` | `SUBSTACK_BASE_URL` *(url)*, `SUBSTACK_TOKEN` |
| SAP SuccessFactors | `successfactors` | `SUCCESSFACTORS_BASE_URL` *(url)*, `SUCCESSFACTORS_TOKEN` |
| SugarCRM REST (v11+) | `sugarcrm` | `SUGARCRM_BASE_URL` *(url)*, `SUGARCRM_TOKEN` |
| SugarWOD | `sugarwod` | `SUGARWOD_BASE_URL` *(url)*, `SUGARWOD_TOKEN` |
| SuiteCRM REST (v8 JSON:API, self-hosted) | `suitecrm` | `SUITECRM_BASE_URL` *(url)*, `SUITECRM_TOKEN` |
| Sumac nonprofit CRM | `sumac` | `SUMAC_BASE_URL` *(url)*, `SUMAC_TOKEN` |
| Summize CLM | `summize` | `SUMMIZE_BASE_URL` *(url)*, `SUMMIZE_TOKEN` |
| Sumo Logic | `sumologic` | `SUMOLOGIC_BASE_URL` *(url)*, `SUMOLOGIC_TOKEN` |
| SumUp payments REST API | `sumup` | `SUMUP_BASE_URL` *(url)*, `SUMUP_TOKEN` |
| Supabase management REST API | `supabase` | `SUPABASE_BASE_URL` *(url)*, `SUPABASE_TOKEN` |
| Supermetrics REST API | `supermetrics` | `SUPERMETRICS_BASE_URL` *(url)*, `SUPERMETRICS_TOKEN` |
| Apache Superset REST API | `superset` | `SUPERSET_BASE_URL` *(url)*, `SUPERSET_TOKEN` |
| SupportBee helpdesk | `supportbee` | `SUPPORTBEE_BASE_URL` *(url)*, `SUPPORTBEE_TOKEN` |
| SupportPal helpdesk REST (self-hosted) | `supportpal` | `SUPPORTPAL_BASE_URL` *(url)*, `SUPPORTPAL_TOKEN` |
| Sure (Sure App) embedded insurance | `sure_app` | `SURE_APP_BASE_URL` *(url)*, `SURE_APP_TOKEN` |
| SurveyLegend | `surveylegend` | `SURVEYLEGEND_BASE_URL` *(url)*, `SURVEYLEGEND_TOKEN` |
| SurveyMonkey | `surveymonkey` | `SURVEYMONKEY_BASE_URL` *(url)*, `SURVEYMONKEY_TOKEN` |
| SurveySparrow | `surveysparrow` | `SURVEYSPARROW_BASE_URL` *(url)*, `SURVEYSPARROW_TOKEN` |
| Swell headless commerce REST/GraphQL API | `swell` | `SWELL_BASE_URL` *(url)*, `SWELL_TOKEN` |
| Swiftype (Elastic App Search) REST API | `swiftype` | `SWIFTYPE_BASE_URL` *(url)*, `SWIFTYPE_TOKEN` |
| Swiggy partner | `swiggy` | `SWIGGY_BASE_URL` *(url)*, `SWIGGY_TOKEN` |
| Swimlane SOAR | `swimlane` | `SWIMLANE_BASE_URL` *(url)*, `SWIMLANE_TOKEN` |
| Switcher Studio live production | `switcherstudio` | `SWITCHERSTUDIO_BASE_URL` *(url)*, `SWITCHERSTUDIO_TOKEN` |
| Swyftx exchange | `swyftx` | `SWYFTX_BASE_URL` *(url)*, `SWYFTX_TOKEN` |
| Syft Analytics financial reporting | `syft_analytics` | `SYFT_ANALYTICS_BASE_URL` *(url)*, `SYFT_ANALYTICS_TOKEN` |
| Broadcom Symantec Endpoint Security | `symantec_endpoint` | `SYMANTEC_ENDPOINT_BASE_URL` *(url)*, `SYMANTEC_ENDPOINT_TOKEN` |
| Symphony messaging | `symphony` | `SYMPHONY_BASE_URL` *(url)*, `SYMPHONY_TOKEN` |
| Symplicity career-services/campus-life | `symplicity` | `SYMPLICITY_BASE_URL` *(url)*, `SYMPLICITY_TOKEN` |
| Synapse WMS | `synapse_wms` | `SYNAPSE_WMS_BASE_URL` *(url)*, `SYNAPSE_WMS_TOKEN` |
| Synapse banking-as-a-service | `synapsefi` | `SYNAPSEFI_BASE_URL` *(url)*, `SYNAPSEFI_TOKEN` |
| Syncron aftermarket/service parts | `syncron` | `SYNCRON_BASE_URL` *(url)*, `SYNCRON_TOKEN` |
| Synctera banking-as-a-service | `synctera` | `SYNCTERA_BASE_URL` *(url)*, `SYNCTERA_TOKEN` |
| Syniverse CPaaS/messaging REST API | `syniverse` | `SYNIVERSE_BASE_URL` *(url)*, `SYNIVERSE_TOKEN` |
| Synthesia AI video generation | `synthesia` | `SYNTHESIA_BASE_URL` *(url)*, `SYNTHESIA_TOKEN` |
| SysAid ITSM | `sysaid` | `SYSAID_BASE_URL` *(url)*, `SYSAID_TOKEN` |
| Sysdig Secure/Monitor REST API | `sysdig` | `SYSDIG_BASE_URL` *(url)*, `SYSDIG_TOKEN` |
| SYSPRO ERP | `syspro` | `SYSPRO_BASE_URL` *(url)*, `SYSPRO_TOKEN` |
| TabaPay payment disbursement | `tabapay` | `TABAPAY_BASE_URL` *(url)*, `TABAPAY_TOKEN` |
| Tableau Server/Cloud | `tableau` | `TABLEAU_BASE_URL` *(url)*, `TABLEAU_TOKEN` |
| TableCheck reservation | `tablecheck` | `TABLECHECK_BASE_URL` *(url)*, `TABLECHECK_TOKEN` |
| Taboola Backstage REST API | `taboola` | `TABOOLA_BASE_URL` *(url)*, `TABOOLA_TOKEN` |
| Tabs3 legal billing/practice management | `tabs3` | `TABS3_BASE_URL` *(url)*, `TABS3_TOKEN` |
| Tadabase REST API | `tadabase` | `TADABASE_BASE_URL` *(url)*, `TADABASE_TOKEN` |
| Taiga project management | `taiga` | `TAIGA_BASE_URL` *(url)*, `TAIGA_TOKEN` |
| Takealot marketplace seller REST API (South Africa) | `takealot` | `TAKEALOT_BASE_URL` *(url)*, `TAKEALOT_TOKEN` |
| talech (U.S | `talech` | `TALECH_BASE_URL` *(url)*, `TALECH_TOKEN` |
| Talend Cloud | `talend` | `TALEND_BASE_URL` *(url)*, `TALEND_TOKEN` |
| TalentLMS learning management | `talentlms` | `TALENTLMS_BASE_URL` *(url)*, `TALENTLMS_TOKEN` |
| Talkdesk | `talkdesk` | `TALKDESK_BASE_URL` *(url)*, `TALKDESK_TOKEN` |
| Tally Forms REST API | `tally_forms` | `TALLY_FORMS_BASE_URL` *(url)*, `TALLY_FORMS_TOKEN` |
| Tally forms | `tallyforms` | `TALLYFORMS_BASE_URL` *(url)*, `TALLYFORMS_TOKEN` |
| Tanla Platforms CPaaS messaging REST API | `tanla_platforms` | `TANLA_PLATFORMS_BASE_URL` *(url)*, `TANLA_PLATFORMS_TOKEN` |
| Tap Payments (MENA) REST API | `tap_payments` | `TAP_PAYMENTS_BASE_URL` *(url)*, `TAP_PAYMENTS_TOKEN` |
| Tapfiliate REST API | `tapfiliate` | `TAPFILIATE_BASE_URL` *(url)*, `TAPFILIATE_TOKEN` |
| Targetprocess | `targetprocess` | `TARGETPROCESS_BASE_URL` *(url)*, `TARGETPROCESS_TOKEN` |
| TargetX (Salesforce-based admissions CRM) | `targetx` | `TARGETX_BASE_URL` *(url)*, `TARGETX_TOKEN` |
| Tars REST API (no-code chatbot/landing page builder) | `tars_chatbot` | `TARS_CHATBOT_BASE_URL` *(url)*, `TARS_CHATBOT_TOKEN` |
| Taskade | `taskade` | `TASKADE_BASE_URL` *(url)*, `TASKADE_TOKEN` |
| Tastytrade brokerage | `tastytrade` | `TASTYTRADE_BASE_URL` *(url)*, `TASTYTRADE_TOKEN` |
| Tatango REST API (SMS marketing) | `tatango` | `TATANGO_BASE_URL` *(url)*, `TATANGO_TOKEN` |
| tawk.to chat | `tawkto` | `TAWKTO_BASE_URL` *(url)*, `TAWKTO_TOKEN` |
| TaxJar (Stripe) sales-tax REST API | `taxjar` | `TAXJAR_BASE_URL` *(url)*, `TAXJAR_TOKEN` |
| TD Ameritrade brokerage | `td_ameritrade` | `TD_AMERITRADE_BASE_URL` *(url)*, `TD_AMERITRADE_TOKEN` |
| Tealium REST API (CDP/tag management) | `tealium` | `TEALIUM_BASE_URL` *(url)*, `TEALIUM_TOKEN` |
| TeamBuildr | `teambuildr` | `TEAMBUILDR_BASE_URL` *(url)*, `TEAMBUILDR_TOKEN` |
| Siemens Teamcenter PLM | `teamcenter` | `TEAMCENTER_BASE_URL` *(url)*, `TEAMCENTER_TOKEN` |
| JetBrains TeamCity REST API | `teamcity` | `TEAMCITY_BASE_URL` *(url)*, `TEAMCITY_TOKEN` |
| TeamGantt | `teamgantt` | `TEAMGANTT_BASE_URL` *(url)*, `TEAMGANTT_TOKEN` |
| Teamgate CRM | `teamgate` | `TEAMGATE_BASE_URL` *(url)*, `TEAMGATE_TOKEN` |
| Teamleader CRM/invoicing REST API (Belgium) | `teamleader` | `TEAMLEADER_BASE_URL` *(url)*, `TEAMLEADER_TOKEN` |
| Microsoft Teams | `teams` | `TEAMS_WEBHOOK_URL` |
| TeamSnap | `teamsnap` | `TEAMSNAP_BASE_URL` *(url)*, `TEAMSNAP_TOKEN` |
| TeamSupport helpdesk | `teamsupport` | `TEAMSUPPORT_BASE_URL` *(url)*, `TEAMSUPPORT_TOKEN` |
| Teamtailor recruiting | `teamtailor` | `TEAMTAILOR_BASE_URL` *(url)*, `TEAMTAILOR_TOKEN` |
| TeamUp fitness scheduling | `teamup_fitness` | `TEAMUP_FITNESS_BASE_URL` *(url)*, `TEAMUP_FITNESS_TOKEN` |
| TeamViewer | `teamviewer` | `TEAMVIEWER_BASE_URL` *(url)*, `TEAMVIEWER_TOKEN` |
| Teamwork Projects | `teamwork` | `TEAMWORK_BASE_URL` *(url)*, `TEAMWORK_TOKEN` |
| Teamworks | `teamworks` | `TEAMWORKS_BASE_URL` *(url)*, `TEAMWORKS_TOKEN` |
| Tebra (Kareo) medical practice management REST API | `tebra` | `TEBRA_BASE_URL` *(url)*, `TEBRA_TOKEN` |
| Telegram Bot | `telegram` | `TELEGRAM_BASE_URL` *(url)*, `TELEGRAM_TOKEN` |
| Teleport access-plane REST/gRPC-gateway API | `teleport` | `TELEPORT_BASE_URL` *(url)*, `TELEPORT_TOKEN` |
| Telesign phone verification/messaging REST API | `telesign` | `TELESIGN_BASE_URL` *(url)*, `TELESIGN_TOKEN` |
| Teletrac Navman fleet/telematics | `teletrac_navman` | `TELETRAC_NAVMAN_BASE_URL` *(url)*, `TELETRAC_NAVMAN_TOKEN` |
| Telnyx REST API (SMS/voice/numbers) | `telnyx` | `TELNYX_BASE_URL` *(url)*, `TELNYX_TOKEN` |
| Telr payment gateway REST API (MENA) | `telr` | `TELR_BASE_URL` *(url)*, `TELR_TOKEN` |
| Temporal Cloud REST API | `temporal` | `TEMPORAL_BASE_URL` *(url)*, `TEMPORAL_TOKEN` |
| Tenable.io | `tenable` | `TENABLE_BASE_URL` *(url)*, `TENABLE_TOKEN` |
| Tencent Cloud REST API (China) | `tencent_cloud` | `TENCENT_CLOUD_BASE_URL` *(url)*, `TENCENT_CLOUD_TOKEN` |
| Tenor GIF REST API | `tenor` | `TENOR_BASE_URL` *(url)*, `TENOR_TOKEN` |
| 10to8 scheduling | `tentoeight` | `TENTOEIGHT_BASE_URL` *(url)*, `TENTOEIGHT_TOKEN` |
| Ten-X commercial real estate auction platform | `tenx` | `TENX_BASE_URL` *(url)*, `TENX_TOKEN` |
| Teradata REST (Vantage) | `teradata` | `TERADATA_BASE_URL` *(url)*, `TERADATA_TOKEN` |
| Termii African messaging/OTP REST API | `termii` | `TERMII_BASE_URL` *(url)*, `TERMII_TOKEN` |
| Terra Dotta study-abroad management | `terradotta` | `TERRADOTTA_BASE_URL` *(url)*, `TERRADOTTA_TOKEN` |
| Terraform Cloud/Enterprise | `terraform` | `TERRAFORM_BASE_URL` *(url)*, `TERRAFORM_TOKEN` |
| TestRail REST API | `testrail` | `TESTRAIL_BASE_URL` *(url)*, `TESTRAIL_TOKEN` |
| Tethr conversation analytics | `tethr` | `TETHR_BASE_URL` *(url)*, `TETHR_TOKEN` |
| Tettra wiki | `tettra` | `TETTRA_BASE_URL` *(url)*, `TETTRA_TOKEN` |
| Textedly REST API (SMS marketing) | `textedly` | `TEXTEDLY_BASE_URL` *(url)*, `TEXTEDLY_TOKEN` |
| Textlocal SMS REST API (India/UK) | `textlocal` | `TEXTLOCAL_BASE_URL` *(url)*, `TEXTLOCAL_TOKEN` |
| TextMagic REST API (SMS marketing) | `textmagic` | `TEXTMAGIC_BASE_URL` *(url)*, `TEXTMAGIC_TOKEN` |
| Textura (Oracle) construction payment management | `textura` | `TEXTURA_BASE_URL` *(url)*, `TEXTURA_TOKEN` |
| Thanx loyalty | `thanx` | `THANX_BASE_URL` *(url)*, `THANX_TOKEN` |
| TherapyNotes EHR REST API | `therapynotes` | `THERAPYNOTES_BASE_URL` *(url)*, `THERAPYNOTES_TOKEN` |
| PTC ThingWorx industrial IoT | `thingworx` | `THINGWORX_BASE_URL` *(url)*, `THINGWORX_TOKEN` |
| Thomson Reuters Elite legal billing | `thomson_reuters_elite` | `THOMSON_REUTERS_ELITE_BASE_URL` *(url)*, `THOMSON_REUTERS_ELITE_TOKEN` |
| Thoropass Compliance Automation | `thoropass` | `THOROPASS_BASE_URL` *(url)*, `THOROPASS_TOKEN` |
| ThoughtSpot | `thoughtspot` | `THOUGHTSPOT_BASE_URL` *(url)*, `THOUGHTSPOT_TOKEN` |
| Meta Threads API | `threads` | `THREADS_BASE_URL` *(url)*, `THREADS_TOKEN` |
| ThreatConnect Threat Intelligence Platform | `threatconnect` | `THREATCONNECT_BASE_URL` *(url)*, `THREATCONNECT_TOKEN` |
| 3CX PBX/UCaaS REST API | `three_cx` | `THREE_CX_BASE_URL` *(url)*, `THREE_CX_TOKEN` |
| 3CLogic contact center (ServiceNow-integrated) | `threeclogic` | `THREECLOGIC_BASE_URL` *(url)*, `THREECLOGIC_TOKEN` |
| Dassault Systemes 3DEXPERIENCE platform | `threedexperience` | `THREEDEXPERIENCE_BASE_URL` *(url)*, `THREEDEXPERIENCE_TOKEN` |
| Threema Work messaging | `threema` | `THREEMA_BASE_URL` *(url)*, `THREEMA_TOKEN` |
| 3Play Media captioning/subtitling | `threeplay_media` | `THREEPLAY_MEDIA_BASE_URL` *(url)*, `THREEPLAY_MEDIA_TOKEN` |
| ThriveCart REST API | `thrivecart` | `THRIVECART_BASE_URL` *(url)*, `THRIVECART_TOKEN` |
| Thunkable REST API (app builder resources) | `thunkable` | `THUNKABLE_BASE_URL` *(url)*, `THUNKABLE_TOKEN` |
| Ticket Tailor | `tickettailor` | `TICKETTAILOR_BASE_URL` *(url)*, `TICKETTAILOR_TOKEN` |
| Tidal music REST API | `tidal` | `TIDAL_BASE_URL` *(url)*, `TIDAL_TOKEN` |
| Tide business banking REST API (UK) | `tide` | `TIDE_BASE_URL` *(url)*, `TIDE_TOKEN` |
| Tide business banking | `tide_bank` | `TIDE_BANK_BASE_URL` *(url)*, `TIDE_BANK_TOKEN` |
| Tidio REST API | `tidio` | `TIDIO_BASE_URL` *(url)*, `TIDIO_TOKEN` |
| Tiingo market-data | `tiingo` | `TIINGO_BASE_URL` *(url)*, `TIINGO_TOKEN` |
| TikTok for Developers REST API | `tiktok` | `TIKTOK_BASE_URL` *(url)*, `TIKTOK_TOKEN` |
| TikTok Marketing API (Ads) | `tiktokads` | `TIKTOKADS_BASE_URL` *(url)*, `TIKTOKADS_TOKEN` |
| Tiller Money budgeting | `tiller_money` | `TILLER_MONEY_BASE_URL` *(url)*, `TILLER_MONEY_TOKEN` |
| Timecounts volunteer management | `timecounts` | `TIMECOUNTS_BASE_URL` *(url)*, `TIMECOUNTS_TOKEN` |
| Timescale Cloud REST API | `timescale` | `TIMESCALE_BASE_URL` *(url)*, `TIMESCALE_TOKEN` |
| TimescaleDB (Timescale Cloud) REST/management API | `timescaledb` | `TIMESCALEDB_BASE_URL` *(url)*, `TIMESCALEDB_TOKEN` |
| TimeSolv legal time/billing | `timesolv` | `TIMESOLV_BASE_URL` *(url)*, `TIMESOLV_TOKEN` |
| TimeTap scheduling | `timetap` | `TIMETAP_BASE_URL` *(url)*, `TIMETAP_TOKEN` |
| TimeTrade appointment scheduling | `timetrade` | `TIMETRADE_BASE_URL` *(url)*, `TIMETRADE_TOKEN` |
| TinaCMS content API (GraphQL) | `tinacms` | `TINACMS_BASE_URL` *(url)*, `TINACMS_TOKEN` |
| Tines Security Automation | `tines` | `TINES_BASE_URL` *(url)*, `TINES_TOKEN` |
| Tink open-banking | `tink` | `TINK_BASE_URL` *(url)*, `TINK_TOKEN` |
| Tiny ERP REST API (Brazil) | `tiny_erp` | `TINY_ERP_BASE_URL` *(url)*, `TINY_ERP_TOKEN` |
| Tinybird real-time analytics REST API | `tinybird` | `TINYBIRD_BASE_URL` *(url)*, `TINYBIRD_TOKEN` |
| TinyPNG image compression | `tinypng` | `TINYPNG_BASE_URL` *(url)*, `TINYPNG_TOKEN` |
| Tipalti payables automation | `tipalti` | `TIPALTI_BASE_URL` *(url)*, `TIPALTI_TOKEN` |
| Titan School Solutions (meal payment/SIS) | `titan_school` | `TITAN_SCHOOL_BASE_URL` *(url)*, `TITAN_SCHOOL_TOKEN` |
| tl;dv meeting recorder | `tldv` | `TLDV_BASE_URL` *(url)*, `TLDV_TOKEN` |
| Toast POS REST API | `toast` | `TOAST_BASE_URL` *(url)*, `TOAST_TOKEN` |
| Toast restaurant POS REST API | `toast_pos` | `TOAST_POS_BASE_URL` *(url)*, `TOAST_POS_TOKEN` |
| Tock reservations | `tock` | `TOCK_BASE_URL` *(url)*, `TOCK_TOKEN` |
| Todoist | `todoist` | `TODOIST_BASE_URL` *(url)*, `TODOIST_TOKEN` |
| Together AI REST API | `together_ai` | `TOGETHER_AI_BASE_URL` *(url)*, `TOGETHER_AI_TOKEN` |
| Toggl Track time tracking | `toggl` | `TOGGL_BASE_URL` *(url)*, `TOGGL_TOKEN` |
| Toggl Plan | `toggl_plan` | `TOGGL_PLAN_BASE_URL` *(url)*, `TOGGL_PLAN_TOKEN` |
| Tokopedia (GoTo) Seller REST API | `tokopedia` | `TOKOPEDIA_BASE_URL` *(url)*, `TOKOPEDIA_TOKEN` |
| Toky VoIP calling REST API | `toky` | `TOKY_BASE_URL` *(url)*, `TOKY_TOKEN` |
| Tookan field service/delivery management | `tookan` | `TOOKAN_BASE_URL` *(url)*, `TOOKAN_TOKEN` |
| ToolJet REST API (low-code internal tool builder) | `tooljet` | `TOOLJET_BASE_URL` *(url)*, `TOOLJET_TOKEN` |
| ToolsGroup demand/supply planning | `toolsgroup` | `TOOLSGROUP_BASE_URL` *(url)*, `TOOLSGROUP_TOKEN` |
| Toornament REST API (esports tournaments) | `toornament` | `TOORNAMENT_BASE_URL` *(url)*, `TOORNAMENT_TOKEN` |
| TOPdesk Service Management | `topdesk` | `TOPDESK_BASE_URL` *(url)*, `TOPDESK_TOKEN` |
| Top Producer real estate CRM | `topproducer` | `TOPPRODUCER_BASE_URL` *(url)*, `TOPPRODUCER_TOKEN` |
| Torq Security Automation | `torq` | `TORQ_BASE_URL` *(url)*, `TORQ_TOKEN` |
| Toss Payments REST API (South Korea) | `toss` | `TOSS_BASE_URL` *(url)*, `TOSS_TOKEN` |
| Totango customer success | `totango` | `TOTANGO_BASE_URL` *(url)*, `TOTANGO_TOKEN` |
| TOTVS ERP REST API (Brazil) | `totvs` | `TOTVS_BASE_URL` *(url)*, `TOTVS_TOKEN` |
| TouchBistro POS REST API | `touchbistro` | `TOUCHBISTRO_BASE_URL` *(url)*, `TOUCHBISTRO_TOKEN` |
| Track It Forward volunteer tracking | `trackitforward` | `TRACKITFORWARD_BASE_URL` *(url)*, `TRACKITFORWARD_TOKEN` |
| TrackJS REST API | `trackjs` | `TRACKJS_BASE_URL` *(url)*, `TRACKJS_TOKEN` |
| Sparta Systems TrackWise quality management | `trackwise` | `TRACKWISE_BASE_URL` *(url)*, `TRACKWISE_TOKEN` |
| The Trade Desk REST API | `tradedesk` | `TRADEDESK_BASE_URL` *(url)*, `TRADEDESK_TOKEN` |
| TradeStation brokerage | `tradestation` | `TRADESTATION_BASE_URL` *(url)*, `TRADESTATION_TOKEN` |
| Tradier brokerage | `tradier` | `TRADIER_BASE_URL` *(url)*, `TRADIER_TOKEN` |
| Trading 212 | `trading212` | `TRADING212_BASE_URL` *(url)*, `TRADING212_TOKEN` |
| TradingView REST/broker-integration API | `tradingview` | `TRADINGVIEW_BASE_URL` *(url)*, `TRADINGVIEW_TOKEN` |
| Trainerize | `trainerize` | `TRAINERIZE_BASE_URL` *(url)*, `TRAINERIZE_TOKEN` |
| TrainHeroic | `trainheroic` | `TRAINHEROIC_BASE_URL` *(url)*, `TRAINHEROIC_TOKEN` |
| TrainingPeaks | `trainingpeaks` | `TRAININGPEAKS_BASE_URL` *(url)*, `TRAININGPEAKS_TOKEN` |
| Parsec TrakSYS MES | `traksys` | `TRAKSYS_BASE_URL` *(url)*, `TRAKSYS_TOKEN` |
| Transak on/off-ramp | `transak` | `TRANSAK_BASE_URL` *(url)*, `TRANSAK_TOKEN` |
| Transfix freight brokerage REST API | `transfix` | `TRANSFIX_BASE_URL` *(url)*, `TRANSFIX_TOKEN` |
| Transistor.fm podcast hosting | `transistor_fm` | `TRANSISTOR_FM_BASE_URL` *(url)*, `TRANSISTOR_FM_TOKEN` |
| Transmit Security (Identity Orchestration) | `transmit_security` | `TRANSMIT_SECURITY_BASE_URL` *(url)*, `TRANSMIT_SECURITY_TOKEN` |
| Travelport Universal API for travel distribution | `travelport` | `TRAVELPORT_BASE_URL` *(url)*, `TRAVELPORT_TOKEN` |
| Travis CI REST API | `travisci` | `TRAVISCI_BASE_URL` *(url)*, `TRAVISCI_TOKEN` |
| Tray.io (Tray Platform) REST API | `trayio` | `TRAYIO_BASE_URL` *(url)*, `TRAYIO_TOKEN` |
| Treasure Data REST API (CDP) | `treasuredata` | `TREASUREDATA_BASE_URL` *(url)*, `TREASUREDATA_TOKEN` |
| Treasury Prime banking-as-a-service | `treasury_prime` | `TREASURY_PRIME_BASE_URL` *(url)*, `TREASURY_PRIME_TOKEN` |
| Trellis litigation analytics | `trellis_law` | `TRELLIS_LAW_BASE_URL` *(url)*, `TRELLIS_LAW_TOKEN` |
| Trellix (Helix/EDR) | `trellix` | `TRELLIX_BASE_URL` *(url)*, `TRELLIX_TOKEN` |
| Trello | `trello` | `TRELLO_KEY`, `TRELLO_TOKEN` |
| Trend Micro Vision One | `trend_micro` | `TREND_MICRO_BASE_URL` *(url)*, `TREND_MICRO_TOKEN` |
| TriNet HR/PEO | `trinet` | `TRINET_BASE_URL` *(url)*, `TRINET_TOKEN` |
| Trino REST API | `trino` | `TRINO_BASE_URL` *(url)*, `TRINO_TOKEN` |
| Trint transcription for media | `trint` | `TRINT_BASE_URL` *(url)*, `TRINT_TOKEN` |
| Trintech financial close/reconciliation | `trintech` | `TRINTECH_BASE_URL` *(url)*, `TRINTECH_TOKEN` |
| Trip.com travel partner REST API (China) | `trip_com` | `TRIP_COM_BASE_URL` *(url)*, `TRIP_COM_TOKEN` |
| Tripadvisor Content REST API | `tripadvisor` | `TRIPADVISOR_BASE_URL` *(url)*, `TRIPADVISOR_TOKEN` |
| Tripletex accounting/ERP REST API (Norway) | `tripletex` | `TRIPLETEX_BASE_URL` *(url)*, `TRIPLETEX_TOKEN` |
| Triple Whale REST API (marketing analytics) | `triplewhale` | `TRIPLEWHALE_BASE_URL` *(url)*, `TRIPLEWHALE_TOKEN` |
| Trivago hotel search partner REST API (Germany) | `trivago` | `TRIVAGO_BASE_URL` *(url)*, `TRIVAGO_TOKEN` |
| Trovo live streaming | `trovo` | `TROVO_BASE_URL` *(url)*, `TROVO_TOKEN` |
| Truffle Security (TruffleHog Enterprise) | `trufflesecurity` | `TRUFFLESECURITY_BASE_URL` *(url)*, `TRUFFLESECURITY_TOKEN` |
| Trulioo global identity verification | `trulioo` | `TRULIOO_BASE_URL` *(url)*, `TRULIOO_TOKEN` |
| Trumpia SMS marketing/automation REST API | `trumpia` | `TRUMPIA_BASE_URL` *(url)*, `TRUMPIA_TOKEN` |
| Trust Wallet API | `trust_wallet` | `TRUST_WALLET_BASE_URL` *(url)*, `TRUST_WALLET_TOKEN` |
| TrustArc privacy compliance management | `trustarc` | `TRUSTARC_BASE_URL` *(url)*, `TRUSTARC_TOKEN` |
| Trustly open banking payments REST API (Sweden/EU) | `trustly` | `TRUSTLY_BASE_URL` *(url)*, `TRUSTLY_TOKEN` |
| Trustpilot REST API | `trustpilot` | `TRUSTPILOT_BASE_URL` *(url)*, `TRUSTPILOT_TOKEN` |
| QuickBooks Time (TSheets) time tracking | `tsheets` | `TSHEETS_BASE_URL` *(url)*, `TSHEETS_TOKEN` |
| TubeBuddy YouTube channel tools | `tubebuddy` | `TUBEBUDDY_BASE_URL` *(url)*, `TUBEBUDDY_TOKEN` |
| Tulip frontline operations platform | `tulip_mes` | `TULIP_MES_BASE_URL` *(url)*, `TULIP_MES_TOKEN` |
| Tumblr REST API | `tumblr` | `TUMBLR_BASE_URL` *(url)*, `TUMBLR_TOKEN` |
| TurboTenant property management | `turbotenant` | `TURBOTENANT_BASE_URL` *(url)*, `TURBOTENANT_TOKEN` |
| Turnitin similarity/originality REST API | `turnitin` | `TURNITIN_BASE_URL` *(url)*, `TURNITIN_TOKEN` |
| Turvo transportation-management REST API | `turvo` | `TURVO_BASE_URL` *(url)*, `TURVO_TOKEN` |
| Twelve Data market-data | `twelvedata` | `TWELVEDATA_BASE_URL` *(url)*, `TWELVEDATA_TOKEN` |
| Twilio | `twilio` | `TWILIO_ACCOUNT_SID` *(url)*, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER` *(url)* |
| Twinfield accounting REST API (Netherlands, Wolters Kluwer) | `twinfield` | `TWINFIELD_BASE_URL` *(url)*, `TWINFIELD_TOKEN` |
| Twist (Doist) team messaging | `twist` | `TWIST_BASE_URL` *(url)*, `TWIST_TOKEN` |
| Twitch Helix REST API | `twitch` | `TWITCH_BASE_URL` *(url)*, `TWITCH_TOKEN` |
| Twitter/X API v2 | `twitter` | `TWITTER_BASE_URL` *(url)*, `TWITTER_TOKEN` |
| X (Twitter) Ads API | `twitterads` | `TWITTERADS_BASE_URL` *(url)*, `TWITTERADS_TOKEN` |
| 2Checkout (Verifone) payments REST API | `twocheckout` | `TWOCHECKOUT_BASE_URL` *(url)*, `TWOCHECKOUT_TOKEN` |
| Tyler Technologies (Munis/EnerGov) | `tylertechnologies` | `TYLERTECHNOLOGIES_BASE_URL` *(url)*, `TYLERTECHNOLOGIES_TOKEN` |
| tyntec communications REST API | `tyntec` | `TYNTEC_BASE_URL` *(url)*, `TYNTEC_TOKEN` |
| Typeform REST API | `typeform` | `TYPEFORM_BASE_URL` *(url)*, `TYPEFORM_TOKEN` |
| Typesense REST API | `typesense` | `TYPESENSE_BASE_URL` *(url)*, `TYPESENSE_TOKEN` |
| TYPO3 CMS REST API (extension-based) | `typo3` | `TYPO3_BASE_URL` *(url)*, `TYPO3_TOKEN` |
| Uber Eats | `ubereats` | `UBEREATS_BASE_URL` *(url)*, `UBEREATS_TOKEN` |
| Ubidots IoT platform | `ubidots` | `UBIDOTS_BASE_URL` *(url)*, `UBIDOTS_TOKEN` |
| Ubindi class scheduling | `ubindi` | `UBINDI_BASE_URL` *(url)*, `UBINDI_TOKEN` |
| Udemy Business REST API | `udemy` | `UDEMY_BASE_URL` *(url)*, `UDEMY_TOKEN` |
| UJET contact center | `ujet` | `UJET_BASE_URL` *(url)*, `UJET_TOKEN` |
| UKG (Ultimate Kronos) | `ukg` | `UKG_BASE_URL` *(url)*, `UKG_TOKEN` |
| Ultimate.ai conversational AI REST API | `ultimate_ai` | `ULTIMATE_AI_BASE_URL` *(url)*, `ULTIMATE_AI_TOKEN` |
| Umbraco Content Delivery/Management REST API | `umbraco` | `UMBRACO_BASE_URL` *(url)*, `UMBRACO_TOKEN` |
| Unbounce REST API (landing pages) | `unbounce` | `UNBOUNCE_BASE_URL` *(url)*, `UNBOUNCE_TOKEN` |
| UniCourt court records/litigation data | `unicourt` | `UNICOURT_BASE_URL` *(url)*, `UNICOURT_TOKEN` |
| Unily intranet | `unily` | `UNILY_BASE_URL` *(url)*, `UNILY_TOKEN` |
| Unit4 ERP | `unit4` | `UNIT4_BASE_URL` *(url)*, `UNIT4_TOKEN` |
| Unit banking-as-a-service | `unit_finance` | `UNIT_FINANCE_BASE_URL` *(url)*, `UNIT_FINANCE_TOKEN` |
| Unity Cloud Services REST API | `unity` | `UNITY_BASE_URL` *(url)*, `UNITY_TOKEN` |
| Universe events/ticketing | `universe_events` | `UNIVERSE_EVENTS_BASE_URL` *(url)*, `UNIVERSE_EVENTS_TOKEN` |
| Unleash feature-flag REST API | `unleash` | `UNLEASH_BASE_URL` *(url)*, `UNLEASH_TOKEN` |
| Unleashed Software inventory REST API | `unleashed_software` | `UNLEASHED_SOFTWARE_BASE_URL` *(url)*, `UNLEASHED_SOFTWARE_TOKEN` |
| Unqork no-code insurance/enterprise platform | `unqork` | `UNQORK_BASE_URL` *(url)*, `UNQORK_TOKEN` |
| Unsplash REST API | `unsplash` | `UNSPLASH_BASE_URL` *(url)*, `UNSPLASH_TOKEN` |
| Unzer payment gateway REST API (Germany, formerly Heidelpay) | `unzer` | `UNZER_BASE_URL` *(url)*, `UNZER_TOKEN` |
| Upbit exchange | `upbit` | `UPBIT_BASE_URL` *(url)*, `UPBIT_TOKEN` |
| UpCloud REST API | `upcloud` | `UPCLOUD_BASE_URL` *(url)*, `UPCLOUD_TOKEN` |
| Updox (fax/document) | `updox` | `UPDOX_BASE_URL` *(url)*, `UPDOX_TOKEN` |
| Upgrade Inc | `upgrade_inc` | `UPGRADE_INC_BASE_URL` *(url)*, `UPGRADE_INC_TOKEN` |
| UpGuard CyberRisk | `upguard` | `UPGUARD_BASE_URL` *(url)*, `UPGUARD_TOKEN` |
| UpKeep CMMS | `upkeep` | `UPKEEP_BASE_URL` *(url)*, `UPKEEP_TOKEN` |
| UpLead prospecting | `uplead` | `UPLEAD_BASE_URL` *(url)*, `UPLEAD_TOKEN` |
| Uploadcare file/image CDN | `uploadcare` | `UPLOADCARE_BASE_URL` *(url)*, `UPLOADCARE_TOKEN` |
| Upserve (Lightspeed Restaurant) | `upserve` | `UPSERVE_BASE_URL` *(url)*, `UPSERVE_TOKEN` |
| Upstart lending | `upstart` | `UPSTART_BASE_URL` *(url)*, `UPSTART_TOKEN` |
| Upstash (Redis/Kafka/QStash) REST API | `upstash` | `UPSTASH_BASE_URL` *(url)*, `UPSTASH_TOKEN` |
| Uptake industrial asset performance | `uptake` | `UPTAKE_BASE_URL` *(url)*, `UPTAKE_TOKEN` |
| UptimeRobot REST API | `uptimerobot` | `UPTIMEROBOT_BASE_URL` *(url)*, `UPTIMEROBOT_TOKEN` |
| Uscreen video monetization platform | `uscreen` | `USCREEN_BASE_URL` *(url)*, `USCREEN_TOKEN` |
| Userlike chat | `userlike` | `USERLIKE_BASE_URL` *(url)*, `USERLIKE_TOKEN` |
| Usersnap | `usersnap` | `USERSNAP_BASE_URL` *(url)*, `USERSNAP_TOKEN` |
| UserVoice | `uservoice` | `USERVOICE_BASE_URL` *(url)*, `USERVOICE_TOKEN` |
| Vagaro scheduling | `vagaro` | `VAGARO_BASE_URL` *(url)*, `VAGARO_TOKEN` |
| Vald REST/gRPC-gateway API (distributed vector search) | `vald_search` | `VALD_SEARCH_BASE_URL` *(url)*, `VALD_SEARCH_TOKEN` |
| Valohai REST API (MLOps orchestration) | `valohai` | `VALOHAI_BASE_URL` *(url)*, `VALOHAI_TOKEN` |
| ValueFirst messaging REST API | `valuefirst` | `VALUEFIRST_BASE_URL` *(url)*, `VALUEFIRST_TOKEN` |
| Vanta REST (GRC/compliance) | `vanta` | `VANTA_BASE_URL` *(url)*, `VANTA_TOKEN` |
| Vantaca HOA/community management | `vantaca` | `VANTACA_BASE_URL` *(url)*, `VANTACA_TOKEN` |
| Varo Bank | `varo` | `VARO_BASE_URL` *(url)*, `VARO_TOKEN` |
| Varonis Data Security Platform | `varonis` | `VARONIS_BASE_URL` *(url)*, `VARONIS_TOKEN` |
| Vast.ai REST API (GPU compute marketplace) | `vast_ai` | `VAST_AI_BASE_URL` *(url)*, `VAST_AI_TOKEN` |
| HashiCorp Vault | `vault` | `VAULT_BASE_URL` *(url)*, `VAULT_TOKEN` |
| Vbrick enterprise video | `vbrick` | `VBRICK_BASE_URL` *(url)*, `VBRICK_TOKEN` |
| Vectara REST API (RAG-as-a-service search platform) | `vectara` | `VECTARA_BASE_URL` *(url)*, `VECTARA_TOKEN` |
| Vecteezy stock vectors | `vecteezy` | `VECTEEZY_BASE_URL` *(url)*, `VECTEEZY_TOKEN` |
| Vectra AI Platform | `vectra` | `VECTRA_BASE_URL` *(url)*, `VECTRA_TOKEN` |
| VEED.IO video editing | `veed` | `VEED_BASE_URL` *(url)*, `VEED_TOKEN` |
| Veeqo inventory/order REST API | `veeqo` | `VEEQO_BASE_URL` *(url)*, `VEEQO_TOKEN` |
| Veeva Vault QMS | `veeva_vault_qms` | `VEEVA_VAULT_QMS_BASE_URL` *(url)*, `VEEVA_VAULT_QMS_TOKEN` |
| Veloxy sales engagement | `veloxy` | `VELOXY_BASE_URL` *(url)*, `VELOXY_TOKEN` |
| Vena Solutions FP&A | `vena_solutions` | `VENA_SOLUTIONS_BASE_URL` *(url)*, `VENA_SOLUTIONS_TOKEN` |
| Vend (Lightspeed X-Series) POS REST API | `vend` | `VEND_BASE_URL` *(url)*, `VEND_TOKEN` |
| Venmo (PayPal) business REST API | `venmo` | `VENMO_BASE_URL` *(url)*, `VENMO_TOKEN` |
| Venngage infographic/design | `venngage` | `VENNGAGE_BASE_URL` *(url)*, `VENNGAGE_TOKEN` |
| Veracode REST API | `veracode` | `VERACODE_BASE_URL` *(url)*, `VERACODE_TOKEN` |
| Veracross independent-school SIS | `veracross` | `VERACROSS_BASE_URL` *(url)*, `VERACROSS_TOKEN` |
| Veradigm (Allscripts) EHR REST/FHIR API | `veradigm` | `VERADIGM_BASE_URL` *(url)*, `VERADIGM_TOKEN` |
| Verifone payments REST API | `verifone` | `VERIFONE_BASE_URL` *(url)*, `VERIFONE_TOKEN` |
| Verint workforce engagement/contact center | `verint` | `VERINT_BASE_URL` *(url)*, `VERINT_TOKEN` |
| Verisk insurance data/analytics | `verisk` | `VERISK_BASE_URL` *(url)*, `VERISK_TOKEN` |
| Verizon Connect fleet-management REST API | `verizon_connect` | `VERIZON_CONNECT_BASE_URL` *(url)*, `VERIZON_CONNECT_TOKEN` |
| Verloop.io chatbot REST API | `verloop` | `VERLOOP_BASE_URL` *(url)*, `VERLOOP_TOKEN` |
| Vertafore (AMS360) insurance REST API | `vertafore` | `VERTAFORE_BASE_URL` *(url)*, `VERTAFORE_TOKEN` |
| Google Vertex AI | `vertex` | `VERTEX_PROJECT` *(url)*, `VERTEX_LOCATION` *(url)*, `VERTEX_ACCESS_TOKEN` |
| Vertex O Series tax REST (calculation/returns; distinct from the Vertex AI tool) | `vertex_tax` | `VERTEX_TAX_BASE_URL` *(url)*, `VERTEX_TAX_TOKEN` |
| Vertica REST API (management/query) | `vertica` | `VERTICA_BASE_URL` *(url)*, `VERTICA_TOKEN` |
| Vespa.ai REST API (search/vector engine) | `vespa_ai` | `VESPA_AI_BASE_URL` *(url)*, `VESPA_AI_TOKEN` |
| Veza Access Security Platform | `veza` | `VEZA_BASE_URL` *(url)*, `VEZA_TOKEN` |
| Viber messaging | `viber` | `VIBER_BASE_URL` *(url)*, `VIBER_TOKEN` |
| Splunk On-Call (VictorOps) REST API | `victorops` | `VICTOROPS_BASE_URL` *(url)*, `VICTOROPS_TOKEN` |
| vidIQ YouTube analytics | `vidiq` | `VIDIQ_BASE_URL` *(url)*, `VIDIQ_TOKEN` |
| Vidyard video | `vidyard` | `VIDYARD_BASE_URL` *(url)*, `VIDYARD_TOKEN` |
| Vidyo video conferencing | `vidyo` | `VIDYO_BASE_URL` *(url)*, `VIDYO_TOKEN` |
| Viewpoint (Trimble Construction One) | `viewpoint_construction` | `VIEWPOINT_CONSTRUCTION_BASE_URL` *(url)*, `VIEWPOINT_CONSTRUCTION_TOKEN` |
| Vimeo REST API for video hosting | `vimeo` | `VIMEO_BASE_URL` *(url)*, `VIMEO_TOKEN` |
| Vindi subscription billing REST API (Brazil) | `vindi` | `VINDI_BASE_URL` *(url)*, `VINDI_TOKEN` |
| VinSolutions automotive CRM REST API | `vinsolutions` | `VINSOLUTIONS_BASE_URL` *(url)*, `VINSOLUTIONS_TOKEN` |
| Virtuagym | `virtuagym` | `VIRTUAGYM_BASE_URL` *(url)*, `VIRTUAGYM_TOKEN` |
| Virtuous CRM | `virtuous` | `VIRTUOUS_BASE_URL` *(url)*, `VIRTUOUS_TOKEN` |
| VirusTotal | `virustotal` | `VIRUSTOTAL_BASE_URL` *(url)*, `VIRUSTOTAL_TOKEN` |
| Visier people analytics | `visier` | `VISIER_BASE_URL` *(url)*, `VISIER_TOKEN` |
| Vision Helpdesk | `visionhelpdesk` | `VISIONHELPDESK_BASE_URL` *(url)*, `VISIONHELPDESK_TOKEN` |
| Visma ERP/accounting REST API (Nordics) | `visma` | `VISMA_BASE_URL` *(url)*, `VISMA_TOKEN` |
| Visme visual content design | `visme` | `VISME_BASE_URL` *(url)*, `VISME_TOKEN` |
| VistaCreate (Crello) design/media | `vistacreate` | `VISTACREATE_BASE_URL` *(url)*, `VISTACREATE_TOKEN` |
| Vitally customer success | `vitally` | `VITALLY_BASE_URL` *(url)*, `VITALLY_TOKEN` |
| VKontakte (VK) REST API | `vk` | `VK_BASE_URL` *(url)*, `VK_TOKEN` |
| vLex legal research | `vlex` | `VLEX_BASE_URL` *(url)*, `VLEX_TOKEN` |
| Voiceflow REST API (conversational app builder) | `voiceflow` | `VOICEFLOW_BASE_URL` *(url)*, `VOICEFLOW_TOKEN` |
| VoIP.ms REST API | `voipms` | `VOIPMS_BASE_URL` *(url)*, `VOIPMS_TOKEN` |
| Volgistics volunteer management | `volgistics` | `VOLGISTICS_BASE_URL` *(url)*, `VOLGISTICS_TOKEN` |
| Voltage Park REST API (GPU cloud compute) | `voltage_park` | `VOLTAGE_PARK_BASE_URL` *(url)*, `VOLTAGE_PARK_TOKEN` |
| VolunteerHub | `volunteerhub` | `VOLUNTEERHUB_BASE_URL` *(url)*, `VOLUNTEERHUB_TOKEN` |
| VolunteerLocal | `volunteerlocal` | `VOLUNTEERLOCAL_BASE_URL` *(url)*, `VOLUNTEERLOCAL_TOKEN` |
| VolunteerMatch | `volunteermatch` | `VOLUNTEERMATCH_BASE_URL` *(url)*, `VOLUNTEERMATCH_TOKEN` |
| Volusion REST API | `volusion` | `VOLUSION_BASE_URL` *(url)*, `VOLUSION_TOKEN` |
| VOMO volunteer management | `vomo` | `VOMO_BASE_URL` *(url)*, `VOMO_TOKEN` |
| Vonage | `vonage` | `VONAGE_BASE_URL` *(url)*, `VONAGE_TOKEN` |
| Vonigo field service scheduling | `vonigo` | `VONIGO_BASE_URL` *(url)*, `VONIGO_TOKEN` |
| Vouch Insurance (startup-focused) | `vouch_insurance` | `VOUCH_INSURANCE_BASE_URL` *(url)*, `VOUCH_INSURANCE_TOKEN` |
| Voximplant cloud communications platform REST API | `voximplant` | `VOXIMPLANT_BASE_URL` *(url)*, `VOXIMPLANT_TOKEN` |
| VMware vSphere | `vsphere` | `VSPHERE_BASE_URL` *(url)*, `VSPHERE_TOKEN` |
| VTEX commerce REST API | `vtex` | `VTEX_BASE_URL` *(url)*, `VTEX_TOKEN` |
| Vtiger CRM webservice | `vtiger` | `VTIGER_BASE_URL` *(url)*, `VTIGER_TOKEN` |
| Vulcan Cyber (Voyager18) | `vulcan_cyber` | `VULCAN_CYBER_BASE_URL` *(url)*, `VULCAN_CYBER_TOKEN` |
| Vultr Cloud REST API | `vultr` | `VULTR_BASE_URL` *(url)*, `VULTR_TOKEN` |
| VWO REST API (A/B testing) | `vwo` | `VWO_BASE_URL` *(url)*, `VWO_TOKEN` |
| Vzaar video hosting | `vzaar` | `VZAAR_BASE_URL` *(url)*, `VZAAR_TOKEN` |
| Wagepoint payroll | `wagepoint` | `WAGEPOINT_BASE_URL` *(url)*, `WAGEPOINT_TOKEN` |
| Wagtail CMS REST API (wagtail.api.v2) | `wagtail` | `WAGTAIL_BASE_URL` *(url)*, `WAGTAIL_TOKEN` |
| Wahoo Fitness | `wahoo_fitness` | `WAHOO_FITNESS_BASE_URL` *(url)*, `WAHOO_FITNESS_TOKEN` |
| Walla studio management | `walla_fitness` | `WALLA_FITNESS_BASE_URL` *(url)*, `WALLA_FITNESS_TOKEN` |
| Wallarm API Security | `wallarm` | `WALLARM_BASE_URL` *(url)*, `WALLARM_TOKEN` |
| Walmart Marketplace REST API | `walmart_marketplace` | `WALMART_MARKETPLACE_BASE_URL` *(url)*, `WALMART_MARKETPLACE_TOKEN` |
| Weights & Biases REST API (experiment/model tracking) | `wandb_weave` | `WANDB_WEAVE_BASE_URL` *(url)*, `WANDB_WEAVE_TOKEN` |
| Wandera (Jamf Threat Defense) | `wandera` | `WANDERA_BASE_URL` *(url)*, `WANDERA_TOKEN` |
| Wasabi Cloud Storage REST API (S3-compatible) | `wasabi` | `WASABI_BASE_URL` *(url)*, `WASABI_TOKEN` |
| Wati WhatsApp Business API platform REST API | `wati` | `WATI_BASE_URL` *(url)*, `WATI_TOKEN` |
| IBM Watson Assistant REST API | `watson_assistant` | `WATSON_ASSISTANT_BASE_URL` *(url)*, `WATSON_ASSISTANT_TOKEN` |
| Wave accounting REST/GraphQL | `waveapps` | `WAVEAPPS_BASE_URL` *(url)*, `WAVEAPPS_TOKEN` |
| VMware Aria Operations for Applications (Wavefront) REST API | `wavefront` | `WAVEFRONT_BASE_URL` *(url)*, `WAVEFRONT_TOKEN` |
| Wayfair Supplier REST API | `wayfair` | `WAYFAIR_BASE_URL` *(url)*, `WAYFAIR_TOKEN` |
| WazirX exchange | `wazirx` | `WAZIRX_BASE_URL` *(url)*, `WAZIRX_TOKEN` |
| WealthEngine | `wealthengine` | `WEALTHENGINE_BASE_URL` *(url)*, `WEALTHENGINE_TOKEN` |
| Wealthfront robo-advisor | `wealthfront` | `WEALTHFRONT_BASE_URL` *(url)*, `WEALTHFRONT_TOKEN` |
| Wealthsimple Trade | `wealthsimple` | `WEALTHSIMPLE_BASE_URL` *(url)*, `WEALTHSIMPLE_TOKEN` |
| Weaviate REST API (vector database) | `weaviate` | `WEAVIATE_BASE_URL` *(url)*, `WEAVIATE_TOKEN` |
| WebEngage marketing automation REST API (India) | `webengage` | `WEBENGAGE_BASE_URL` *(url)*, `WEBENGAGE_TOKEN` |
| Cisco Webex | `webex` | `WEBEX_BASE_URL` *(url)*, `WEBEX_TOKEN` |
| Webflow REST API v2 | `webflow` | `WEBFLOW_BASE_URL` *(url)*, `WEBFLOW_TOKEN` |
| WebinarJam | `webinarjam` | `WEBINARJAM_BASE_URL` *(url)*, `WEBINARJAM_TOKEN` |
| Webiny headless CMS/serverless REST/GraphQL API | `webiny` | `WEBINY_BASE_URL` *(url)*, `WEBINY_TOKEN` |
| Webnode website builder REST API | `webnode` | `WEBNODE_BASE_URL` *(url)*, `WEBNODE_TOKEN` |
| WebPT physical therapy EHR REST API | `webpt` | `WEBPT_BASE_URL` *(url)*, `WEBPT_TOKEN` |
| Webull brokerage | `webull` | `WEBULL_BASE_URL` *(url)*, `WEBULL_TOKEN` |
| WeChat Official Account REST API | `wechat` | `WECHAT_BASE_URL` *(url)*, `WECHAT_TOKEN` |
| WeChat Pay REST API | `wechat_pay` | `WECHAT_PAY_BASE_URL` *(url)*, `WECHAT_PAY_TOKEN` |
| WeChat Work (WeCom) | `wechat_work` | `WECHAT_WORK_BASE_URL` *(url)*, `WECHAT_WORK_TOKEN` |
| weclapp ERP/CRM REST API (Germany) | `weclapp` | `WECLAPP_BASE_URL` *(url)*, `WECLAPP_TOKEN` |
| Weebly (Square Online) REST API | `weebly` | `WEEBLY_BASE_URL` *(url)*, `WEEBLY_TOKEN` |
| Sina Weibo REST API | `weibo` | `WEIBO_BASE_URL` *(url)*, `WEIBO_TOKEN` |
| WellnessLiving | `wellnessliving` | `WELLNESSLIVING_BASE_URL` *(url)*, `WELLNESSLIVING_TOKEN` |
| WePay (Chase) payments REST API | `wepay` | `WEPAY_BASE_URL` *(url)*, `WEPAY_TOKEN` |
| Westlaw (Thomson Reuters) legal research | `westlaw` | `WESTLAW_BASE_URL` *(url)*, `WESTLAW_TOKEN` |
| WeTransfer file/media transfer | `wetransfer` | `WETRANSFER_BASE_URL` *(url)*, `WETRANSFER_TOKEN` |
| WhatsApp Business Cloud REST API | `whatsapp_business` | `WHATSAPP_BUSINESS_BASE_URL` *(url)*, `WHATSAPP_BUSINESS_TOKEN` |
| When I Work scheduling | `when_i_work` | `WHEN_I_WORK_BASE_URL` *(url)*, `WHEN_I_WORK_TOKEN` |
| Whereby video meetings | `whereby` | `WHEREBY_BASE_URL` *(url)*, `WHEREBY_TOKEN` |
| Whimsical whiteboard/diagram | `whimsical` | `WHIMSICAL_BASE_URL` *(url)*, `WHIMSICAL_TOKEN` |
| Whoop | `whoop` | `WHOOP_BASE_URL` *(url)*, `WHOOP_TOKEN` |
| WildApricot membership/association management | `wildapricot` | `WILDAPRICOT_BASE_URL` *(url)*, `WILDAPRICOT_TOKEN` |
| Wimi collaboration | `wimi` | `WIMI_BASE_URL` *(url)*, `WIMI_TOKEN` |
| PTC Windchill PLM | `windchill` | `WINDCHILL_BASE_URL` *(url)*, `WINDCHILL_TOKEN` |
| Windsor.ai data connector REST API | `windsorai` | `WINDSORAI_BASE_URL` *(url)*, `WINDSORAI_TOKEN` |
| Wire secure messaging | `wire_app` | `WIRE_APP_BASE_URL` *(url)*, `WIRE_APP_TOKEN` |
| Wise (TransferWise) REST (multi-currency balances/transfers; writes need confirm) | `wise` | `WISE_BASE_URL` *(url)*, `WISE_TOKEN` |
| Wise (TransferWise) Platform | `wise_platform` | `WISE_PLATFORM_BASE_URL` *(url)*, `WISE_PLATFORM_TOKEN` |
| Wise Agent real estate CRM | `wiseagent` | `WISEAGENT_BASE_URL` *(url)*, `WISEAGENT_TOKEN` |
| Wisely restaurant CRM | `wisely` | `WISELY_BASE_URL` *(url)*, `WISELY_TOKEN` |
| Wish Merchant REST API | `wish` | `WISH_BASE_URL` *(url)*, `WISH_TOKEN` |
| Wistia REST API (video marketing) | `wistia` | `WISTIA_BASE_URL` *(url)*, `WISTIA_TOKEN` |
| Meta Wit.ai natural language understanding REST API | `wit_ai` | `WIT_AI_BASE_URL` *(url)*, `WIT_AI_TOKEN` |
| Wix REST API | `wix` | `WIX_BASE_URL` *(url)*, `WIX_TOKEN` |
| Wiz CNAPP | `wiz` | `WIZ_BASE_URL` *(url)*, `WIZ_TOKEN` |
| Wodify | `wodify` | `WODIFY_BASE_URL` *(url)*, `WODIFY_TOKEN` |
| Wolt delivery | `wolt` | `WOLT_BASE_URL` *(url)*, `WOLT_TOKEN` |
| Wonderchat REST API (no-code AI chatbot builder) | `wonderchat` | `WONDERCHAT_BASE_URL` *(url)*, `WONDERCHAT_TOKEN` |
| WooCommerce REST API for WordPress stores | `woocommerce` | `WOOCOMMERCE_BASE_URL` *(url)*, `WOOCOMMERCE_TOKEN` |
| Woodpecker.co cold-email sales engagement | `woodpecker` | `WOODPECKER_BASE_URL` *(url)*, `WOODPECKER_TOKEN` |
| Woopra analytics REST API | `woopra` | `WOOPRA_BASE_URL` *(url)*, `WOOPRA_TOKEN` |
| Wootric (InMoment CX) | `wootric` | `WOOTRIC_BASE_URL` *(url)*, `WOOTRIC_TOKEN` |
| WordPress REST API | `wordpress` | `WORDPRESS_BASE_URL` *(url)*, `WORDPRESS_TOKEN` |
| WordStream REST API (ad management) | `wordstream` | `WORDSTREAM_BASE_URL` *(url)*, `WORDSTREAM_TOKEN` |
| Workable REST (recruiting) | `workable` | `WORKABLE_BASE_URL` *(url)*, `WORKABLE_TOKEN` |
| Workamajig | `workamajig` | `WORKAMAJIG_BASE_URL` *(url)*, `WORKAMAJIG_TOKEN` |
| Workato | `workato` | `WORKATO_BASE_URL` *(url)*, `WORKATO_TOKEN` |
| Workbooks CRM REST/JSON API | `workbooks` | `WORKBOOKS_BASE_URL` *(url)*, `WORKBOOKS_TOKEN` |
| Workday | `workday` | `WORKDAY_BASE_URL` *(url)*, `WORKDAY_TOKEN` |
| Workday HCM/Financials REST (distinct from generic workday entry) | `workday_hcm` | `WORKDAY_HCM_BASE_URL` *(url)*, `WORKDAY_HCM_TOKEN` |
| WorkFlowy | `workflowy` | `WORKFLOWY_BASE_URL` *(url)*, `WORKFLOWY_TOKEN` |
| Adobe Workfront | `workfront` | `WORKFRONT_BASE_URL` *(url)*, `WORKFRONT_TOKEN` |
| Workiva (Wdesk) | `workiva` | `WORKIVA_BASE_URL` *(url)*, `WORKIVA_TOKEN` |
| Workiva Wdesk connected risk/compliance REST (distinct from generic workiva entry) | `workiva_grc` | `WORKIVA_GRC_BASE_URL` *(url)*, `WORKIVA_GRC_TOKEN` |
| WorkMax (AboutTime Technologies) construction time/data collection | `workmax` | `WORKMAX_BASE_URL` *(url)*, `WORKMAX_TOKEN` |
| Workplace by Meta REST (Graph API) | `workplace_meta` | `WORKPLACE_META_BASE_URL` *(url)*, `WORKPLACE_META_TOKEN` |
| WorkWave field service/routing | `workwave` | `WORKWAVE_BASE_URL` *(url)*, `WORKWAVE_TOKEN` |
| Workzone project management | `workzone` | `WORKZONE_BASE_URL` *(url)*, `WORKZONE_TOKEN` |
| Worldline payments REST API | `worldline` | `WORLDLINE_BASE_URL` *(url)*, `WORLDLINE_TOKEN` |
| Worldox document management | `worldox` | `WORLDOX_BASE_URL` *(url)*, `WORLDOX_TOKEN` |
| Worldpay payments REST API | `worldpay` | `WORLDPAY_BASE_URL` *(url)*, `WORLDPAY_TOKEN` |
| WorldRemit remittance | `worldremit` | `WORLDREMIT_BASE_URL` *(url)*, `WORLDREMIT_TOKEN` |
| Worximity manufacturing performance | `worximity` | `WORXIMITY_BASE_URL` *(url)*, `WORXIMITY_TOKEN` |
| Wowza Streaming Cloud REST API | `wowza` | `WOWZA_BASE_URL` *(url)*, `WOWZA_TOKEN` |
| Wrike work-management | `wrike` | `WRIKE_BASE_URL` *(url)*, `WRIKE_TOKEN` |
| Wufoo REST API (forms) | `wufoo` | `WUFOO_BASE_URL` *(url)*, `WUFOO_TOKEN` |
| X-Cart REST API | `x_cart` | `X_CART_BASE_URL` *(url)*, `X_CART_TOKEN` |
| Xactware / Xactimate claims estimating | `xactimate` | `XACTIMATE_BASE_URL` *(url)*, `XACTIMATE_TOKEN` |
| Xano REST API (no-code backend/database) | `xano` | `XANO_BASE_URL` *(url)*, `XANO_TOKEN` |
| Xbox Live REST API | `xbox` | `XBOX_BASE_URL` *(url)*, `XBOX_TOKEN` |
| Xendit payments REST API (Indonesia) | `xendit` | `XENDIT_BASE_URL` *(url)*, `XENDIT_TOKEN` |
| Xero accounting | `xero` | `XERO_BASE_URL` *(url)*, `XERO_TOKEN` |
| xMatters | `xmatters` | `XMATTERS_BASE_URL` *(url)*, `XMATTERS_TOKEN` |
| Yammer (Microsoft Viva Engage) | `yammer` | `YAMMER_BASE_URL` *(url)*, `YAMMER_TOKEN` |
| Yapily open-banking | `yapily` | `YAPILY_BASE_URL` *(url)*, `YAPILY_TOKEN` |
| Yardi Voyager property management REST/SOAP gateway | `yardi` | `YARDI_BASE_URL` *(url)*, `YARDI_TOKEN` |
| Yellow.ai conversational support | `yellowai` | `YELLOWAI_BASE_URL` *(url)*, `YELLOWAI_TOKEN` |
| Yellowbrick Data Warehouse REST API | `yellowbrick` | `YELLOWBRICK_BASE_URL` *(url)*, `YELLOWBRICK_TOKEN` |
| Yellowfin BI REST API | `yellowfin` | `YELLOWFIN_BASE_URL` *(url)*, `YELLOWFIN_TOKEN` |
| Yelp Guest Manager (Reservations) | `yelp_reservations` | `YELP_RESERVATIONS_BASE_URL` *(url)*, `YELP_RESERVATIONS_TOKEN` |
| Yesware sales engagement | `yesware` | `YESWARE_BASE_URL` *(url)*, `YESWARE_TOKEN` |
| You Need A Budget (YNAB) | `ynab` | `YNAB_BASE_URL` *(url)*, `YNAB_TOKEN` |
| Yoco payments REST API (South Africa) | `yoco` | `YOCO_BASE_URL` *(url)*, `YOCO_TOKEN` |
| Envestnet Yodlee account aggregation | `yodlee` | `YODLEE_BASE_URL` *(url)*, `YODLEE_TOKEN` |
| Yotpo REST API (reviews & loyalty) | `yotpo` | `YOTPO_BASE_URL` *(url)*, `YOTPO_TOKEN` |
| YouCanBook.me | `youcanbookme` | `YOUCANBOOKME_BASE_URL` *(url)*, `YOUCANBOOKME_TOKEN` |
| YouGile | `yougile` | `YOUGILE_BASE_URL` *(url)*, `YOUGILE_TOKEN` |
| YourCause (Blackbaud CSR) | `yourcause` | `YOURCAUSE_BASE_URL` *(url)*, `YOURCAUSE_TOKEN` |
| Yousign | `yousign` | `YOUSIGN_BASE_URL` *(url)*, `YOUSIGN_TOKEN` |
| Yubico YubiEnterprise/KeyManager | `yubico` | `YUBICO_BASE_URL` *(url)*, `YUBICO_TOKEN` |
| Yuki accounting REST API (Netherlands) | `yuki` | `YUKI_BASE_URL` *(url)*, `YUKI_TOKEN` |
| Yumpu digital publishing | `yumpu` | `YUMPU_BASE_URL` *(url)*, `YUMPU_TOKEN` |
| Zabbix JSON-RPC monitoring API | `zabbix` | `ZABBIX_BASE_URL` *(url)*, `ZABBIX_TOKEN` |
| Zadarma VoIP REST API | `zadarma` | `ZADARMA_BASE_URL` *(url)*, `ZADARMA_TOKEN` |
| Zalando Partner Program REST API | `zalando` | `ZALANDO_BASE_URL` *(url)*, `ZALANDO_TOKEN` |
| Zapier NLA / | `zapier` | `ZAPIER_BASE_URL` *(url)*, `ZAPIER_TOKEN` |
| Zappix visual IVR/contact center | `zappix` | `ZAPPIX_BASE_URL` *(url)*, `ZAPPIX_TOKEN` |
| Zapproved (Reveal) legal hold/e-discovery | `zapproved` | `ZAPPROVED_BASE_URL` *(url)*, `ZAPPROVED_TOKEN` |
| Zebra Reflexis workforce/task management | `zebra_reflexis` | `ZEBRA_REFLEXIS_BASE_URL` *(url)*, `ZEBRA_REFLEXIS_TOKEN` |
| Zen Cart REST API (plugin-based) | `zen_cart` | `ZEN_CART_BASE_URL` *(url)*, `ZEN_CART_TOKEN` |
| Zendesk Support | `zendesk` | `ZENDESK_BASE_URL` *(url)*, `ZENDESK_TOKEN` |
| Zendesk QA (Klaus) conversation review | `zendesk_qa` | `ZENDESK_QA_BASE_URL` *(url)*, `ZENDESK_QA_TOKEN` |
| TriNet Zenefits HR | `zenefits` | `ZENEFITS_BASE_URL` *(url)*, `ZENEFITS_TOKEN` |
| Zenfolio photography portfolio | `zenfolio` | `ZENFOLIO_BASE_URL` *(url)*, `ZENFOLIO_TOKEN` |
| Zenkit | `zenkit` | `ZENKIT_BASE_URL` *(url)*, `ZENKIT_TOKEN` |
| Zenoti spa/wellness | `zenoti` | `ZENOTI_BASE_URL` *(url)*, `ZENOTI_TOKEN` |
| Zen Planner | `zenplanner` | `ZENPLANNER_BASE_URL` *(url)*, `ZENPLANNER_TOKEN` |
| Zephyr Scale (SmartBear) REST API | `zephyr` | `ZEPHYR_BASE_URL` *(url)*, `ZEPHYR_TOKEN` |
| Zeplin REST API | `zeplin` | `ZEPLIN_BASE_URL` *(url)*, `ZEPLIN_TOKEN` |
| Zillow Group / Bridge Interactive | `zillow` | `ZILLOW_BASE_URL` *(url)*, `ZILLOW_TOKEN` |
| Zimperium Mobile Threat Defense | `zimperium` | `ZIMPERIUM_BASE_URL` *(url)*, `ZIMPERIUM_TOKEN` |
| Zingfit | `zingfit` | `ZINGFIT_BASE_URL` *(url)*, `ZINGFIT_TOKEN` |
| Zinier field service automation | `zinier` | `ZINIER_BASE_URL` *(url)*, `ZINIER_TOKEN` |
| Zip (Quadpay) merchant REST API | `zip_co` | `ZIP_CO_BASE_URL` *(url)*, `ZIP_CO_TOKEN` |
| Ziteboard whiteboard | `ziteboard` | `ZITEBOARD_BASE_URL` *(url)*, `ZITEBOARD_TOKEN` |
| Zocdoc partner REST API for appointment booking | `zocdoc` | `ZOCDOC_BASE_URL` *(url)*, `ZOCDOC_TOKEN` |
| Zoho CRM | `zoho` | `ZOHO_BASE_URL` *(url)*, `ZOHO_TOKEN` |
| Zoho Analytics | `zoho_analytics` | `ZOHO_ANALYTICS_BASE_URL` *(url)*, `ZOHO_ANALYTICS_TOKEN` |
| Zoho Books accounting | `zoho_books` | `ZOHO_BOOKS_BASE_URL` *(url)*, `ZOHO_BOOKS_TOKEN` |
| Zoho Cliq | `zoho_cliq` | `ZOHO_CLIQ_BASE_URL` *(url)*, `ZOHO_CLIQ_TOKEN` |
| Zoho Connect | `zoho_connect` | `ZOHO_CONNECT_BASE_URL` *(url)*, `ZOHO_CONNECT_TOKEN` |
| Zoho Creator | `zoho_creator` | `ZOHO_CREATOR_BASE_URL` *(url)*, `ZOHO_CREATOR_TOKEN` |
| Zoho Expense | `zoho_expense` | `ZOHO_EXPENSE_BASE_URL` *(url)*, `ZOHO_EXPENSE_TOKEN` |
| Zoho People HR | `zoho_people` | `ZOHO_PEOPLE_BASE_URL` *(url)*, `ZOHO_PEOPLE_TOKEN` |
| Zoho Projects | `zoho_projects` | `ZOHO_PROJECTS_BASE_URL` *(url)*, `ZOHO_PROJECTS_TOKEN` |
| Zoho Recruit ATS | `zoho_recruit` | `ZOHO_RECRUIT_BASE_URL` *(url)*, `ZOHO_RECRUIT_TOKEN` |
| Zoho Sign | `zoho_sign` | `ZOHO_SIGN_BASE_URL` *(url)*, `ZOHO_SIGN_TOKEN` |
| Zoho Survey | `zoho_survey` | `ZOHO_SURVEY_BASE_URL` *(url)*, `ZOHO_SURVEY_TOKEN` |
| Zoho Desk helpdesk | `zohodesk` | `ZOHODESK_BASE_URL` *(url)*, `ZOHODESK_TOKEN` |
| Zoko WhatsApp commerce messaging REST API | `zoko` | `ZOKO_BASE_URL` *(url)*, `ZOKO_TOKEN` |
| Zola Suite legal practice management | `zolasuite` | `ZOLASUITE_BASE_URL` *(url)*, `ZOLASUITE_TOKEN` |
| Zomato | `zomato` | `ZOMATO_BASE_URL` *(url)*, `ZOMATO_TOKEN` |
| Zonka Feedback | `zonka` | `ZONKA_BASE_URL` *(url)*, `ZONKA_TOKEN` |
| Zoom | `zoom` | `ZOOM_USER_ID` *(url)*, `ZOOM_OAUTH_TOKEN` |
| ZoomGrants grants management | `zoomgrants` | `ZOOMGRANTS_BASE_URL` *(url)*, `ZOOMGRANTS_TOKEN` |
| ZoomInfo | `zoominfo` | `ZOOMINFO_BASE_URL` *(url)*, `ZOOMINFO_TOKEN` |
| Zscaler | `zscaler` | `ZSCALER_BASE_URL` *(url)*, `ZSCALER_TOKEN` |
| Zulip | `zulip` | `ZULIP_BASE_URL` *(url)*, `ZULIP_TOKEN` |
| Zuora billing / revenue | `zuora` | `ZUORA_BASE_URL` *(url)*, `ZUORA_TOKEN` |
| Zywave insurance agency-management REST API | `zywave` | `ZYWAVE_BASE_URL` *(url)*, `ZYWAVE_TOKEN` |

Variables marked *(url)* are non-secret endpoints/identifiers; the rest are
secrets (tokens, keys, or `user:pass` for basic-auth connectors) and belong in
`.env`, never in `config.toml` or version control.

## Relational databases

The `database` tool connects to PostgreSQL, MySQL/MariaDB, SQL Server,
CockroachDB, Oracle, Amazon Redshift, and any other SQLAlchemy-supported
engine via a single `DATABASE_URL` (or a per-call `url`). Reads run; writes
(INSERT/UPDATE/DELETE/DDL) require `confirm=true`. Install the matching driver
(`psycopg`, `pymysql`, `pyodbc`, ...) for your database.

## Ambient-credential connectors

The `lambda`, `dynamodb`, `airtable`, `asana`, `clickup`, `vercel` and `gdrive`
connectors can use ambient host credentials and register only when
`MAVERICK_ENABLE_CRED_TOOLS=1` (or `[tools] credential_connectors` is enabled).
The `s3`, `ses` and `sns` descriptors register without that opt-in; their
credential and authorization checks still apply at use time. See
[env-vars.md](env-vars.md).

## Enterprise mode and the hand-written connectors

In Enterprise mode (the `enterprise` profile, or a compliance profile that
requires the egress lock such as HIPAA), a task run by a signed-in person or
agent cannot use operator-global environment credentials. The REST and GraphQL
connectors in `enterprise_connectors.py` honour that: they use only a saved
connection that admits the person (see **Connections** in the dashboard). The
hand-written connectors, such as `salesforce`, `servicenow`, `workday`, `sap`,
`msgraph`, `slack_bot`, `jira`, `confluence`, `notion`, `hubspot`, `snowflake`,
`gmail` and `stripe`, still read environment credentials directly, so in that
situation the registry refuses them with `REFUSED (credentials)`, even when a
saved connection of the same name exists. Tasks with no signed-in person, and
deployments outside Enterprise mode, are unaffected.

The dashboard **Tools** page marks every affected tool as "Not available in
Enterprise mode yet", so an administrator can see the list before rollout. The
list is the `AUTHENTICATED_AMBIENT_CRED_TOOL_NAMES` set in
`maverick/tools/__init__.py`; a connector leaves it once it resolves its
credentials from a principal-authorized saved connection.

## Don't see your system?

Most enterprise SaaS exposes a token-authed JSON REST or GraphQL API, which
means a new connector is usually a one-line spec in
`packages/maverick-core/maverick/tools/enterprise_connectors.py` — no new
module. Open a request or add the spec and it registers automatically.
