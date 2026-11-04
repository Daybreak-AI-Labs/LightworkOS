/**
 * Lightwork BYOA gateway — the "screen" half of screen-then-act for
 * Salesforce Agentforce.
 *
 * Exposes one invocable screen action (Apex allows a single
 * @InvocableMethod per class; the run-report action lives in
 * LightworkReportRun.cls and reuses the shared plumbing here). The agent
 * calls "Lightwork: Screen Action" BEFORE any consequential action and
 * proceeds only on allowed = true; requiresApproval = true means a human
 * decision is parked in the Lightwork approval queue under approvalId.
 *
 * All callouts go through the Named Credential "Lightwork_Gateway"
 * (see README.md for the exact Setup clicks). The per-agent rest bearer
 * lives on the External Credential as a custom Authorization header —
 * it never appears in Apex, debug logs, or version control.
 *
 * Endpoint contract: GET /api/v1/external/openapi.json on your Lightwork
 * deployment (the importable gateway description).
 */
public with sharing class LightworkGateway {

    // Must match the Named Credential API name created in Setup.
    private static final String NAMED_CREDENTIAL = 'Lightwork_Gateway';
    private static final Integer TIMEOUT_MS = 30000;

    public class ScreenRequest {
        @InvocableVariable(
            label='Tool'
            description='Action/tool name to screen (e.g. send_email)'
            required=true)
        public String tool;

        @InvocableVariable(
            label='Detail'
            description='One line describing what will be done')
        public String detail;

        @InvocableVariable(
            label='Risk'
            description='low, medium, or high (defaults to low)')
        public String risk;
    }

    public class ScreenResult {
        @InvocableVariable(
            label='Allowed'
            description='Proceed only when true')
        public Boolean allowed;

        @InvocableVariable(
            label='Rule'
            description='Gateway rule behind the decision (allow, capability, budget, approval_required, ...); transport_error when the callout itself failed')
        public String rule;

        @InvocableVariable(
            label='Reason'
            description='Human-readable explanation — on HTTP/callout failure this carries the readable error message')
        public String reason;

        @InvocableVariable(
            label='Requires approval'
            description='True when the action parked a human approval; poll until it is decided')
        public Boolean requiresApproval;

        @InvocableVariable(
            label='Approval Id'
            description='Approval row to poll at GET /api/v1/external/approvals/{id} when requiresApproval is true')
        public Integer approvalId;
    }

    @InvocableMethod(
        label='Lightwork: Screen Action'
        description='Ask Lightwork before acting: applies the enrolled tool/risk/budget ceilings, Shield input scan, and the human-approval floor. Proceed only on allowed = true.'
        callout=true)
    public static List<ScreenResult> screen(List<ScreenRequest> requests) {
        List<ScreenResult> results = new List<ScreenResult>();
        for (ScreenRequest request : requests) {
            results.add(screenOne(request));
        }
        return results;
    }

    private static ScreenResult screenOne(ScreenRequest request) {
        ScreenResult result = new ScreenResult();
        result.allowed = false; // fail closed until the gateway says otherwise
        result.requiresApproval = false;

        JSONGenerator gen = JSON.createGenerator(false);
        gen.writeStartObject();
        gen.writeStringField('tool', request.tool == null ? '' : request.tool);
        gen.writeStringField('detail', request.detail == null ? '' : request.detail);
        gen.writeStringField('risk',
            String.isBlank(request.risk) ? 'low' : request.risk.trim().toLowerCase());
        gen.writeEndObject();

        try {
            HttpResponse response = post('/api/v1/external/screen', gen.getAsString());
            if (response.getStatusCode() != 200) {
                result.rule = 'transport_error';
                result.reason = readableHttpError(response);
                return result;
            }
            Map<String, Object> body =
                (Map<String, Object>) JSON.deserializeUntyped(response.getBody());
            result.allowed = asBoolean(body.get('allowed'));
            result.rule = asString(body.get('rule'));
            result.reason = asString(body.get('reason'));
            result.requiresApproval = asBoolean(body.get('requires_approval'));
            result.approvalId = asInteger(body.get('approval_id'));
        } catch (Exception e) {
            // Stay fail-closed: a callout failure is never an implicit allow.
            result.rule = 'transport_error';
            result.reason = 'Lightwork gateway callout failed: ' + e.getMessage();
        }
        return result;
    }

    // ---- shared plumbing (also used by LightworkReportRun) -----------------

    public static HttpResponse post(String path, String jsonBody) {
        HttpRequest request = new HttpRequest();
        request.setEndpoint('callout:' + NAMED_CREDENTIAL + path);
        request.setMethod('POST');
        request.setHeader('Content-Type', 'application/json');
        request.setTimeout(TIMEOUT_MS);
        request.setBody(jsonBody);
        return new Http().send(request);
    }

    public static String readableHttpError(HttpResponse response) {
        Integer code = response.getStatusCode();
        String detail = '';
        try {
            Object parsed = JSON.deserializeUntyped(response.getBody());
            if (parsed instanceof Map<String, Object>) {
                detail = asString(((Map<String, Object>) parsed).get('detail'));
            }
        } catch (Exception ignored) {
            // Non-JSON error body; fall through to the status line.
        }
        if (String.isBlank(detail)) {
            detail = response.getStatus();
        }
        String hint = '';
        if (code == 401) {
            hint = ' (rest bearer missing, rotated, or revoked — mint a new credential on /external-agents and update the External Credential header)';
        } else if (code == 403) {
            hint = ' (the agent hit a governance refusal)';
        } else if (code == 404) {
            hint = ' (the external-agents plane is off — enable [external_agents] on the Lightwork deployment)';
        } else if (code == 429) {
            hint = ' (per-agent rate limit — honor Retry-After and retry)';
        }
        return 'Lightwork gateway returned HTTP ' + code + ': ' + detail + hint;
    }

    public static String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    public static Boolean asBoolean(Object value) {
        return (value instanceof Boolean) && (Boolean) value;
    }

    public static Integer asInteger(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Integer) {
            return (Integer) value;
        }
        if (value instanceof Long) {
            return ((Long) value).intValue();
        }
        if (value instanceof Double) {
            return ((Double) value).intValue();
        }
        if (value instanceof Decimal) {
            return ((Decimal) value).intValue();
        }
        try {
            return Integer.valueOf(String.valueOf(value));
        } catch (Exception e) {
            return null;
        }
    }
}
