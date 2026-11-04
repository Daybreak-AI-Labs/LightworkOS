/**
 * Lightwork BYOA gateway — the "report-after" half for Salesforce
 * Agentforce.
 *
 * Companion to LightworkGateway.cls (Apex allows one @InvocableMethod per
 * class, so the two agent actions are two classes sharing one HTTP layer).
 * The agent calls "Lightwork: Report Run" exactly once when a job
 * completes; the run lands on the Lightwork Operating Record as a
 * first-class goal owned by agent:<id>, metered against the enrolled
 * budget ceiling.
 *
 * Pass a stable idempotencyKey per logical run: a retried report returns
 * the original record instead of double-counting spend.
 */
public with sharing class LightworkReportRun {

    public class ReportRequest {
        @InvocableVariable(
            label='Title'
            description='Short title for the completed run'
            required=true)
        public String title;

        @InvocableVariable(
            label='Outcome'
            description='success or failure'
            required=true)
        public String outcome;

        @InvocableVariable(
            label='Cost (dollars)'
            description='Total spend for the run in USD; metered against the enrolled budget ceiling')
        public Decimal costDollars;

        @InvocableVariable(
            label='Idempotency key'
            description='Stable key per logical run (max 128 chars); retries return the original record instead of double-counting')
        public String idempotencyKey;
    }

    public class ReportResult {
        @InvocableVariable(
            label='OK'
            description='True when the run was recorded')
        public Boolean ok;

        @InvocableVariable(
            label='Goal Id'
            description='Operating Record goal created for this run')
        public Integer goalId;

        @InvocableVariable(
            label='Over budget'
            description='True once cumulative reported spend crossed the enrolled ceiling — further actions will be denied at screen time')
        public Boolean overBudget;

        @InvocableVariable(
            label='Error message'
            description='Readable HTTP/callout error when the report failed (ok = false)')
        public String errorMessage;
    }

    @InvocableMethod(
        label='Lightwork: Report Run'
        description='Report a completed run to Lightwork so it lands on the Operating Record with its cost. Call once per job, with a stable idempotency key.'
        callout=true)
    public static List<ReportResult> report(List<ReportRequest> requests) {
        List<ReportResult> results = new List<ReportResult>();
        for (ReportRequest request : requests) {
            results.add(reportOne(request));
        }
        return results;
    }

    private static ReportResult reportOne(ReportRequest request) {
        ReportResult result = new ReportResult();
        result.ok = false;

        JSONGenerator gen = JSON.createGenerator(false);
        gen.writeStartObject();
        gen.writeStringField('title', request.title == null ? '' : request.title);
        gen.writeStringField('outcome',
            String.isBlank(request.outcome)
                ? 'success' : request.outcome.trim().toLowerCase());
        gen.writeNumberField('cost_dollars',
            request.costDollars == null ? 0 : request.costDollars);
        if (String.isNotBlank(request.idempotencyKey)) {
            gen.writeStringField('idempotency_key', request.idempotencyKey);
        }
        gen.writeEndObject();

        try {
            HttpResponse response =
                LightworkGateway.post('/api/v1/external/runs', gen.getAsString());
            if (response.getStatusCode() != 201) {
                result.errorMessage = LightworkGateway.readableHttpError(response);
                return result;
            }
            Map<String, Object> body =
                (Map<String, Object>) JSON.deserializeUntyped(response.getBody());
            result.ok = LightworkGateway.asBoolean(body.get('ok'));
            result.goalId = LightworkGateway.asInteger(body.get('goal_id'));
            result.overBudget = LightworkGateway.asBoolean(body.get('over_budget'));
        } catch (Exception e) {
            result.errorMessage = 'Lightwork gateway callout failed: ' + e.getMessage();
        }
        return result;
    }
}
