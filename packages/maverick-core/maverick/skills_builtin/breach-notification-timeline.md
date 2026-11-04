---
name: breach-notification-timeline
triggers:
  - who do we have to notify about this breach
  - 72 hour breach notification
  - map our breach reporting obligations
tools_needed:
  - knowledge_search
---
# What this skill does

Maps the notification obligations triggered by a confirmed or suspected data/security incident across the jurisdictions and regulatory regimes that apply. It produces a per-obligation timeline: who must be notified (regulator, data subjects, partners), the deadline clock and its trigger event, the threshold/exemptions, and the content required. Output is a sequenced obligation timeline to drive incident response — it does not decide that a breach is notifiable.

# Steps

1. Capture the incident facts that drive obligations: nature of the data and number of affected subjects, the subjects' locations/residency, the sectors and regimes in play (GDPR, US state breach laws, HIPAA, sectoral/financial, contractual), the role (controller vs processor), and the "aware" timestamp that starts the clock. State explicitly what is still unconfirmed.
2. Use `knowledge_search` against the internal incident-response plan, breach-notification matrix, prior incident records, and customer/processor contract terms (which often impose tighter notice windows than statute). Cite the source for each obligation; mark any obligation inferred without a primary source as "unverified — confirm with counsel".
3. For each applicable regime, record: trigger event, deadline (e.g. GDPR supervisory authority within 72 hours of awareness, plus affected-subject notice "without undue delay" if high risk; specific US state AG/resident timelines; HIPAA HHS/individual/media thresholds), the risk threshold or exemption (e.g. encryption safe-harbor), and required notification content. Distinguish a hard statutory clock from a contractual one.
4. Output a single timeline sorted by deadline, each row showing recipient, due date/time computed from the awareness timestamp, threshold, source, and status. Lead with the nearest deadline. Report assumptions and the unconfirmed facts that could add or remove obligations, and hand off to legal/privacy counsel to confirm notifiability and approve every notice before it is sent.

# Notes

The timeline is wrong if the clock starts from discovery date when the statute keys off "awareness" or "confirmation", if a contractual notice window (often 24-48h) is missed because only statutes were checked, or if a safe-harbor (encrypted data) is assumed without verifying the keys weren't also exposed. Common failure modes: missing every state where an affected resident lives, conflating processor and controller duties, and forgetting media/large-scale thresholds. Never send or auto-file a notification and never make the final call that an incident is or isn't notifiable — those are counsel decisions; this skill stages the schedule. Do not use it as the forensic root-cause analysis or as legal advice.
