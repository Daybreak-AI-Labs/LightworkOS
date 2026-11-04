---
name: event-schema-design
triggers:
  - event schema
  - message contract
  - kafka schema
tools_needed:
  - knowledge_search
---
# What this skill does

Designs the schema/contract for an event or message published to a stream or broker (Kafka, queue, pub/sub). Produces an event-schema design: the field set with types and semantics, envelope/metadata, a versioning scheme, and a compatibility policy (backward/forward) so producers and consumers can evolve independently without breaking in flight.

# Steps

1. Establish the event from the inputs: the business fact it records (past tense — `OrderPlaced`, not `PlaceOrder`), the producer, the known consumers, the topic, and the delivery guarantee (at-least-once vs exactly-once). Ground every field in a stated need; do not pad the payload with speculative fields.
2. Specify the payload and envelope: typed fields with units and nullability, plus envelope metadata (event_id, event_type, schema_version, occurred_at, producer, partition/correlation keys). Mark required vs optional and which field carries the partition key.
3. Pick the serialization and registry approach (Avro/Protobuf/JSON Schema), and use `knowledge_search` to confirm the registry's compatibility modes and the platform's conventions before committing; flag anything unverified.
4. Define the versioning and compatibility rules: additive-only with defaulted optional fields for backward compatibility, no field renumbering/retyping/removal once published, and how breaking changes are handled (new event type or major version + dual-publish migration).
5. Report the schema, envelope, partition-key choice, version policy, and a worked example of one safe additive change plus one breaking change handled correctly — with assumptions and unverified registry behaviors called out.

# Notes

The design is wrong if a "minor" change is actually breaking (removing/renaming/retyping a field, tightening a constraint, changing partition-key semantics), if the partition key doesn't preserve required ordering, or if optional fields lack defaults (forward-compat fails for old consumers). Once an event is published to real consumers the contract is effectively immutable — treat edits like the migration ratchet: additive only, breaking changes get a new version. This is a recommendation; rollout (dual-publish, consumer migration, deprecation) is staged for a human. Not for purely internal in-process function calls.
