# Dashboard conversation and event reads

The chat sidebar calls `conversation_summaries`, which filters root goals and
the current owner before applying the limit. A root remains visible when it
has many newer child goals. Results are ordered by root creation ID, newest
first; updating an old conversation does not reorder it. `before_id` provides
stable keyset paging. Only title, status, owner, update time and ID are selected;
only the visible titles are decrypted. Goal detail reads retain full bodies.

SQLite and PostgreSQL (schema 37 and later) use partial root indexes. PostgreSQL preserves
its configured tenant predicate and transaction/RLS policy. These read projections
do not change goal ownership or execution authority.

The legacy chat and versioned API goal SSE endpoints share one durable replay
state machine. Their existing wire formats remain distinct: chat receives event
batches and a terminal result, while the versioned API receives individual event
frames and an end marker. Both honor Last-Event-ID, drain complete terminal
backlogs, check visibility before reading event bodies, and read SQLite/PostgreSQL
off the event loop. Idle reads use only status/owner/ID; legacy result data is
loaded when a batch or terminal frame needs it.

Heartbeat deadlines use monotonic elapsed time, independently of polling backoff.
The default cadence is 30 seconds, with polling intervals of 0.5 to 5 seconds and a 300-second
stream lifetime. Flow SSE uses the same cadence and lease cleanup, with its
checkpoint recovery errors preserved. A disconnected client stops polling, and
both generator and ASGI response cleanup release the shared stream slot exactly
once, including cancellation before the iterator starts.

The stream is pull-based: a slow consumer cannot create an unbounded prefetch
queue. There is no process-local fanout cache; durable event IDs remain replay
authority across worker/dashboard processes. Slow database calls or blocked
network sends can delay delivery, so virtual-clock tests establish scheduler
correctness, not a production proxy/network latency guarantee.
