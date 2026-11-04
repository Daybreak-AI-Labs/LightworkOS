"""Reviewed, data-preserving PostgreSQL learning-key migration.

The same transaction-scoped statements serve WorldModel v39 and standalone
learning-store initialization. No existing table, row or policy is replaced.
"""
from __future__ import annotations

LEARNING_SCHEMA_LOCK = 0x6D766B6C7363


class LearningSchemaError(RuntimeError):
    """Schema refusal must never be interpreted as an empty learning store."""

PG_BOOTSTRAP = [
    "CREATE TABLE IF NOT EXISTS harness_addenda ("
    " key TEXT PRIMARY KEY, block TEXT NOT NULL, updated_at DOUBLE PRECISION NOT NULL)",
    "CREATE TABLE IF NOT EXISTS harness_line_meta ("
    " line_id TEXT PRIMARY KEY, record TEXT NOT NULL, updated_at DOUBLE PRECISION NOT NULL)",
    "CREATE TABLE IF NOT EXISTS harness_transfer_tried ("
    " line_id TEXT PRIMARY KEY, ts DOUBLE PRECISION NOT NULL)",
    "CREATE TABLE IF NOT EXISTS harness_corpus ("
    " kind TEXT NOT NULL, key TEXT NOT NULL, seq INTEGER NOT NULL,"
    " row TEXT NOT NULL, PRIMARY KEY (kind, key, seq))",
]

LEARNING_TENANT_MIGRATION = [
    f"SELECT pg_advisory_xact_lock({LEARNING_SCHEMA_LOCK})",
    *[f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS tenant_id TEXT" for table in (
        "harness_addenda", "harness_line_meta", "harness_transfer_tried", "harness_corpus",
    )],
    """
DO $learning_keys$
DECLARE
    spec record;
    rel oid;
    schema_name text;
    old_key record;
    expected smallint[];
    tenant_att smallint;
    index_name text;
    index_oid oid;
    key_sql text;
    predicate text;
    scoped boolean;
    has_legacy boolean;
BEGIN
    FOR spec IN SELECT * FROM (VALUES
        ('harness_addenda', ARRAY['key']),
        ('harness_line_meta', ARRAY['line_id']),
        ('harness_transfer_tried', ARRAY['line_id']),
        ('harness_corpus', ARRAY['kind', 'key', 'seq'])
    ) AS tables(table_name, natural_keys)
    LOOP
        rel := to_regclass(spec.table_name);
        SELECT n.nspname INTO schema_name FROM pg_class c
          JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE c.oid=rel AND c.relkind='r';
        IF schema_name IS NULL THEN
            RAISE EXCEPTION 'learning-key upgrade refused: unsupported table layout for %', spec.table_name;
        END IF;
        EXECUTE format('LOCK TABLE %I.%I IN ACCESS EXCLUSIVE MODE', schema_name, spec.table_name);
        SELECT array_agg(a.attnum::smallint ORDER BY k.ord),
               string_agg(format('%I', a.attname), ', ' ORDER BY k.ord)
          INTO expected, key_sql
          FROM unnest(spec.natural_keys) WITH ORDINALITY AS k(name, ord)
          JOIN pg_attribute a ON a.attrelid=rel AND a.attname=k.name
          AND NOT a.attisdropped AND a.attnotnull;
        SELECT attnum INTO tenant_att FROM pg_attribute
          WHERE attrelid=rel AND attname='tenant_id' AND atttypid='text'::regtype
            AND NOT attisdropped AND NOT attnotnull;
        IF cardinality(expected) IS DISTINCT FROM cardinality(spec.natural_keys) OR tenant_att IS NULL THEN
            RAISE EXCEPTION 'learning-key upgrade refused: unexpected columns for %', spec.table_name;
        END IF;
        SELECT conname, conkey, conindid, condeferrable, convalidated INTO old_key
          FROM pg_constraint WHERE conrelid=rel AND contype='p';
        has_legacy := FOUND;
        IF NOT has_legacy AND (
            to_regclass(format('%I.%I', schema_name, 'uq_'||spec.table_name||'_tenant')) IS NULL OR
            to_regclass(format('%I.%I', schema_name, 'uq_'||spec.table_name||'_unbound')) IS NULL
        ) THEN
            RAISE EXCEPTION 'learning-key upgrade refused: missing recognized key layout for %', spec.table_name;
        END IF;
        IF has_legacy AND (old_key.conkey IS DISTINCT FROM expected OR old_key.condeferrable OR NOT old_key.convalidated) THEN
            RAISE EXCEPTION 'learning-key upgrade refused: unexpected primary key for %', spec.table_name;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_constraint WHERE confrelid=rel AND contype='f') THEN
            RAISE EXCEPTION 'learning-key upgrade refused: foreign-key dependencies on % require operator review', spec.table_name;
        END IF;
        IF EXISTS (
            SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
            WHERE i.indrelid=rel AND i.indisunique
            AND (NOT has_legacy OR i.indexrelid<>old_key.conindid)
            AND c.relname NOT IN ('uq_'||spec.table_name||'_tenant', 'uq_'||spec.table_name||'_unbound')
        ) THEN
            RAISE EXCEPTION 'learning-key upgrade refused: unexpected unique index on %', spec.table_name;
        END IF;
        FOREACH scoped IN ARRAY ARRAY[true, false]
        LOOP
            index_name := 'uq_'||spec.table_name||CASE WHEN scoped THEN '_tenant' ELSE '_unbound' END;
            predicate := CASE WHEN scoped THEN '(tenant_id IS NOT NULL)' ELSE '(tenant_id IS NULL)' END;
            EXECUTE format('CREATE UNIQUE INDEX IF NOT EXISTS %I ON %I.%I (%s%s) WHERE %s',
                index_name, schema_name, spec.table_name,
                CASE WHEN scoped THEN 'tenant_id, ' ELSE '' END, key_sql, predicate);
            index_oid := to_regclass(format('%I.%I', schema_name, index_name));
            IF NOT EXISTS (
                SELECT 1 FROM pg_index i
                WHERE i.indexrelid=index_oid AND i.indrelid=rel AND i.indisunique AND i.indisvalid AND i.indisready
                  AND i.indexprs IS NULL AND NOT i.indisexclusion
                  AND i.indnatts=i.indnkeyatts
                  AND (SELECT array_agg(v::smallint ORDER BY n) FROM unnest(i.indkey) WITH ORDINALITY x(v,n))
                    = CASE WHEN scoped THEN ARRAY[tenant_att]||expected ELSE expected END
                  AND pg_get_expr(i.indpred, i.indrelid)=predicate
                  AND NOT EXISTS (SELECT 1 FROM unnest(i.indoption) AS opts(v) WHERE v<>0)
                  AND NOT EXISTS (SELECT 1 FROM unnest(i.indclass) AS classes(v)
                       JOIN pg_opclass o ON o.oid=classes.v JOIN pg_am a ON a.oid=o.opcmethod
                       WHERE NOT o.opcdefault OR a.amname<>'btree')
                  AND (SELECT array_agg(a.attcollation ORDER BY x.n)
                       FROM unnest(i.indkey) WITH ORDINALITY x(v,n)
                       JOIN pg_attribute a ON a.attrelid=rel AND a.attnum=x.v)
                    = (SELECT array_agg(v ORDER BY n) FROM unnest(i.indcollation) WITH ORDINALITY x(v,n))
            ) THEN
                RAISE EXCEPTION 'learning-key upgrade refused: unexpected tenant index on %', spec.table_name;
            END IF;
        END LOOP;
        IF has_legacy THEN
            EXECUTE format('ALTER TABLE %I.%I DROP CONSTRAINT %I', schema_name, spec.table_name, old_key.conname);
        END IF;
    END LOOP;
END;
$learning_keys$
""",
]


def ensure_schema(cursor) -> None:
    """Caller owns the transaction; any failure rolls back every table change."""
    try:
        cursor.execute(LEARNING_TENANT_MIGRATION[0])
        for statement in PG_BOOTSTRAP:
            cursor.execute(statement)
        for statement in LEARNING_TENANT_MIGRATION[1:]:
            cursor.execute(statement)
    except Exception as error:
        if getattr(error, "outcome_unknown", False):
            raise
        # Do not include driver diagnostics: uniqueness failures can quote row
        # values. The reason is sufficient to direct safe operator inspection.
        reason = {"23505": "duplicate keys", "42501": "schema privileges",
                  "P0001": "unexpected constraints or dependencies"}.get(getattr(error, "sqlstate", None), "schema verification")
        raise LearningSchemaError(
            f"learning-key upgrade refused: {reason}; review learning-store-tenant-keys.md before retrying"
        ) from None
