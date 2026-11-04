"""Codec / codebook CLI commands: the emergent coordination shorthand.

Registered by importing this module at the end
of the package __init__ so the @main.command decorators fire on package import.
"""
from __future__ import annotations

import click

from . import main

# ``open_world`` is resolved lazily inside each command (via ``from . import
# open_world``) rather than bound at module import, so tests that monkeypatch
# ``maverick.cli.open_world`` still reach these commands.


@main.command("codebook")
@click.option("--limit", type=int, default=5000, help="Coordination messages to learn from.")
@click.option("--show", is_flag=True, help="Show the current codebook without relearning.")
@click.pass_context
def codebook(ctx, limit: int, show: bool) -> None:
    """Learn (or show) the swarm's coordination shorthand from its real messages.

    The Emergent Substrate: reads the coordination the agents have actually
    exchanged (goal_events) and learns short codes for the phrases they repeat --
    every code decodes EXACTLY back to English, so nothing is hidden from the
    Shield or a human. Reports the achievable compression. (Agents actively
    *speaking* the shorthand is a separate opt-in; this learns + inspects it.)
    """
    from ..emergent_protocol import compression_ratio, learn, shared
    from . import open_world
    store = shared()
    if show:
        book = store.book()
        click.echo(f"codebook: {book.size} codes")
    else:
        world = open_world(ctx.obj["db"])
        msgs = world.recent_event_contents(limit=limit)
        book = learn(msgs)
        store.update(book)
        ratio = compression_ratio(msgs, book)
        click.echo(f"learned {book.size} codes from {len(msgs)} messages "
                   f"({(1 - ratio) * 100:.0f}% smaller on this corpus)")
    for phrase, code in list(book.forward.items())[:10]:
        click.echo(f"  {code} = {phrase!r}")


@main.command("codec-probe")
@click.option("--limit", type=int, default=5000, help="Coordination messages to probe.")
@click.option("--encoding", default="cl100k_base", help="tiktoken encoding for the local proxy.")
@click.option("--model", default=None, help="Anthropic model for the EXACT count (needs API key).")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def codec_probe(ctx, limit: int, encoding: str, model: str | None, as_json: bool) -> None:
    """Measure whether the emergent codec saves TOKENS, not just bytes.

    The kill-switch experiment: bytes and frontier tokens do NOT move together,
    because the audit-safe sentinel codes can tokenize worse than the English they
    replace. Learns a codebook from real coordination (goal_events) and reports the
    byte delta beside the *token* delta -- and whether the compressed form actually
    costs fewer tokens. Pass --model (with an API key) for the exact Anthropic count;
    otherwise a local tiktoken proxy answers the directional question for free.
    """
    import json as _json

    from ..codec_probe import measure, resolve_counter
    from ..emergent_protocol import learn
    from . import open_world
    world = open_world(ctx.obj["db"])
    msgs = world.recent_event_contents(limit=limit)
    if not msgs:
        click.echo("no coordination messages to probe")
        return
    book = learn(msgs)
    try:
        counter = resolve_counter(encoding=encoding, model=model)
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e
    delta = measure(msgs, book, count_tokens=counter)
    d = delta.to_dict()
    if as_json:
        click.echo(_json.dumps(d, indent=2))
        return
    click.echo(f"probed {d['n_messages']} messages, {book.size} codes")
    click.echo(f"  bytes : {d['byte_savings_pct']:+.1f}%")
    verdict = "SAVES tokens" if d["pays_off"] else "COSTS MORE tokens"
    click.echo(f"  tokens: {d['token_savings_pct']:+.1f}%   -> {verdict}")
    be = d["breakeven_messages"]
    click.echo(f"  read-coded: {d['codebook_tokens']} tokens to carry the codebook; "
               + (f"break-even after {be:.0f} reuses" if be != float("inf")
                  else "NEVER breaks even (no per-message token saving)"))


@main.command("codec-learn")
@click.option("--limit", type=int, default=5000, help="Coordination messages to learn from.")
@click.option("--encoding", default="cl100k_base", help="tiktoken encoding for the local proxy.")
@click.option("--model", default=None, help="Anthropic model for the EXACT count (needs API key).")
@click.pass_context
def codec_learn(ctx, limit: int, encoding: str, model: str | None) -> None:
    """Learn the token-aware codebook from real coordination and persist it.

    This is the codec that actually saves frontier tokens (byte-stuffed ~2-token
    codes), not just bytes. Picks token-cheap, collision-safe codes from the
    target tokenizer, learns the swarm's repeated phrases from goal_events, and
    saves the codebook for the live blackboard to measure against. Reports the
    token savings on the historical corpus -- the authoritative, cross-process
    number (the live blackboard telemetry confirms it during an actual run).
    """
    from .. import emergent_tokens as et
    from ..codec_probe import resolve_counter
    from . import open_world
    world = open_world(ctx.obj["db"])
    msgs = world.recent_event_contents(limit=limit)
    if not msgs:
        click.echo("no coordination messages to learn from")
        return
    try:
        counter = resolve_counter(encoding=encoding, model=model)
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e
    learned = et.learn_from_messages(msgs, count_tokens=counter)
    if learned is None:
        click.echo("no token-cheap markers available for this tokenizer; codec would not help")
        return
    book, saved = learned
    click.echo(f"learned {book.size} token-aware codes from {len(msgs)} messages")
    click.echo(f"  estimated token savings on this corpus: {saved:+.1f}%")
    click.echo("  enable [emergent_codec] to measure it live on the coordination stream")
