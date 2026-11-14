"""Built-in fallback prompt-injection rules.

When the ``agent-shield`` SDK isn't installed -- which is every environment we
ship, since it is not on PyPI and not vendored -- we still want *some* safety,
not a wide-open no-op. This module is therefore the backend that actually runs;
its measured accuracy is in ``benchmarks/security/RESULTS.md`` (F1 0.821-0.900).
This
module provides a small but real set of regex rules covering the
highest-impact attack categories from the agent-shield README:

  - prompt injection / instruction hijacking (ignore-previous, override-system)
  - role hijacking (DAN, developer mode, jailbreak templates)
  - data exfiltration markers (markdown image leaks, base64 url params)
  - tool-abuse markers (rm -rf, /etc/passwd, .env exfil)

The full agent-shield SDK detects ~115 patterns; this fallback covers
~20 of the most common ones. Good enough to block the obvious attacks;
weak against sophisticated obfuscation (homoglyphs, base64-wrapped
payloads, etc.). The installer's smoke test makes this gap visible to
users via the "agent-shield not installed" warning.
"""
from __future__ import annotations

import base64
import html
import os
import re
import unicodedata
from dataclasses import dataclass


def _max_scan_chars() -> int:
    """Upper bound on the input length scan() de-obfuscates + regex-matches.

    scan() builds ~6 full-size de-obfuscated variants of the input (NFKC,
    invisible-strip/space-sub, casefold, homoglyph-fold, shell-deobfuscate) and
    runs ~40 regexes over each, so cost is linear in input length. The MCP HTTP
    transport accepts a 2 MB body and feeds it straight in: ~2.7s of CPU per
    scan, a linear-amplification DoS at the default 600 req/min. Treat inputs
    above this operator-tunable ceiling as unsafe instead of scanning only a
    prefix; otherwise malicious content in an unscanned suffix could bypass the
    fallback shield while still reaching downstream agents.
    """
    raw = os.environ.get("MAVERICK_SHIELD_MAX_SCAN_CHARS")
    if not raw:
        try:  # ``[safety] max_scan_chars`` when the kernel is installed
            from maverick.env_setting import env_or_config

            raw = env_or_config("MAVERICK_SHIELD_MAX_SCAN_CHARS", "safety", "max_scan_chars")
        except ImportError:  # pragma: no cover -- standalone shield package
            raw = None
    if raw:
        try:
            parsed = int(raw)
            if parsed > 0:
                return parsed
        except ValueError:
            pass
    return 262_144


@dataclass
class Rule:
    name: str
    severity: str           # "low" | "medium" | "high" | "critical"
    pattern: re.Pattern
    description: str


def _compile(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


# Split-flag hardening: `rm_rf_root` and `recursive_chmod_chown_root` below
# must not require their two dangerous flags (recursive + force, or recursive
# alone) in ONE contiguous token (`-rf`, `-...R...`). Splitting the flags
# across separate tokens -- `rm -r -f /`, `chmod -c -R 777 /` -- is
# functionally identical, and a single-token match would miss it. `_FLAG_TOKEN`
# matches one short-option cluster (`-rf`, `-c`) or one GNU long option
# (`--recursive`); the rules below use it, bounded to a handful of
# repetitions (never unbounded, so this can't blow up on adversarial input),
# to detect the two flags regardless of how they're grouped or ordered.
# A bare ``--`` (end of options) is a token too: ``rm -rf -- /`` is the same
# command.
_FLAG_TOKEN = r"(?:-[a-zA-Z]+|--[a-zA-Z][a-zA-Z-]*|--)"


def _has_flag(letter: str, long_name: str) -> str:
    """A flag-token alternative matching a short cluster containing
    ``letter`` (any position, case-insensitive via the module's IGNORECASE
    compile flag) or the GNU long option ``--<long_name>``."""
    return rf"(?:-[a-zA-Z]*{letter}[a-zA-Z]*\b|--{long_name}\b)"


# --- de-obfuscation pre-pass -----------------------------------------------
# The regex rules below only match literal text. A trivial obfuscation
# (fullwidth chars, a zero-width space mid-word, a Cyrillic look-alike, a
# base64-wrapped payload, or a quoted/`$IFS`-split shell command) slips
# straight past them. Before scanning we therefore derive a set of
# normalised/decoded CANDIDATE strings and run every rule over all of them,
# so a match in any variant counts. This converts the fallback from
# "stops only a verbatim copy-paste" to "stops the common encodings too".

# Zero-width spaces/joiners, bidi controls, BOM, and the Unicode tag block
# (steganographic invisible chars), plus the soft hyphen, combining grapheme
# joiner, Mongolian vowel separator, Hangul fillers and variation selectors,
# which render as nothing inside a word ("ig\u00adnore").
_INVISIBLE = re.compile(
    r"[\u00ad\u034f\u115f\u1160\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f"
    r"\u3164\ufe00-\ufe0f\uffa0\ufeff]|[\U000E0000-\U000E007F]|[\U000E0100-\U000E01EF]"
)

# Common confusable code points folded to their ASCII look-alike. Covers the
# Cyrillic/Greek homoglyphs used to spell "ignore", "system", etc.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ԁ": "d", "ո": "n", "ⅼ": "l", "ӏ": "l", "ʟ": "l",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ϲ": "c", "ѐ": "e", "ƽ": "s",
    "ɡ": "g", "ⅰ": "i", "ｉ": "i", "ι": "i",
})

# ``\\xHH`` escapes written inline ("\\x69\\x67nore all previous ...").
_INLINE_HEX = re.compile(r"\\x([0-9a-fA-F]{2})")


def _strip_combining(text: str) -> str:
    """Drop combining marks ("ignóre" -> "ignore"); ASCII text is unchanged."""
    if text.isascii():
        return text
    decomposed = unicodedata.normalize("NFD", text)
    return unicodedata.normalize(
        "NFC", "".join(c for c in decomposed if not unicodedata.combining(c)))


def _unescape_inline(text: str) -> str:
    """Decode HTML entities and inline ``\\xHH`` escapes in place, so a keyword
    spelled ``ignore&#32;all`` or ``\x69gnore`` reads as the plain words."""
    if "&" in text:
        text = html.unescape(text)
    if "\\x" in text:
        text = _INLINE_HEX.sub(lambda m: chr(int(m.group(1), 16)), text)
    return text

# A base64-shaped run long enough to carry a payload (but not so short it
# matches every hex id). Decoded and re-scanned.
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

# Cap how much work the pre-pass does on hostile input (the scanner runs on
# untrusted text; keep it linear and bounded).
_MAX_B64_BLOBS = 20
_MAX_B64_WINDOWS_PER_BLOB = 20

# Decode base64 in bounded, overlapping windows. A window is capped so a
# hostile blob cannot create one giant re-scan candidate, but windows continue
# across the full blob so padding cannot hide an instruction after the prefix.
# 8 KiB of base64 -> ~6 KiB of decoded text.
_MAX_B64_DECODE_CHARS = 8192
_B64_DECODE_STEP_CHARS = _MAX_B64_DECODE_CHARS // 2


def _strip_invisible(text: str) -> str:
    return _INVISIBLE.sub("", text)


def _shell_deobfuscate(text: str) -> str:
    """Neutralise common shell-quoting evasions so the tool-abuse rules still
    match: ``rm -rf "/"`` / ``rm -rf $IFS/`` / ``r\\m -rf /`` all canonicalise
    to ``rm -rf /``. Only used to build an extra candidate, so over-stripping
    can't corrupt the original text the other rules see."""
    text = text.replace("${IFS}", " ").replace("$IFS", " ")
    text = text.replace("\\", "")          # drop backslash escapes
    text = re.sub(r"['\"`]", "", text)      # drop quotes/backticks
    return re.sub(r"[ \t]{2,}", " ", text)


def _decode_b64_blobs(text: str) -> list[str]:
    out: list[str] = []
    # Bound TOTAL decode work, not the count of text-yielding blobs. The old
    # `useful_blobs >= _MAX_B64_BLOBS` break was order-dependent: an attacker
    # could prepend 20+ short benign base64 tokens that each decode to text,
    # exhausting the budget before finditer reached the real payload blob -- so
    # the payload was never decoded and the attack bypassed every rule. A global
    # window budget keeps the pre-pass linear while letting later blobs still be
    # reached, and we always grant each blob its first phase-0 window so a
    # trailing payload is never starved by benign decoys preceding it.
    total_windows = 0
    max_total_windows = _MAX_B64_BLOBS * _MAX_B64_WINDOWS_PER_BLOB
    for m in _B64_BLOB.finditer(text):
        # Decode bounded, overlapping windows across the whole blob. Decoding
        # only the leading slice let attackers prepend benign bytes and hide a
        # malicious instruction later in the same regex match. Keep the window
        # and step 4-byte aligned so each base64 chunk is self-contained.
        blob = m.group(0)
        window = _MAX_B64_DECODE_CHARS & ~3
        step = _B64_DECODE_STEP_CHARS & ~3
        windows_used = 0
        # Try all 4 phase alignments. _B64_BLOB greedily grabs any leading
        # base64-alphabet chars, so an attacker can prepend 1-3 filler chars
        # ("ABCignore..." base64'd) -- that shifts every 4-byte boundary and the
        # real payload decodes to garbage, silently defeating this defense.
        # Decoding from each of the 4 offsets re-aligns one of them. The window
        # budget is shared across phases so the pre-pass stays bounded/linear.
        for phase in range(4):
            if windows_used >= _MAX_B64_WINDOWS_PER_BLOB:
                break
            shifted = blob[phase:]
            starts = range(0, len(shifted), step) if step else (0,)
            for i, start in enumerate(starts):
                if windows_used >= _MAX_B64_WINDOWS_PER_BLOB:
                    break
                # Always decode each blob's very first window (phase 0, start 0)
                # even after the global budget is spent, so a trailing payload
                # blob is still scanned no matter how many benign decoys precede
                # it. All other windows draw from the shared global budget.
                is_first_window = phase == 0 and i == 0
                if not is_first_window and total_windows >= max_total_windows:
                    break
                windows_used += 1
                total_windows += 1
                chunk = shifted[start:start + window]
                if not chunk:
                    continue
                try:
                    raw = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=False)
                    decoded = raw.decode("utf-8", errors="ignore")
                except (ValueError, UnicodeDecodeError):
                    continue
                # Only keep decodes that look like text (the attack is in words).
                if decoded and any(c.isalpha() for c in decoded):
                    out.append(decoded)
    return out


def _candidates(text: str) -> list[str]:
    """Return the set of strings to scan: the original plus de-obfuscated and
    base64-decoded variants. NFKC folds fullwidth/compatibility forms.

    Invisible chars are handled BOTH ways: stripped (joiner-inside-a-word
    evasion, ``ig​nore``) AND space-substituted (invisible-as-separator
    evasion, ``ignore​all​previous`` -- deletion would collapse it to
    ``ignoreallprevious`` and the ``\\s+`` rules would miss). Homoglyphs are
    folded after a ``casefold()`` so an upper/mixed-case confusable (Cyrillic
    capital ``І`` -> ``і``) maps onto the lowercase confusable table;
    rules are IGNORECASE so the extra lowercasing is safe."""
    norm0 = unicodedata.normalize("NFKC", _unescape_inline(text))
    cands = {text}
    # strip vs space-substitute invisibles; original-case vs casefolded.
    for base in (_strip_combining(_strip_invisible(norm0)), _INVISIBLE.sub(" ", norm0)):
        for variant in (base, base.casefold()):
            folded = variant.translate(_HOMOGLYPHS)
            cands.add(folded)
            cands.add(_shell_deobfuscate(folded))
    for decoded in _decode_b64_blobs(text):
        cands.add(decoded)
        decoded_norm = unicodedata.normalize("NFKC", decoded)
        cands.add(decoded_norm)
        # A base64-wrapped command can still hide behind shell quoting/concat
        # (e.g. rm -rf "$HOME"/). Apply the same deobfuscation to decoded blobs
        # so rules like rm_rf_root fire on the unwrapped form.
        cands.add(_shell_deobfuscate(decoded_norm))
    return [c for c in cands if c]


# Severity guidance:
#   low      -> notice; never blocks at any profile
#   medium   -> blocks at 'strict' (threshold='medium')
#   high     -> blocks at 'balanced' (threshold='high') and stricter
#   critical -> blocks at all enforcing profiles (incl. 'permissive')
RULES: list[Rule] = [
    # Prompt injection / override
    # Anchor directional/context overrides to the conversation. Ordinary
    # edits such as "ignore everything above row 10" must remain allowed.
    Rule("discard_conversation", "high",
         _compile(
             r"\b(?:ignore|disregard|forget|discard)\s+"
             r"(?:everything|all(?:\s+(?:the\s+)?(?:text|content|instructions?))?)\s+"
             r"(?:above|before)(?:\s+(?:this|my|the)\s+(?:line|message|request|prompt))?"
             r"\s*(?=[,.;:!?\n\u2014\u2013]|$|(?:and|then|now|instead)\b)"),
         "Instruction override: discard the preceding conversation"),
    Rule("configured_directives_leak", "medium",
         _compile(
             r"\b(?:paste|show|print|repeat|output|quote|dump|share|reveal)\s+"
             r"(?:back\s+)?(?:me\s+)?(?:the\s+|your\s+)?"
             r"(?:directives?|instructions?|rules?|prompt|guidance)\s+"
             r"(?:that\s+)?you\s+were\s+(?:configured|initiali[sz]ed|set\s+up)\s+with\b"),
         "System prompt extraction: request the assistant's startup directives"),
    Rule("cancel_setup_limits", "high",
         _compile(
             r"\b(?:treat|consider|regard)\s+(?:the\s+|your\s+)?(?:setup\s+)?"
             r"(?:limits?|constraints?|rules?|instructions?|directives?|guidelines?|guardrails?)\s+"
             r"(?:that\s+)?you\s+(?:started|began)\s+with\s+as\s+(?:now\s+)?"
             r"(?:cancelled|canceled|void|invalid|revoked|inapplicable|nullified)\b"),
         "Instruction override: cancel the assistant's initial constraints"),
    Rule("ignore_previous", "high",
         _compile(r"\b(ignore|disregard|forget)\s+(all|every|the)?\s*(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|rules?|context)"),
         "Classic prompt-injection: instruction override"),
    Rule("override_system", "high",
         _compile(r"\b(override|bypass|disable)\s+(the\s+)?(system|safety|guardrails?)\s+(prompt|rules?|filter)"),
         "System-prompt override attempt"),
    Rule("chatml_injection", "critical",
         _compile(r"(<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[INST\]|\[\/INST\])"),
         "ChatML / LLaMA delimiter injection"),
    Rule("system_prompt_leak", "medium",
         _compile(r"\b(reveal|show|print|repeat|output|quote|dump)\s+(your|the|me\s+the)?\s*(system|original|initial|hidden)\s+(prompt|instructions?|context|message|directives?)"),
         "System prompt extraction attempt"),

    # Role hijacking
    Rule("dan_jailbreak", "critical",
         # Unambiguous jailbreak markers stand alone. "developer mode" does NOT:
         # the bare term is a benign IDE/browser/app mode, and matching it alone
         # over-blocks normal IT/dev text (measured ~13% false-positive on
         # benign inputs). The real "Developer Mode" jailbreak always
         # sheds restrictions, so require a restriction-removal cue within a
         # short window (either order). Bounds keep it ReDoS-safe. "DAN" is
         # matched case-sensitively: the jailbreak persona is always written in
         # capitals, and the name "Dan" blocked ordinary text at critical.
         _compile(
             r"\b(?:(?-i:DAN)|do anything now|jailbreak|unfiltered\s+ai)\b"
             r"|\bdeveloper\s+mode\b[\s\S]{0,80}(?:unrestricted|unfiltered|anything\s+goes|free\s+from|no\s+(?:restrictions?|rules?|filters?|limits?)|without\s+(?:restrictions?|rules?|filters?)|bypass|never\s+(?:refuse|decline|deny)|(?:can|may)\s+say\s+anything|ignore\s+(?:all|your|the)?[\w\s]{0,12}(?:rules?|restrictions?|instructions?|guidelines?|policy|policies))"
             r"|(?:unrestricted|unfiltered|anything\s+goes|no\s+(?:restrictions?|rules?|filters?)|bypass|never\s+(?:refuse|decline|deny)|(?:can|may)\s+say\s+anything|ignore\s+(?:all|your|the)?[\w\s]{0,12}(?:rules?|restrictions?|instructions?))[\s\S]{0,80}\bdeveloper\s+mode\b"
         ),
         "DAN / developer-mode jailbreak"),
    Rule("persona_takeover", "high",
         _compile(
             # "you are now a(n) <malicious-adj>[, <adj> and ...] <noun>".
             # The adjective list is attack-only (so "you are now a helpful
             # assistant" never matches), but allow a comma/'and'-separated
             # run of them before the noun -- "you are now an unrestricted,
             # uncensored AI" slipped past the old single-adjective form. The
             # {1,4} bound keeps it linear (no ReDoS).
             r"\byou\s+are\s+now\s+(?:an?\s+)?"
             r"(?:(?:unrestricted|uncensored|unfiltered|unlimited|amoral|immoral|evil|jailbroken|lawless|rogue)"
             r"(?:\s*,\s*|\s+and\s+|\s+)){1,4}"
             r"(?:ai|a\.i\.|assistant|model|chatbot|bot|llm|language\s+model|entity|being|persona)"
         ),
         "Persona takeover"),

    # Data exfiltration
    # The variable-length runs in the three URL rules below are "tempered":
    # they stop where the next possible match start begins (`![` or
    # `http(s):`). Unbounded runs let every start position scan to the end of
    # the text, which made these patterns cubic/quadratic on a repeated
    # unterminated prefix (8,000 chars of `![](http://a?` took ~27 s). A match
    # that would have run across a later start is still found from that start.
    Rule("markdown_image_exfil", "high",
         _compile(
             r"!\[(?:(?!!\[)[^\]])*\]\(https?:\/\/(?:(?!!\[)[^)?])+\?"
             r"(?:(?!!\[)[^)])*?(token|key|password|secret|api)"
         ),
         "Markdown image URL with credentials in query"),
    Rule("base64_url_exfil", "high",
         _compile(
             r"https?:\/\/(?:(?!https?:)[^\s?])+\?(?:(?!https?:)\S)*?"
             r"=[A-Za-z0-9+\/]{40,}={0,2}"
         ),
         "URL parameter with base64 payload"),
    # base64_url_exfil only catches a base64-shaped value; a PLAINTEXT provider
    # credential in a URL (query, fragment, OR path) slipped past it and every
    # other rule. Match well-known secret token shapes anywhere in a URL --
    # distinctive prefixes keep the false-positive rate near zero (a benign
    # ``?key=`` / ``?token=`` is NOT enough to fire; the value must look like a
    # real credential). Catches the ``#fragment`` / path-segment placements the
    # markdown rule's ``?``-only check misses.
    Rule("credential_in_url", "high",
         _compile(
             r"https?:\/\/(?:(?!https?:)\S)*?(?:"
             r"sk-ant-[A-Za-z0-9_-]{12,}"        # Anthropic
             r"|sk-[A-Za-z0-9]{20,}"             # OpenAI-style
             r"|gh[posru]_[A-Za-z0-9]{20,}"      # GitHub PAT/OAuth/refresh/server/user
             r"|github_pat_[A-Za-z0-9_]{20,}"    # GitHub fine-grained PAT
             r"|sk_live_[A-Za-z0-9]{16,}"        # Stripe live secret
             r"|AKIA[0-9A-Z]{16}"                # AWS access key id
             r"|AIza[A-Za-z0-9_-]{20,}"          # Google API key
             r"|xox[baprs]-[A-Za-z0-9-]{10,}"    # Slack token
             r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"  # JWT
             r")"
         ),
         "Recognizable credential token embedded in a URL (exfiltration)"),

    # Tool abuse markers (these trigger on tool-call args, not free text).
    # The `_shell_deobfuscate` candidate strips quotes/$IFS, so quoted and
    # $IFS-split variants canonicalise into these patterns.
    Rule(
        "rm_rf_root", "critical",
        _compile(
            r"\brm\s+"
            rf"(?=(?:{_FLAG_TOKEN}\s+){{0,5}}{_has_flag('r', 'recursive')})"
            rf"(?=(?:{_FLAG_TOKEN}\s+){{0,5}}{_has_flag('f', 'force')})"
            rf"(?:{_FLAG_TOKEN}\s+){{1,5}}(\/|~|\$HOME|\$\{{HOME\}})(\*|\/|[\s;&|]|$)"
        ),
        "rm -rf/-fr (contiguous OR split across flags, e.g. `rm -r -f /`) "
        "against /, ~, or $HOME",
    ),
    Rule("disk_overwrite", "critical",
         _compile(
             r"\b(dd\s+(?:(?!\bdd\s)[^\n])*?\bof=\/dev\/(sd[a-z]|nvme\d|disk\d|hd[a-z])"
             r"|mkfs(\.[a-z0-9]+)?\s+(?:(?!\bmkfs)[^\n])*?\/dev\/)"
         ),
         "Raw disk overwrite via dd/mkfs against a block device"),
    Rule(
        "recursive_chmod_chown_root", "critical",
        _compile(
            r"\bch(mod|own)\s+"
            rf"(?=(?:{_FLAG_TOKEN}\s+){{0,5}}{_has_flag('R', 'recursive')})"
            r"(?:(?!\bch(?:mod|own)\s)[^\n])*\s(\/|~|\$HOME|\$\{HOME\})(\s|;|&|\||$)"
        ),
        "Recursive chmod/chown (contiguous OR split across flags, e.g. "
        "`chmod -c -R 777 /`) against /, ~, or $HOME",
    ),
    Rule("fork_bomb", "critical",
         _compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
         "Classic shell fork bomb :(){ :|:& };:"),
    Rule("sensitive_file_read", "high",
         _compile(r"(\/etc\/+(passwd|shadow|ssh|sudoers)|\bNOPASSWD\b|~?\/\.ssh\/|~?\/\.aws\/credentials|\.env\b)"),
         "Read of /etc/passwd, ssh keys, sudoers, AWS creds, or .env"),
    Rule("curl_pipe_shell", "critical",
         _compile(r"(curl|wget)\s+(?:(?!(?:curl|wget)\s)[^|])+\|\s*(sudo\s+)?(sh|bash|zsh|python)\b"),
         "curl-pipe-to-shell remote code execution"),
    Rule("reverse_shell", "critical",
         _compile(r"(bash\s+-i\s+>&\s+\/dev\/tcp\/|nc\s+-e\s+\/bin\/(sh|bash))"),
         "Reverse shell payload"),

    # Social engineering markers
    Rule("urgency_authority", "medium",
         _compile(r"\bthis\s+is\s+(an?\s+)?(emergency|urgent|critical)\b(?:(?!\bthis\s+is\s)[^\n])*\b(execute|run|do)\s+(immediately|now|asap)"),
         "Urgency + authority pressure"),
    Rule("false_preapproval", "medium",
         _compile(r"\b(the\s+user|admin|operator)\s+(has\s+)?already\s+(approved|authorized|allowed)"),
         "False pre-approval claim"),

    # --- Newer attack families (close the held-out benchmark gaps) -----------
    # These generalize the family, not the specific benchmark sentence: each
    # requires an attack verb/marker AND a target, so benign text that merely
    # name-drops the vocabulary does not trip them. Bounded `{0,N}?` gaps keep
    # them linear (no ReDoS) and allow the two tokens to span a newline.
    Rule("directive_supersede", "high",
         _compile(r"\b(new|updated|latest|the\s+following)\s+(directive|instruction|rule|policy|order)s?\b[\s\S]{0,40}?\b(supersed|overrid|replac|take[\s-]?priorit|come\s+first)"),
         "Instruction-override: a new directive supersedes prior ones"),
    Rule("stop_following_policy", "high",
         _compile(r"\bstop\s+(following|obeying|applying|enforcing|adhering\s+to)\s+(your|the|all|its)?\s*(configured\s+)?(polic\w+|rules?|guidelines?|instructions?|guardrails?|safety)"),
         "Instruction-override: stop following configured policy"),
    Rule("comply_without_restrictions", "high",
         _compile(r"\b(comply|respond|answer|proceed|continue|do\s+it)\b[\s\S]{0,40}?\bwithout\s+(any\s+)?(restrictions?|limits?|limitations?|filters?|guardrails?|refus\w+)"),
         "Instruction-override: comply without restrictions"),

    # Persona takeover — "from now on", "pretend safety is off", "true self".
    Rule("from_now_on_persona", "high",
         _compile(r"\bfrom\s+now\s+on\b[\s\S]{0,40}?\byou\s+(are|act|operate|behave|respond|will|must)\b"),
         "Persona takeover: 'from now on you ...'"),
    Rule("pretend_safety_off", "critical",
         _compile(r"\b(pretend|imagine|assume|act\s+as\s+if|suppose)\b[\s\S]{0,40}?\b(safety|content|filter|guardrails?|alignment|moderation|rules?)\b[\s\S]{0,24}?\b(off|disabled|removed|gone|switched\s+off|turned\s+off|don'?t\s+apply|never\s+existed)"),
         "Jailbreak: pretend the safety layer is disabled"),
    Rule("unaligned_self", "high",
         _compile(r"\b(answer|respond|act|reply|speak)\s+as\s+your\s+(raw|true|real|unaligned|unfiltered|uncensored|unrestricted|boundless)\s+self\b"),
         "Persona takeover: answer as your 'unaligned self'"),

    # System-prompt leak — verbatim / everything above / hidden directives.
    Rule("verbatim_prompt_leak", "medium",
         _compile(r"\b(print|repeat|output|show|reveal|echo|paste|reproduce|quote)\b[\s\S]{0,40}?\b(verbatim|word[\s-]for[\s-]word|line[\s-]for[\s-]line|exact\s+text|everything\s+(above|that\s+appears)|hidden\s+(directive|instruction|prompt)|configuration\s+block)"),
         "System-prompt extraction: dump hidden/preceding text verbatim"),

    # Secret exfiltration — name a credential AND move it out (either order).
    Rule("secret_exfil_request", "critical",
         _compile(r"\b(api[\s_-]?(key|token)|access[\s_-]?token|secret|credential|password|private\s+key|\.env\b|config\.toml|/\.aws/|id_rsa)\b[\s\S]{0,60}?\b(include|return|reply|print|show|reveal|paste|email|send|upload|post|exfil|leak|give\s+me)"),
         "Credential exfiltration request"),
    Rule("secret_exfil_request_rev", "critical",
         _compile(r"\b(read|fetch|get|dump|cat|summari[sz]e|print|reveal|leak|exfil\w*|send|email|forward|post|upload|transmit)\b[\s\S]{0,40}?\b(environment\s+variable|env\s+var|api[\s_-]?(key|token)|secret|credential|password|private\s+key|\.env\b|config\.toml|/\.aws/|id_rsa)"),
         "Credential read/exfiltration request"),

    # Indirect / tool-output injection — content addressing the agent.
    Rule("ai_reading_this", "high",
         _compile(r"\bif\s+you\s+(are|'?re|happen\s+to\s+be|find\s+yourself)\s+(an?\s+)?(automated\s+|virtual\s+|digital\s+|ai\s+|language\s+)?(ai|agent|assistant|llm|model|language\s+model|bot|system)\b[\s\S]{0,40}?\b(reading|seeing|processing|parsing|viewing|summari[sz]ing|handling)\b"),
         "Indirect injection: content addressed to an AI that reads it"),
    Rule("real_task_hijack", "high",
         # "new"/"primary" remain too broad by themselves: ordinary delegation
         # uses phrases such as "your new task is to review the PR". Treat those
         # adjectives as hijacks only when the continuation carries injection or
         # exfiltration intent (e.g. "follow only this document", "email/report
         # success to ..."). Bounds keep the regex linear and local.
         _compile(
             r"\byour\s+(?:real|actual|true|secret|hidden)\s+(?:task|job|goal|mission|instruction|objective|purpose)\s+is\b"
             r"|\byour\s+(?:new|primary)\s+(?:task|job|goal|mission|instruction|objective|purpose)\s+is\b[\s\S]{0,80}?(?:follow\s+only\s+(?:this|the)\s+(?:document|file|page|message|instructions?)|ignore\s+(?:all|every|the)?\s*(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules?|context)|(?:email|send|forward|upload|post|exfil\w*|leak)\b|report\s+success\b)"
         ),
         "Task hijack: your 'real task' is ..."),
    Rule("injected_command_to_agent", "high",
         _compile(r"\b(system\s+note|important|attention|urgent|note\s+from\s+file)\b[\s\S]{0,60}?\b(assistant|ai|agent|model)\b[\s\S]{0,24}?\b(must|should|needs?\s+to|has\s+to|now)\b[\s\S]{0,24}?\b(email|send|upload|exfil\w*|delete|run|execute|forward|leak|transfer)"),
         "Tool-output / file injection issuing a command to the agent"),

    # Jailbreak framing — fiction/hypothetical used to elicit a bypass.
    Rule("fiction_bypass_framing", "high",
         _compile(r"\b(fiction|story|stories|roleplay|role[\s-]?play|hypothetical|screenplay|novel|game|scenario)\b[\s\S]{0,80}?\b(bypass\w*|disabl\w*|ignor\w*|circumvent\w*|evad\w*|get\s+around|turn\s+off|defeat\w*|get\s+past)[\s\S]{0,40}?\b(filter|safety|guardrails?|rules?|restrictions?|alignment|content\s+(policy|filter)|moderation)"),
         "Jailbreak via fiction / hypothetical framing"),

    # Encoding evasion — "decode X and treat it as an instruction".
    Rule("decode_and_obey", "high",
         _compile(r"\bdecode\b[\s\S]{0,60}?\b(treat|use\s+it|execute|run|obey|follow|act\s+on|top[\s-]?priority|overrid)"),
         "Encoding evasion: decode then treat as instruction"),

    # Invisible/bidi chars are an evasion signal in their own right -- medium
    # so 'strict' blocks on smuggling even when the de-obfuscated payload
    # happens to match no other rule.
    Rule("zero_width_chars", "medium",
         _compile(r"[\u200b-\u200f\u2028-\u202f\u2060-\u206f]"),
         "Zero-width / bidi characters"),

    # --- families from the end-to-end ASR benchmark ----------------------------
    # Each needs an attack verb/marker AND a target, so benign vocab name-drops
    # don't trip them; bounded gaps keep them linear (no ReDoS).
    Rule("prompt_leak_query", "medium",
         _compile(r"\b(what|which)\s+(system\s+)?(instructions?|rules?|directives?|prompt|guidance)\s+(were|was|did)\s+you\s+(give[n]?|told|provided|configured|set\s+up\s+with)"),
         "System-prompt extraction via question"),
    Rule("forget_setup_constraints", "high",
         _compile(r"\b(ignore|disregard|forget|drop|abandon|discard)\s+(the\s+|all\s+|any\s+|your\s+)?(constraints?|limits?|limitations?|restrictions?|rules?|guardrails?|guidance|guidelines?)\s+(from|in|of|set\s+(by|in)|that\s+came\s+with)\s+(your\s+)?(setup|config\w*|system|instructions?|prompt|training)"),
         "Instruction-override: forget the constraints from your setup"),
    Rule("instructions_voided", "high",
         _compile(r"\b(your|the)\s+(previous|prior|original|earlier|current|existing)?\s*(instructions?|directives?|rules?|guidelines?|constraints?|guardrails?)\s+(you\s+(began|started)\s+with\s+)?(are|is|have\s+been)\s+(now\s+)?(void|null|nullified|cancel\w+|revoked|invalid|defunct|no\s+longer\s+(valid|in\s+effect|active))"),
         "Instruction-override: prior instructions declared void"),
    Rule("content_directs_agent_exfil", "high",
         _compile(r"\b(note|message|instruction|memo|reminder)\s+(for|to)\s+(the\s+)?(ai|assistant|agent|model|llm|bot)\b[\s\S]{0,60}?\b(forward|send|email|post|upload|transmit|exfil\w*|leak|deliver|hand\s+over)\b[\s\S]{0,40}?\b(credential|password|secret|invoice|bank|account|details|file|data|token|key)"),
         "Indirect injection: content instructs the AI to exfiltrate"),
    Rule("destructive_db_no_confirm", "critical",
         _compile(r"\b(drop|truncate|delete\s+from|wipe|destroy|purge)\s+(every|all|each|the\s+entire|the\s+whole)?\s*(table|database|schema|collection|index|record)s?\b[\s\S]{0,50}?\b(skip|without|bypass|no|ignore|don'?t|avoid)\s*\w*\s*(confirm\w*|approv\w*|verif\w*|prompt|backup|safeguard)"),
         "Destructive database op that skips the confirmation/approval"),
    Rule("self_privilege_escalation", "critical",
         _compile(r"\b(grant|give|assign|escalate|elevate|add)\b[\s\S]{0,24}?\b(your(self)?|its|the\s+agent'?s?|my\s+own)\b[\s\S]{0,20}?\b(admin\w*|root|sudo|superuser|elevated|privileged)\b[\s\S]{0,20}?\b(scope|access|privileg\w*|right|permission|role)|\b(remove|drop|disable|bypass|waive|eliminate|skip)\s+(the\s+)?(approval|confirmation|consent|sign[\s-]?off|authoriz\w+)\s+(requirement|step|gate|check|process)"),
         "Privilege escalation: self-grant admin or remove the approval gate"),
    Rule("credential_phish", "high",
         _compile(r"\b(reply|respond|provide|shar\w+|send|give|tell|disclose|reveal|hand\s+(me|over|us))\b[\s\S]{0,40}?\b(password|passphrase|2fa\b|two[\s-]factor|one[\s-]time\s+code|otp\b|mfa\b|backup\s+codes?|recovery\s+codes?|security\s+codes?|seed\s+phrase)"),
         "Credential phishing: asks to disclose a password / 2FA / backup code"),
]


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _threshold_to_min_severity(threshold: str) -> int:
    # Normalize: block_threshold comes from user-typed TOML. A non-lowercase or
    # padded spelling ("Medium", " high ") missed the lookup and silently fell
    # back to "high", strengthening the gate past the operator's intent.
    return SEVERITY_ORDER.get(str(threshold).strip().lower(), SEVERITY_ORDER["high"])


def scan(
    text: str,
    block_threshold: str = "high",
) -> tuple[bool, str, list[str]]:
    """Run all rules over ``text``.

    Returns (blocked, max_severity, matched_rule_names).
    Blocked = True iff any rule fired at or above the configured threshold.
    """
    threshold_idx = _threshold_to_min_severity(block_threshold)
    # Bound the scanned length first: candidate generation + ~40 regexes are
    # linear in input size, so an oversized body (the MCP transport allows 2 MB)
    # is a linear-amplification CPU DoS. Do not scan a prefix and allow the
    # original oversized text through: that turns the cap into a deterministic
    # bypass for malicious suffixes. Oversized inputs are conservatively blocked
    # before the expensive de-obfuscation.
    max_chars = _max_scan_chars()
    if len(text) > max_chars:
        return True, "critical", ["input_too_large"]
    # Scan the original text AND its de-obfuscated / base64-decoded variants,
    # so an encoded or quoted payload still trips the rule it was hiding from.
    candidates = _candidates(text)
    matched: list[str] = []
    max_idx = -1
    max_sev = "none"
    for r in RULES:
        if any(r.pattern.search(c) for c in candidates):
            matched.append(r.name)
            idx = SEVERITY_ORDER[r.severity]
            if idx > max_idx:
                max_idx = idx
                max_sev = r.severity
    blocked = max_idx >= threshold_idx and len(matched) > 0
    return blocked, max_sev, matched
