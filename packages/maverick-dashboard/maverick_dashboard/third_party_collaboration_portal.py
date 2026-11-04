"""Public shell for invitation-authenticated third-party collaboration.

The page is deliberately tenant-neutral and contains no invitation material.
It loads a same-origin client which keeps the respondent credential in memory
and sends it only in the external API ``Authorization`` header.  It is written
for an outside supplier: plain words only, a file chooser for evidence (the
server measures each file), and any reference values inside collapsed
"Technical details".
"""

from __future__ import annotations

import re
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse

_PORTAL_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{15,127}\Z")
_TENANT_HEADERS = ("x-lightwork-tenant", "x-maverick-tenant", "x-tenant-id")
_STATIC = Path(__file__).with_name("static")

_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>Supplier questionnaire | Lightwork</title>
  <link rel="stylesheet" href="portal/assets/styles.css">
  <script defer src="portal/assets/client.js"></script>
</head>
<body>
  <main class="portal-shell" id="portal-shell">
    <header class="portal-hero">
      <p class="eyebrow">Lightwork</p>
      <h1>Supplier Questionnaire</h1>
      <p class="lede">
        Answer the questions you have been sent and add any documents that back
        up your answers. You can save and come back until the request closes.
      </p>
    </header>

    <p class="status" id="portal-status" role="status" aria-live="polite">
      Paste your access code to begin.
    </p>

    <section class="panel" id="unlock-panel" aria-labelledby="unlock-title">
      <h2 id="unlock-title">Open Your Request</h2>
      <form id="unlock-form" autocomplete="off" novalidate>
        <div class="field">
          <label for="invitation-credential">Access code</label>
          <input
            id="invitation-credential"
            type="password"
            maxlength="256"
            autocapitalize="none"
            autocomplete="off"
            spellcheck="false"
            aria-describedby="credential-help"
            required
          >
          <p class="help" id="credential-help">
            Paste the access code from your invitation. For your security it is
            kept only while this page is open.
          </p>
        </div>
        <label class="check-label" for="show-credential">
          <input id="show-credential" type="checkbox">
          <span>Show the code</span>
        </label>
        <div class="actions">
          <button type="submit" id="unlock-button">Open my request</button>
        </div>
      </form>
    </section>

    <section class="workspace" id="workspace" aria-labelledby="workspace-title" hidden>
      <div class="workspace-heading">
        <div>
          <h2 id="workspace-title">Your Questions</h2>
          <p class="help">
            You can send your answers until <time id="invitation-expiry"></time>.
          </p>
          <p class="progress" id="question-progress"></p>
        </div>
        <button class="secondary" type="button" id="lock-button">Close and sign out</button>
      </div>

      <form id="response-form" novalidate>
        <section aria-labelledby="questions-title">
          <h3 id="questions-title">Questions</h3>
          <p class="help">
            Questions marked Required must be answered before you send. Some
            questions only appear after you save, depending on your answers.
          </p>
          <div id="questions"></div>
        </section>

        <section class="evidence" aria-labelledby="evidence-title">
          <div class="section-heading">
            <div>
              <h3 id="evidence-title">Evidence Files</h3>
              <p class="help">
                Add documents that back up your answers, such as certificates,
                audit reports or policies. Each file is checked as soon as you
                add it.
              </p>
            </div>
            <button class="secondary" type="button" id="add-files-button">Add files</button>
            <input
              id="evidence-file-input"
              type="file"
              multiple
              hidden
              aria-label="Choose evidence files from your computer"
            >
          </div>
          <p class="policy" id="evidence-policy"></p>
          <p class="help empty-files" id="evidence-empty">
            No files added yet. Choose Add files to pick documents from your computer.
          </p>
          <ul class="file-list" id="evidence-files" aria-labelledby="evidence-title"></ul>
        </section>

        <section class="attestation" id="attestation-section" aria-labelledby="attestation-title">
          <h3 id="attestation-title">Confirm and Send</h3>
          <label class="check-label" for="respondent-attestation">
            <input id="respondent-attestation" type="checkbox" data-answer="confirmation">
            <span>
              I am allowed to answer for my organisation, and my answers and files
              are accurate to the best of my knowledge. I understand the
              organisation that invited me will review them.
            </span>
          </label>
          <p class="field-error" id="attestation-error" hidden></p>
        </section>

        <div class="actions">
          <button class="secondary" type="button" id="save-draft-button">Save my answers</button>
          <button type="button" id="finalize-button">Send my answers</button>
        </div>
      </form>

      <details class="technical">
        <summary>Technical details</summary>
        <p class="help">Only needed if you contact support about this request.</p>
        <dl class="contract-meta">
          <div><dt>Request reference</dt><dd class="code" id="detail-request"></dd></div>
          <div><dt>Questionnaire reference</dt><dd class="code" id="detail-questionnaire"></dd></div>
          <div><dt>Your organisation's reference</dt><dd class="code" id="detail-company"></dd></div>
          <div><dt>Notice</dt><dd id="detail-notice"></dd></div>
          <div><dt>Notice fingerprint</dt><dd class="code" id="detail-notice-fingerprint"></dd></div>
          <div><dt>Saved version</dt><dd id="detail-version"></dd></div>
        </dl>
      </details>
    </section>

    <section class="panel receipt" id="receipt-panel" aria-labelledby="receipt-title" hidden>
      <h2 id="receipt-title">Your Answers Have Been Sent</h2>
      <p id="receipt-summary"></p>
      <p>
        Thank you. The organisation that invited you will review your answers
        and may contact you with follow-up questions. You can close this page.
      </p>
      <details class="technical">
        <summary>Technical details</summary>
        <p class="help">Keep these with your records if you want proof of what you sent.</p>
        <dl class="contract-meta">
          <div><dt>Confirmation code</dt><dd class="code" id="receipt-confirmation-code"></dd></div>
          <div><dt>Record fingerprint</dt><dd class="code" id="receipt-assessment-fingerprint"></dd></div>
          <div><dt>Record version</dt><dd id="receipt-revision"></dd></div>
          <div><dt>Review status</dt><dd id="receipt-evidence-status"></dd></div>
        </dl>
      </details>
    </section>

    <details class="safeguards">
      <summary>About this page's safeguards</summary>
      <ul>
        <li>
          Your access code is kept only while this page is open. It is never
          saved in your browser, in a cookie or in the web address.
        </li>
        <li>Closing and signing out clears the code and your unsaved answers from this page.</li>
      </ul>
      <ul id="contract-limitations"></ul>
    </details>

    <noscript>
      <p class="status" data-state="error">
        This page needs JavaScript turned on to keep your access code safe. Turn
        it on and reload the page.
      </p>
    </noscript>
  </main>
</body>
</html>
"""

_SECURITY_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "Content-Security-Policy": (
        "default-src 'none'; base-uri 'none'; connect-src 'self'; "
        "font-src 'self'; form-action 'none'; frame-ancestors 'none'; "
        "img-src 'none'; manifest-src 'none'; media-src 'none'; "
        "object-src 'none'; script-src 'self'; style-src 'self'; "
        "worker-src 'none'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
        "serial=(), bluetooth=(), clipboard-read=(), clipboard-write=()"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
}

_ASSET_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
}


def _available(portal_ref: str, request: Request) -> None:
    if (
        not _PORTAL_REF_RE.fullmatch(portal_ref)
        or request.query_params
        or any(request.headers.get(name) for name in _TENANT_HEADERS)
    ):
        raise HTTPException(status_code=404, detail="portal unavailable")


def create_third_party_collaboration_portal_router() -> APIRouter:
    """Create the constant, non-enumerating external portal shell router."""

    router = APIRouter(
        prefix="/api/v1/external/third-party-collaboration",
        tags=["external-third-party-collaboration-portal"],
    )

    @router.get(
        "/{portal_ref}/portal",
        include_in_schema=False,
        response_class=HTMLResponse,
    )
    async def portal(portal_ref: str, request: Request) -> HTMLResponse:
        _available(portal_ref, request)
        return HTMLResponse(_PAGE, headers=_SECURITY_HEADERS)

    @router.get(
        "/{portal_ref}/portal/assets/client.js",
        include_in_schema=False,
        response_class=FileResponse,
    )
    async def client_asset(portal_ref: str, request: Request) -> FileResponse:
        _available(portal_ref, request)
        return FileResponse(
            _STATIC / "lightwork-third-party-portal.js",
            media_type="text/javascript",
            headers=_ASSET_HEADERS,
        )

    @router.get(
        "/{portal_ref}/portal/assets/styles.css",
        include_in_schema=False,
        response_class=FileResponse,
    )
    async def style_asset(portal_ref: str, request: Request) -> FileResponse:
        _available(portal_ref, request)
        return FileResponse(
            _STATIC / "lightwork-third-party-portal.css",
            media_type="text/css",
            headers=_ASSET_HEADERS,
        )

    return router


router = create_third_party_collaboration_portal_router()

__all__ = ["create_third_party_collaboration_portal_router", "router"]
