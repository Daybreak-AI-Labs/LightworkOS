"""whatsapp/sms must import and refuse cleanly when fastapi/twilio are absent.

``Form(...)`` as a method DEFAULT ARGUMENT is evaluated at class-definition
(import) time. With fastapi/twilio missing, ``Form`` is ``None``, so an
unguarded default would raise ``TypeError: 'NoneType' object is not callable``
on import -- defeating the ``_HAVE_DEPS`` guard in ``__init__`` and giving the
operator a cryptic error instead of the actionable "pip install" message.
"""
from __future__ import annotations

import pytest


@pytest.mark.parametrize("modname,channel_cls,extra", [
    ("maverick_channels.whatsapp", "WhatsAppChannel", "whatsapp"),
    ("maverick_channels.sms", "SMSChannel", "sms"),
])
def test_import_does_not_crash_and_construct_is_actionable(modname, channel_cls, extra):
    import importlib
    mod = importlib.import_module(modname)  # must not raise at class-def time
    cls = getattr(mod, channel_cls)

    if mod._HAVE_DEPS:
        pytest.skip("fastapi/twilio installed; the absent-deps path is dormant")

    # Without deps, construction must raise the actionable ImportError -- NOT
    # the cryptic "'NoneType' object is not callable" TypeError.
    with pytest.raises(ImportError) as ei:
        cls(handler=lambda *a, **k: None)
    assert extra in str(ei.value) or "pip install" in str(ei.value)
