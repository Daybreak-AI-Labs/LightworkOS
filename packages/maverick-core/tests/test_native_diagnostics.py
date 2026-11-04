"""Report the actual optional native wrappers, including partial extensions."""
from types import SimpleNamespace

from maverick.installation_info import native_acceleration_status


def test_python_fallback_is_reported_when_extension_is_absent():
    unicode_module = SimpleNamespace(_native=None)
    image_module = SimpleNamespace(_native=None)
    assert native_acceleration_status(unicode_module, image_module) == {
        "unicode": "Python", "image_hash": "Python",
    }


def test_native_status_requires_both_extension_and_installed_wrapper():
    native = SimpleNamespace(normalize=lambda text: text,
                             average_hash_from_pixels=lambda *args: "")
    unicode_module = SimpleNamespace(_native=native, _normalize_py=lambda text: text)
    image_module = SimpleNamespace(_native=native)
    assert native_acceleration_status(unicode_module, image_module) == {
        "unicode": "native with Python fallback", "image_hash": "Python",
    }
