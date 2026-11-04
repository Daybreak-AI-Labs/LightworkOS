"""Image edit tool: remote inpaint/variation/upscale over a faked
httpx (mirrors replicate_tool's auth + request shape) and local Pillow ops
over a faked PIL. Offline and deterministic."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

from maverick.tools.image_edit import image_edit


def _fake_httpx(monkeypatch, **methods):
    mod = types.ModuleType("httpx")
    for n, v in methods.items():
        setattr(mod, n, v)
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


def _resp(status, body):
    r = MagicMock()
    r.status_code = status
    r.json = MagicMock(return_value=body)
    r.text = str(body)
    return r


def _wire_replicate(monkeypatch):
    monkeypatch.setenv("REPLICATE_API_TOKEN", "r8_xx")
    get = MagicMock(return_value=_resp(200, {"latest_version": {"id": "ver1"}}))
    post = MagicMock(return_value=_resp(201, {"id": "pred1", "status": "starting"}))
    _fake_httpx(monkeypatch, get=get, post=post)
    return get, post


class _SB:
    def __init__(self, workdir):
        self.workdir = str(workdir)


class _FakeImage:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def crop(self, box):
        self.calls.append(("crop", box))
        return self

    def resize(self, size):
        self.calls.append(("resize", size))
        return self

    def rotate(self, degrees, expand=True):
        self.calls.append(("rotate", degrees, expand))
        return self

    def save(self, path):
        Path(path).write_bytes(b"edited")


def _fake_pil(monkeypatch, img=None):
    img = img or _FakeImage()
    image_mod = types.ModuleType("PIL.Image")
    image_mod.open = lambda p: img
    pil = types.ModuleType("PIL")
    pil.Image = image_mod
    monkeypatch.setitem(sys.modules, "PIL", pil)
    monkeypatch.setitem(sys.modules, "PIL.Image", image_mod)
    return img


# ---- op routing ----


def test_requires_op_and_rejects_unknown():
    t = image_edit()
    assert "op is required" in t.fn({})
    assert "unknown op" in t.fn({"op": "bogus"})


# ---- remote ops ----


def test_remote_op_requires_token(monkeypatch):
    monkeypatch.delenv("REPLICATE_API_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock(), post=MagicMock())
    out = image_edit().fn({"op": "variation", "image": "https://x/cat.png"})
    assert "REPLICATE_API_TOKEN" in out


def test_inpaint_creates_prediction_with_data_uris(monkeypatch, tmp_path):
    get, post = _wire_replicate(monkeypatch)
    (tmp_path / "img.png").write_bytes(b"\x89PNG\r\n\x1a\ndata")
    (tmp_path / "mask.png").write_bytes(b"\x89PNG\r\n\x1a\nmask")
    out = image_edit(_SB(tmp_path)).fn(
        {
            "op": "inpaint",
            "image": "img.png",
            "mask": "mask.png",
            "prompt": "a red hat",
        }
    )
    assert "created prediction pred1" in out
    # version resolution hit the default inpaint model
    assert "stability-ai/stable-diffusion-inpainting" in get.call_args[0][0]
    body = post.call_args.kwargs["json"]
    assert body["version"] == "ver1"
    assert body["input"]["image"].startswith("data:image/png;base64,")
    assert body["input"]["mask"].startswith("data:image/png;base64,")
    assert body["input"]["prompt"] == "a red hat"


def test_inpaint_requires_mask_and_prompt(monkeypatch):
    _wire_replicate(monkeypatch)
    out = image_edit().fn({"op": "inpaint", "image": "https://x/cat.png"})
    assert "requires mask and prompt" in out


def test_variation_and_upscale_use_env_model_knobs(monkeypatch):
    get, post = _wire_replicate(monkeypatch)
    monkeypatch.setenv("MAVERICK_VARIATION_MODEL", "acme/vary")
    monkeypatch.setenv("MAVERICK_UPSCALE_MODEL", "acme/upscale")
    t = image_edit()
    t.fn({"op": "variation", "image": "https://x/cat.png", "prompt": "wider"})
    assert "acme/vary" in get.call_args[0][0]
    t.fn({"op": "upscale", "image": "https://x/cat.png", "scale": 4})
    assert "acme/upscale" in get.call_args[0][0]
    assert post.call_args.kwargs["json"]["input"]["scale"] == 4


def test_upscale_validates_scale(monkeypatch):
    _wire_replicate(monkeypatch)
    t = image_edit()
    assert "scale must be a positive number" in t.fn(
        {"op": "upscale", "image": "https://x/c.png", "scale": -2}
    )


def test_remote_local_image_must_be_real_bounded_image(monkeypatch, tmp_path):
    _wire_replicate(monkeypatch)
    (tmp_path / "secret.env").write_text("TOKEN=exfiltrate-me")
    t = image_edit(_SB(tmp_path))
    out = t.fn({"op": "variation", "image": "secret.env"})
    assert out.startswith("ERROR") and "must be .png" in out

    (tmp_path / "fake.png").write_text("TOKEN=exfiltrate-me")
    out = t.fn({"op": "variation", "image": "fake.png"})
    assert out.startswith("ERROR") and "not a valid image/png image" in out

    (tmp_path / "huge.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * (10 * 1024 * 1024 + 1))
    out = t.fn({"op": "variation", "image": "huge.png"})
    assert out.startswith("ERROR") and "too large" in out


def test_remote_model_override_is_ignored(monkeypatch):
    get, _post = _wire_replicate(monkeypatch)
    t = image_edit()
    out = t.fn(
        {
            "op": "variation",
            "image": "https://x/cat.png",
            "model": "attacker/steal-model:version123",
        }
    )
    assert "created prediction pred1" in out
    assert "lambdal/stable-diffusion-image-variation" in get.call_args[0][0]
    assert "attacker/steal-model" not in get.call_args[0][0]


def test_remote_wait_polls_to_terminal(monkeypatch):
    monkeypatch.setenv("REPLICATE_API_TOKEN", "r8_xx")
    get = MagicMock(
        side_effect=[
            _resp(200, {"latest_version": {"id": "ver1"}}),
            _resp(
                200,
                {
                    "id": "pred1",
                    "status": "succeeded",
                    "output": ["https://cdn/out.png"],
                    "error": None,
                },
            ),
        ]
    )
    post = MagicMock(return_value=_resp(201, {"id": "pred1", "status": "starting"}))
    _fake_httpx(monkeypatch, get=get, post=post)
    out = image_edit().fn({"op": "variation", "image": "https://x/cat.png", "wait": True})
    assert "status: succeeded" in out and "out.png" in out


def test_remote_local_image_confined_to_workspace(monkeypatch, tmp_path):
    _wire_replicate(monkeypatch)
    out = image_edit(_SB(tmp_path)).fn({"op": "variation", "image": "../../etc/passwd"})
    assert out.startswith("ERROR") and "escapes the workspace" in out


# ---- local ops (Pillow) ----


def test_crop_resize_rotate_apply_and_write(monkeypatch, tmp_path):
    img = _fake_pil(monkeypatch)
    (tmp_path / "in.png").write_bytes(b"x")
    t = image_edit(_SB(tmp_path))
    assert "wrote" in t.fn(
        {"op": "crop", "input_path": "in.png", "output_path": "c.png", "box": [0, 0, 4, 4]}
    )
    assert "wrote" in t.fn(
        {"op": "resize", "input_path": "in.png", "output_path": "r.png", "width": 8, "height": 6}
    )
    assert "wrote" in t.fn(
        {"op": "rotate", "input_path": "in.png", "output_path": "o.png", "degrees": 90}
    )
    assert img.calls == [("crop", (0, 0, 4, 4)), ("resize", (8, 6)), ("rotate", 90, True)]
    assert (tmp_path / "c.png").read_bytes() == b"edited"


def test_local_ops_validate_args(monkeypatch, tmp_path):
    _fake_pil(monkeypatch)
    t = image_edit(_SB(tmp_path))
    assert "requires input_path and output_path" in t.fn({"op": "crop", "box": [0, 0, 1, 1]})
    assert "box=[left, top, right, bottom]" in t.fn(
        {"op": "crop", "input_path": "a", "output_path": "b", "box": [1, 2]}
    )
    assert "positive integer width and height" in t.fn(
        {"op": "resize", "input_path": "a", "output_path": "b", "width": 0, "height": 2}
    )
    assert "degrees" in t.fn({"op": "rotate", "input_path": "a", "output_path": "b"})


def test_local_output_path_confined(monkeypatch, tmp_path):
    _fake_pil(monkeypatch)
    out = image_edit(_SB(tmp_path)).fn(
        {
            "op": "rotate",
            "input_path": "in.png",
            "output_path": "../evil.png",
            "degrees": 90,
        }
    )
    assert out.startswith("ERROR") and "escapes the workspace" in out


def test_local_ops_actionable_without_pillow(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "PIL", None)
    (tmp_path / "in.png").write_bytes(b"x")
    out = image_edit(_SB(tmp_path)).fn(
        {
            "op": "crop",
            "input_path": "in.png",
            "output_path": "c.png",
            "box": [0, 0, 1, 1],
        }
    )
    assert out.startswith("ERROR") and "packages/maverick-core[computer-use]" in out


def test_factory_registered_in_base_registry():
    from maverick.tools import base_registry

    class _W:
        pass

    names = set(getattr(base_registry(world=_W(), sandbox=None), "_tools", {}).keys())
    assert "image_edit" in names
