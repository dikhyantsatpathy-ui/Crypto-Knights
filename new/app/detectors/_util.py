"""Shared lazy third-party imports used across the detector package."""

_imports = {}


def _np():
    """Return the numpy module, or None if unavailable (lazy, cached)."""
    if "np" not in _imports:
        try:
            import numpy
            _imports["np"] = numpy
        except Exception:
            _imports["np"] = None
    return _imports["np"]


def _pil():
    """Return the PIL module, or None if unavailable (lazy, cached)."""
    if "pil" not in _imports:
        try:
            import PIL.Image
            _imports["pil"] = PIL
        except Exception:
            _imports["pil"] = None
    return _imports["pil"]