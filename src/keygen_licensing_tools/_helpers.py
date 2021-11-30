from __future__ import annotations

import re
from datetime import datetime


def string_to_dict(string: str) -> dict[str, str]:
    """Convert a string like

    "keyid=\"abc\", algorithm=\"ed25519\", signature=\"def==\", headers=\"(request-target) host date digest\""

    to a dictionary

    {
        "keyid": "abc",
        "algorithm" : "ed25519",
        "signature": "def==",
        "headers": "(request-target) host date digest"
    }
    """
    return dict(
        map(
            lambda param: re.match('([^=]+)="([^"]+)"', param).group(1, 2),
            re.split(r",\s*", string),
        )
    )


def safeget(dct: dict, *keys):
    for key in keys:
        try:
            dct = dct[key]
        except (KeyError, TypeError):
            return None
    return dct


def to_datetime(string):
    return datetime.strptime(string, "%Y-%m-%dT%H:%M:%S.%fZ")
