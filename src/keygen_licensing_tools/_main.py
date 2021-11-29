from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import ed25519
import requests


def _api_call(account_id: str, key: str):
    return requests.post(
        f"https://api.keygen.sh/v1/accounts/{account_id}/licenses/actions/validate-key",
        headers={
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
        },
        data=json.dumps({"meta": {"key": key}}),
    )


def _string_to_dict(string: str) -> dict[str, str]:
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


def validate_license_key_online(account_id, key):
    res = _api_call(account_id, key)
    return _create_return_value(res.json())


def _create_return_value(data: dict):
    if "errors" in data:
        code = None
        err = data["errors"][0]
        if "code" in err:
            code = err["code"]
        return SimpleNamespace(
            is_valid=False,
            code=code,
            timestamp=None,
            time_to_expiration=None,
            license_creation_time=None,
        )

    # string format: 2023-01-01T00:00:00.000Z
    attr = data["data"]["attributes"]
    created = datetime.strptime(attr["created"], "%Y-%m-%dT%H:%M:%S.%fZ")
    expiry = datetime.strptime(attr["expiry"], "%Y-%m-%dT%H:%M:%S.%fZ")
    now = datetime.now()
    time_to_expiration = None if now > expiry else expiry - now

    return SimpleNamespace(
        is_valid=data["meta"]["valid"],
        code=data["meta"]["constant"],
        timestamp=data["meta"]["ts"],
        time_to_expiration=time_to_expiration,
        license_creation_time=created,
    )


def validate_license_key_cached(
    account_id: str,
    key: str,
    keygen_verify_key: str,
    cache_path: Path | str,
    refresh_cache_period_s: int,
):
    data = _get_cache_data(
        account_id, key, keygen_verify_key, cache_path, refresh_cache_period_s
    )

    is_data_from_cache = data is not None

    if data is None:
        # fetch validation data
        res = _api_call(account_id, key)
        data = res.json()
        # rewrite cache
        cache_data = {
            "_warning": "Do not edit! Any change will invalidate the cache.",
            "signature": _string_to_dict(res.headers["Keygen-Signature"]),
            "digest": res.headers["Digest"],
            "date": res.headers["Date"],
            "res": res.text,
        }
        with open(cache_path, "w") as f:
            json.dump(cache_data, f, indent=2)

    out =_create_return_value(data)
    out.is_data_from_cache = is_data_from_cache
    return out


def _get_cache_data(
    account_id: str,
    key: str,
    keygen_verify_key: str,
    cache_path: Path | str,
    refresh_cache_period_s: int,
):
    cache_path = Path(cache_path)

    if not cache_path.exists():
        return None

    with open(cache_path) as f:
        cache_data = json.load(f)

    cache_is_ok = _verify_cache_integrity(
        account_id,
        keygen_verify_key,
        cache_data["signature"]["signature"],
        cache_data["date"],
        cache_data["res"],
    )
    if not cache_is_ok:
        return None

    res_data = json.loads(cache_data["res"])

    if res_data["data"]["attributes"]["key"] != key:
        return None

    cache_date = datetime.strptime(res_data["meta"]["ts"], "%Y-%m-%dT%H:%M:%S.%fZ")
    now = datetime.now()
    cache_age = now - cache_date
    if cache_age.seconds > refresh_cache_period_s:
        return None

    return res_data


# Cryptographically verify the response signature using the provided verify key
def _verify_cache_integrity(
    account_id: str,
    keygen_verify_key: str,
    signature,
    date_header,
    response_body,
) -> bool:
    digest_bytes = base64.b64encode(hashlib.sha256(response_body.encode()).digest())
    signing_data = "\n".join(
        [
            f"(request-target): post /v1/accounts/{account_id}/licenses/actions/validate-key",
            "host: api.keygen.sh",
            f"date: {date_header}",
            f"digest: sha-256={digest_bytes.decode()}",
        ]
    )

    verify_key = ed25519.VerifyingKey(keygen_verify_key.encode(), encoding="hex")

    try:
        verify_key.verify(signature, signing_data.encode(), encoding="base64")
    except ed25519.BadSignatureError:
        return False
    return True
