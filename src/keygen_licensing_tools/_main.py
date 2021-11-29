from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import ed25519
import requests

from ._helpers import safeget, string_to_dict


def _to_datetime(string):
    return datetime.strptime(string, "%Y-%m-%dT%H:%M:%S.%fZ")


def _api_call(account_id: str, key: str):
    return requests.post(
        f"https://api.keygen.sh/v1/accounts/{account_id}/licenses/actions/validate-key",
        headers={
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
        },
        data=json.dumps({"meta": {"key": key}}),
    )


def validate_license_key_online(account_id: str, key: str):
    res = _api_call(account_id, key)
    return _create_return_value(res.json())


def _create_return_value(data: dict | None):
    if data is None:
        return SimpleNamespace(
            is_valid=False,
            code="ERR",
            timestamp=None,
            license_creation_time=None,
            license_expiry_time=None,
        )

    meta = data["meta"]

    timestamp = meta.get("ts")
    if timestamp is not None:
        timestamp = _to_datetime(timestamp)

    if "errors" in data:
        code = None
        err = data["errors"][0]
        if "code" in err:
            code = err["code"]
        return SimpleNamespace(
            is_valid=False,
            code=code,
            timestamp=timestamp,
            license_creation_time=None,
            license_expiry_time=None,
        )

    is_valid = meta.get("valid", False)
    code = meta.get("constant")

    license_creation_time = safeget(data, "data", "attributes", "created")
    if isinstance(license_creation_time, str):
        license_creation_time = _to_datetime(license_creation_time)

    license_expiry_time = safeget(data, "data", "attributes", "expiry")
    if isinstance(license_expiry_time, str):
        license_expiry_time = _to_datetime(license_expiry_time)

    return SimpleNamespace(
        is_valid=is_valid,
        code=code,
        timestamp=timestamp,
        license_creation_time=license_creation_time,
        license_expiry_time=license_expiry_time,
    )


def validate_license_key_cached(
    account_id: str,
    key: str,
    keygen_verify_key: str,
    cache_path: Path | str,
    refresh_cache_period: timedelta | int,
):
    if isinstance(refresh_cache_period, int):
        refresh_cache_period = timedelta(seconds=refresh_cache_period)

    assert isinstance(refresh_cache_period, timedelta)

    data = _get_cache_data(account_id, key, keygen_verify_key, cache_path)

    cache_too_old = False
    if data is not None:
        cache_date = _to_datetime(data["meta"]["ts"])
        now = datetime.utcnow()
        cache_age = now - cache_date
        cache_too_old = cache_age > refresh_cache_period

    is_data_from_cache = True
    if data is None or cache_too_old:
        # fetch validation data
        try:
            res = _api_call(account_id, key)
        # except requests.exceptions.ConnectionError:
        except Exception:
            pass
        else:
            data = res.json()
            if "errors" not in data:
                is_data_from_cache = False

                # rewrite cache
                cache_data = {
                    "_warning": "Do not edit! Any change will invalidate the cache.",
                    "signature": string_to_dict(res.headers["Keygen-Signature"]),
                    "digest": res.headers["Digest"],
                    "date": res.headers["Date"],
                    "res": res.text,
                }
                with open(cache_path, "w") as f:
                    json.dump(cache_data, f, indent=2)

    out = _create_return_value(data)
    out.is_data_from_cache = is_data_from_cache
    return out


def _get_cache_data(
    account_id: str, key: str, keygen_verify_key: str, cache_path: Path | str
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
