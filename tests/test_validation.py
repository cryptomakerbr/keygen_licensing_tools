import tempfile
from pathlib import Path

import pytest

import keygen_licensing_tools


# https://keygen.sh/demo/license-key-validation/
@pytest.mark.parametrize(
    "key, is_valid, code",
    [
        ("DEMO-DAD877-FCBF82-B83D5A-03E644-V3", True, "VALID"),
        ("X-DEMO-DAD877-FCBF82-B83D5A-03E644-V3", False, "NOT_FOUND"),
        ("DEMO-2233AF-72BF07-19CB6B-26EAEA-V3", False, "EXPIRED"),
        # Missing entitlements:
        ("DEMO-2D479F-C8C9C8-BD6A82-A6DB80-V3", True, "VALID"),
        ("DEMO-6EB0EA-54BE79-3679CD-6CFCAE-V3", False, "SUSPENDED"),
    ],
)
def test_validation(key, is_valid, code):
    account = "demo"
    out = keygen_licensing_tools.validate_license_key_online(account, key)
    assert out.is_valid == is_valid
    assert out.code == code


@pytest.mark.skip("Don't know demo account's verify key")
def test_cached_validation():
    account = "demo"
    key = "DEMO-DAD877-FCBF82-B83D5A-03E644-V3"
    # https://github.com/keygen-sh/example-python-offline-validation-caching/issues/2
    keygen_verify_key = "?"
    keygen_licensing_tools.validate_license_key_cached(
        account,
        key,
        keygen_verify_key,
        Path(tempfile.gettempdir()) / "demo-license-cache.json",
        refresh_cache_period_s=604800,
    )
