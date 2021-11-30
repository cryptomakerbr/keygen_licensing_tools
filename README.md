# keygen_licensing_tools

[![PyPi Version](https://img.shields.io/pypi/v/keygen_licensing_tools.svg?style=flat-square)](https://pypi.org/project/keygen_licensing_tools/)
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/keygen_licensing_tools.svg?style=flat-square)](https://pypi.org/project/keygen_licensing_tools/)
[![GitHub stars](https://img.shields.io/github/stars/nschloe/keygen_licensing_tools.svg?style=flat-square&logo=github&label=Stars&logoColor=white)](https://github.com/nschloe/keygen_licensing_tools)
[![Downloads](https://pepy.tech/badge/keygen_licensing_tools/month?style=flat-square)](https://pepy.tech/project/keygen_licensing_tools)

[![gh-actions](https://img.shields.io/github/workflow/status/nschloe/keygen_licensing_tools/ci?style=flat-square)](https://github.com/nschloe/keygen_licensing_tools/actions?query=workflow%3Aci)
[![codecov](https://img.shields.io/codecov/c/github/nschloe/keygen_licensing_tools.svg?style=flat-square)](https://codecov.io/gh/nschloe/keygen_licensing_tools)
[![LGTM](https://img.shields.io/lgtm/grade/python/github/nschloe/keygen_licensing_tools.svg?style=flat-square)](https://lgtm.com/projects/g/nschloe/keygen_licensing_tools)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)](https://github.com/psf/black)

Some handy tools for the [Keygen](https://keygen.sh/) licensing service. (This
is a user contribution, not an official Keygen LLC product. For Keygen
software, see [here](https://github.com/keygen-sh).)

Install with

```
pip install keygen_licensing_tools
```

and use as

```python
import sys
from keygen_licensing_tools import validate_license_key_online, ValidationError

try:
    out = validate_license_key_online(
        account_id="demo", key="DEMO-DAD877-FCBF82-B83D5A-03E644-V3"
    )
except ValidationError as e:
    print(f"Error: Invalid license ({e.code}). Exiting.")
    sys.exit(1)
```

The `out` object contains useful information such as

```
out.code
out.timestamp
out.license_creation_time
out.license_expiry_time
```

The validation result can also be safely cached with

<!--pytest-codeblocks:skip-->

```python
import sys
from datetime import datetime, timedelta
from keygen_licensing_tools import validate_license_key_cached, ValidationError

try:
    out = validate_license_key_cached(
        account_id="your accound id",
        key="the license key",
        keygen_verify_key="your Ed25519 128-bit Verify Key",
        cache_path="/tmp/license-cache.json",
        refresh_cache_period=timedelta(days=3),
    )
except ValidationError as e:
    print(f"Error: Invalid license ({e.code}). Exiting.")
    sys.exit(1)

now = datetime.utcnow()
cache_age = now - out.timestamp
if cache_age > timedelta(days=3) and cache_age < timedelta(days=7):
    print("Warning: Could not validate license. Make sure to get online soon.")
elif cache_age > timedelta(days=7):
    print("Error: Could not validate license. Internet connection needed. Exiting.")
    sys.exit(1)
```

For _offline validation_, use

<!--pytest-codeblocks:skip-->

```python
from keygen_licensing_tools import validate_offline_key

license_scheme = (
    "ED25519_SIGN"  # or "RSA_2048_PKCS1_SIGN_V2", "RSA_2048_PKCS1_PSS_SIGN_V2"
)
keygen_verify_key = "your public verify key"
license_key = "your offline license key"

try:
    data = validate_offline_key(license_scheme, license_key, keygen_verify_key)
except ValidationError as e:
    print(f"Error: Invalid license ({e.code}). Exiting.")
    sys.exit(1)

print(data)
```

### Testing

To run the keygen_licensing_tools unit tests, check out this repository and do

```
tox
```

### License

This software is published under the [MIT
license](https://en.wikipedia.org/wiki/MIT_License).
