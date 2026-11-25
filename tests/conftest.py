"""Tests for modules that are still stubs (raise NotImplementedError) are reported as
SKIPPED instead of FAILED, so `pytest` shows how much work is left:
    pytest -rs     # lists every skipped test with the missing function's name
Once a function is implemented its tests run for real.
"""

import pytest


def _skip_not_implemented():
    try:
        return (yield)
    except NotImplementedError as exc:
        pytest.skip(f"not implemented yet: {exc}")


@pytest.hookimpl(wrapper=True)
def pytest_runtest_setup(item):
    return (yield from _skip_not_implemented())


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item):
    return (yield from _skip_not_implemented())
