"""Tests for the mutation harness itself (scripts/mutation_check.py).

The harness is the project's assurance mechanism, so its OWN safety semantics
must be tested, or a subtle harness bug could silently create false confidence in
every security claim it supposedly verifies.

These tests protect the focused-selector safety properties added in the selector
work: green-before, collection-error-is-not-a-kill, and node-id rebasing.
"""

import sys
import tempfile
from pathlib import Path

import pytest

# The harness lives in scripts/, not the package; import it by path.
_SCRIPTS = Path(__file__).resolve().parent.parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))
import mutation_check as mc  # noqa: E402


def test_pytest_target_rebases_node_ids_into_the_copy():
    """A selector must resolve inside the temp copy, not the live tree, or a
    mutation would be tested against unmutated source.

    Compare against an os-native path, since _pytest_target builds paths with
    pathlib (backslashes on Windows, forward slashes elsewhere).
    """
    copy = Path("/tmp/copy")
    t = mc._pytest_target(copy, ["capcore/tests/test_a.py::test_b"])
    expected = f"{copy / 'capcore' / 'tests' / 'test_a.py'}::test_b"
    assert t == [expected]


def test_pytest_target_without_selectors_targets_whole_tests_dir():
    copy = Path("/tmp/copy")
    t = mc._pytest_target(copy, None)
    assert t == [str(copy / "capcore" / "tests")]


def test_selectors_of_returns_none_without_a_fifth_element():
    assert mc._selectors_of(("name", "find", "replace")) is None
    assert mc._selectors_of(("name", "find", "replace", "file")) is None


def test_selectors_of_returns_declared_selectors():
    m = ("name", "find", "replace", "file", ("a::b", "c::d"))
    assert mc._selectors_of(m) == ("a::b", "c::d")


def test_unknown_selector_is_a_harness_error_not_a_kill():
    """A mispaired selector (pointing at a nonexistent test) must raise
    HarnessError, NOT be silently treated as a caught mutation. pytest returns a
    usage/collection exit code (>= 2), which run_suite must reject."""
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        mc.fresh_copy(base)
        with pytest.raises(mc.HarnessError):
            mc.run_suite(base, selectors=[
                "capcore/tests/test_review5_hardening.py::test_DOES_NOT_EXIST"])


def test_valid_selector_passes_green_before_on_unmutated_copy():
    """A correctly-paired selector passes on the unmutated copy (green-before),
    which is the precondition for trusting its red-after result."""
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        mc.fresh_copy(base)
        assert mc.run_suite(base, selectors=[
            "capcore/tests/test_review5_hardening.py::test_resource_str_subclass_is_rejected"
        ]) is True


def test_all_declared_selectors_are_wellformed_node_ids():
    """Every declared selector must look like a real pytest node id
    (file::test), never a bare string that tuple() would iterate into
    characters."""
    for m in mc.MUTATIONS:
        sels = mc._selectors_of(m)
        if sels is None:
            continue
        for s in sels:
            assert isinstance(s, str) and "::" in s and s.endswith(
                tuple(f"::{n}" for n in [s.split("::", 1)[1]])
            ), f"malformed selector on {m[0]}: {s!r}"
