"""Auto-analysis: run every registered check that applies to a given file."""
from sectoolkit.registry import applicable_checks, all_checks


def analyze_file(filepath: str) -> dict:
    """Run all applicable checks against a file and return their results.

    Returns a dict: {check_name: result}. If a check raises an exception,
    its result is recorded as {"error": str(exception)} instead of crashing
    the whole analysis — one broken check should not block the others.
    """
    results = {}
    for check in applicable_checks(filepath):
        try:
            results[check.name] = check.run(filepath)
        except Exception as exc:  # noqa: BLE001 - intentionally broad, see docstring
            results[check.name] = {"error": str(exc)}
    return results


def suggest_commands(filepath: str) -> list[str]:
    """List every registered check name that applies to this file.

    Useful for telling the user 'here's what else you could run manually'.
    """
    return [check.name for check in applicable_checks(filepath)]
