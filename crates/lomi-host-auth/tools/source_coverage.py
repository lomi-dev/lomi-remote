"""Reject missing Rust modules in the bounded local dependency source roots."""
from pathlib import Path, PurePosixPath

SOURCE_ROOTS = (
    "crates/lomi-host-auth/src",
    "crates/lomi-platform/src",
    "crates/lomi-remote-protocol/src",
    "crates/lomi-remote-crypto/src",
    "crates/lomi-remote-crypto/vendor/snow/src",
)


def check_source_coverage(repo: Path, names: list[str]) -> None:
    if len(names) != len(set(names)):
        raise RuntimeError("duplicate public source inventory entry")
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or str(path) != name:
            raise RuntimeError("noncanonical public source inventory entry")
        selected = repo / name
        if selected.is_symlink() or selected.resolve() != selected:
            raise RuntimeError("linked public source inventory entry")
    actual = set()
    for name in SOURCE_ROOTS:
        root = repo / name
        if root.is_symlink() or root.resolve() != root or not root.is_dir():
            raise RuntimeError("unsafe local dependency source root")
        # Do not traverse links. Reject directory links as well as file links,
        # rather than silently excluding a linked subtree from coverage.
        for path in root.rglob("*"):
            if path.is_symlink():
                raise RuntimeError("linked local dependency source entry")
            if path.is_file() and path.suffix == ".rs":
                actual.add(path.relative_to(repo).as_posix())
    selected = {
        name for name in names
        if name.endswith(".rs") and any(name.startswith(root + "/") for root in SOURCE_ROOTS)
    }
    if actual != selected:
        raise RuntimeError("local dependency Rust source inventory mismatch")
