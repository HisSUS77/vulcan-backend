from pathlib import Path


def has_grammar(name: str) -> bool:
    build = Path(__file__).resolve().parent.parent / "build"
    return (build / f"{name}.so").exists() or (build / f"{name}.dll").exists()
