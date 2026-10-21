"""Lets you run the current source with `python -m recontriage <target>` from
the project directory, with NO reinstall needed. Handy on macOS/iCloud where
editable installs misbehave: edit code, run again, see the change immediately.
The installed `recontriage` console script is for end users and demos."""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
