"""Point the app at a throwaway SQLite database before it is imported."""
import os
import tempfile

_tmpdir = tempfile.mkdtemp(prefix="gauntlet-test-")
os.environ["GAUNTLET_DB_URL"] = f"sqlite:///{_tmpdir}/test.db"
os.environ["GAUNTLET_SEED"] = "1"
