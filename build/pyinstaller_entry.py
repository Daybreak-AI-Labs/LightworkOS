"""PyInstaller entry shim.

Wraps :func:`maverick.cli.main` so PyInstaller can produce a single-file
binary. Distributed via GitHub Releases for macOS / Linux / Windows.
"""
import sys

if __name__ == "__main__":
    # Divert the private read-only X11 worker before importing the dashboard.
    import multiprocessing

    multiprocessing.freeze_support()
    if len(sys.argv) == 3 and sys.argv[1] == "--recovery-rehearsal-worker":
        from maverick.recovery_rehearsal import main
        raise SystemExit(main([sys.argv[2]]))
    else:
        from maverick.cli import main
        main()
