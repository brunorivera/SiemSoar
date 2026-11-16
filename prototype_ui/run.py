"""Convenience launcher for the prototype (Windows-friendly).

Usage:
    cd prototype_ui
    python run.py
"""

from __future__ import annotations

import os

import uvicorn


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"SIEM/SOAR prototype -> http://127.0.0.1:{port}")
    uvicorn.run("backend.app:app", host="127.0.0.1", port=port, reload=False)
