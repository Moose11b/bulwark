"""Run the Siege Tower app: `python -m server` (or `siege-tower-server`)."""
import os


def main() -> None:
    import uvicorn
    uvicorn.run(
        "server.app:app",
        host=os.environ.get("SIEGE_HOST", "127.0.0.1"),
        port=int(os.environ.get("SIEGE_PORT", "8000")),
        reload=bool(os.environ.get("SIEGE_RELOAD")),
    )


if __name__ == "__main__":
    main()
