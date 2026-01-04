"""Test script to debug ephemeral worker issues."""
import asyncio
import logging
from pathlib import Path
from ephemeral_worker import EphemeralWorker

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

async def test_scan():
    """Test ephemeral worker scan."""
    worker = EphemeralWorker()
    
    # Test with a public repo
    try:
        report = await worker.scan_repository(
            repo_url="https://github.com/octocat/Hello-World",
            access_token="test_token",  # Won't work but will show where it fails
            project_name="test-project"
        )
        print("Success!")
        print(f"Report has {len(report.get('findings', []))} findings")
    except Exception as e:
        logger.exception(f"Error: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(test_scan())

