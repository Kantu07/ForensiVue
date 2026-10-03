import pytest
import sys
from unittest.mock import patch
from forensivue.cli import main

def test_cli_serve_args():
    # Test that running 'serve' command doesn't crash on missing --audit-log
    test_args = ["forensivue", "serve", "--host", "127.0.0.1", "--port", "8000"]
    
    # We patch uvicorn.run so it doesn't actually start the server and hang the test
    with patch("sys.argv", test_args), patch("uvicorn.run") as mock_run:
        main()
        # Verify it called uvicorn run with correct args
        mock_run.assert_called_once_with("forensivue.api.main:app", host="127.0.0.1", port=8000, reload=False)
