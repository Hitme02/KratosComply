#!/bin/bash
# Docker entrypoint script for KratosComply Agent

# Execute the CLI with all arguments
exec python -c "from agent.agent.cli import app; app()" "$@"

