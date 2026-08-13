# sendgrid-mcp-secure — container for automated safety/quality checks (Glama) and general use.
# Dry-run is the DEFAULT: every tool works with no API key configured, nothing is ever sent.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE server.py ./
RUN pip install --no-cache-dir .

# Non-root: the server needs no privileges. Audit log lands in the workdir.
RUN useradd --create-home mcp && chown -R mcp:mcp /app
USER mcp

# stdio transport; SENDGRID_MCP_MODE defaults to dry-run inside the server —
# set SENDGRID_API_KEY + SENDGRID_MCP_MODE=live only when you mean it.
ENTRYPOINT ["sendgrid-mcp-secure"]
