import os
from fastmcp import FastMCP

# Create FastMCP instance with host set for external access
mcp = FastMCP("workable-fastmcp", host="0.0.0.0")

@mcp.tool()
def echo(text: str) -> str:
    """Echo back the input text."""
    return text

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    # Run the MCP server using HTTP transport on the provided port
    mcp.run(transport="http", port=port)
