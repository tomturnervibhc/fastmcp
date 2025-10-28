import os
from fastmcp import FastMCP

# Create FastMCP instance with host set for external access
mcp = FastMCP("workable-fastmcp", host="0.0.0.0")

@mcp.tool()
def echo(text: str) -> str:
    """Echo back the input text."""
    return text

if __name__ == "__main__":
    # Run the MCP server using HTTP transport; host is set, port determined automatically
    mcp.run(transport="http")
