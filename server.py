import os
from fastmcp import FastMCP

mcp = FastMCP("workable-fastmcp")

@mcp.tool()
def echo(text: str) -> str:
    """Echo back the input text."""
    return text

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    mcp.run(transport="http", host="0.0.0.0", port=port)
