from fastmcp import FastMCP

mcp = FastMCP("workable-fastmcp")

@mcp.tool()
def echo(text: str) -> str:
    """Echo back the input text."""
    return text

if __name__ == "__main__":
    mcp.run(transport="sse")  # ✅ Supported transport
