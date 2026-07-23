# A minimal REAL stdio MCP server (newline-delimited JSON-RPC 2.0). It logs every
# tools/call it ACTUALLY receives to a file, so we can prove what reached it vs
# what the proxy blocked. It never executes anything (safe test double).
import sys, json
RECV = "/tmp/iw-mcp-e2e-received.log"
def send(o):
    sys.stdout.write(json.dumps(o) + "\n"); sys.stdout.flush()
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try: m = json.loads(line)
    except Exception: continue
    mid, method = m.get("id"), m.get("method")
    if method == "initialize":
        send({"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":"2024-11-05",
              "serverInfo":{"name":"test-mcp","version":"0.1"},"capabilities":{"tools":{}}}})
    elif method == "notifications/initialized":
        pass
    elif method == "tools/list":
        send({"jsonrpc":"2.0","id":mid,"result":{"tools":[{"name":"run",
              "description":"run a shell command","inputSchema":{"type":"object",
              "properties":{"command":{"type":"string"}}}}]}})
    elif method == "tools/call":
        cmd = (m.get("params") or {}).get("arguments",{}).get("command","")
        with open(RECV,"a") as f: f.write(cmd + "\n")   # what ACTUALLY reached the server
        send({"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text",
              "text":"executed: "+cmd}],"isError":False}})
    elif mid is not None:
        send({"jsonrpc":"2.0","id":mid,"result":{}})
