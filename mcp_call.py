#!/usr/bin/env python3
"""Drive server.py over MCP stdio from the command line (for testing).

  mcp_call.py 'qemu_start image=0_4_3' 'break_add location=SystemInit' \\
              run_continue regs qemu_stop
Each argument is a tool call: NAME [key=value ...]; values are parsed as
JSON when possible (true, 5, "x"), else taken as strings.
"""
import json
import os
import shlex
import subprocess
import sys
import time

srv = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(
    os.path.abspath(__file__)), "server.py")], stdin=subprocess.PIPE,
    stdout=subprocess.PIPE, text=True, bufsize=1)
n = 0


def rpc(method, params=None):
    global n
    n += 1
    srv.stdin.write(json.dumps({"jsonrpc": "2.0", "id": n, "method": method,
                                "params": params or {}}) + "\n")
    srv.stdin.flush()
    return json.loads(srv.stdout.readline())


r = rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "mcp_call", "version": "0"}})
srv.stdin.write(json.dumps({"jsonrpc": "2.0",
                            "method": "notifications/initialized"}) + "\n")
if sys.argv[1:] == ["--list"]:
    for t in rpc("tools/list")["result"]["tools"]:
        print(f"{t['name']}: {t['description']}")
    sys.exit()
for call in sys.argv[1:]:
    name, *kv = shlex.split(call)
    if name == "sleep":
        time.sleep(float(kv[0]))
        continue
    args = {}
    for item in kv:
        k, _, v = item.partition("=")
        try:
            args[k] = json.loads(v)
        except ValueError:
            args[k] = v
    t = time.monotonic()
    r = rpc("tools/call", {"name": name, "arguments": args})
    res = r.get("result") or {}
    flag = " [ERROR]" if res.get("isError") or "error" in r else ""
    print(f"### {call}{flag} ({time.monotonic() - t:.1f}s)")
    print(res["content"][0]["text"] if res else r)
srv.stdin.close()
srv.wait(15)
