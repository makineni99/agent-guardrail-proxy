import urllib.request, json
class AgentGuardrail:
    def __init__(self, api_key: str, base_url: str = "http://localhost:8080"):
        self.api_key, self.base_url = api_key, base_url.rstrip("/")
    def execute(self, tool_name: str, arguments: dict) -> dict:
        req = urllib.request.Request(f"{self.base_url}/v1/proxy/execute", data=json.dumps({"toolName": tool_name, "arguments": arguments}).encode(), headers={"Content-Type": "application/json", "x-api-key": self.api_key}, method="POST")
        try:
            with urllib.request.urlopen(req) as r: return json.loads(r.read().decode())
        except urllib.error.HTTPError as e: return json.loads(e.read().decode())
