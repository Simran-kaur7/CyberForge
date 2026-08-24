import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { z } from "zod";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const TOOLS_DIR = path.join(__dirname, "tools");

function runPythonTool(scriptName, args = []) {
  return new Promise((resolve, reject) => {
    const scriptPath = path.join(TOOLS_DIR, scriptName);

    const child = spawn("python3", [scriptPath, ...args], {
      cwd: TOOLS_DIR,
      stdio: ["ignore", "pipe", "pipe"]
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    child.on("error", reject);

    child.on("close", (code) => {
      if (code !== 0) {
        reject(
          new Error(
            `${scriptName} exited with code ${code}: ${stderr || stdout}`
          )
        );
        return;
      }

      try {
        resolve(JSON.parse(stdout));
      } catch {
        reject(
          new Error(
            `${scriptName} returned invalid JSON: ${stdout}`
          )
        );
      }
    });
  });
}

function textResult(data) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(data, null, 2)
      }
    ]
  };
}

serveStdio(() => {
  const server = new McpServer({
    name: "cyberforge-security-tools",
    version: "1.0.0"
  });

  server.registerTool(
    "search_security_logs",
    {
      title: "Search Security Logs",
      description:
        "Search CyberForge synthetic authentication logs for security events.",
      inputSchema: z.object({
        query: z
          .string()
          .optional()
          .describe("Text to search for in authentication logs.")
      })
    },
    async ({ query = "" }) => {
      const result = await runPythonTool(
        "search_security_logs.py",
        [query]
      );

      return textResult(result);
    }
  );

  server.registerTool(
    "analyze_evidence",
    {
      title: "Analyze Evidence",
      description:
        "Correlate authentication, process, and network evidence for an incident.",
      inputSchema: z.object({})
    },
    async () => {
      const result = await runPythonTool(
        "analyze_evidence.py"
      );

      return textResult(result);
    }
  );

  server.registerTool(
    "check_system_activity",
    {
      title: "Check System Activity",
      description:
        "Inspect synthetic process and network activity for suspicious behavior.",
      inputSchema: z.object({})
    },
    async () => {
      const result = await runPythonTool(
        "check_system_activity.py"
      );

      return textResult(result);
    }
  );

  server.registerTool(
    "block_ip",
    {
      title: "Block IP",
      description:
        "Simulate blocking an IP address in the CyberForge lab firewall. This is a write/destructive action and must require human approval in the agent configuration.",
      inputSchema: z.object({
        ip_address: z
          .string()
          .describe("IPv4 address to block.")
      })
    },
    async ({ ip_address }) => {
      const result = await runPythonTool(
        "block_ip.py",
        [ip_address]
      );

      return textResult(result);
    }
  );

  console.error("CyberForge MCP server started.");
  return server;
});