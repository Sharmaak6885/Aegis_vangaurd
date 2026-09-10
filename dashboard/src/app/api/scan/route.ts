import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import path from "path";

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const target = searchParams.get("target") || "https://app.archscale.in";
  const modules = searchParams.get("modules") || "all";
  const threads = searchParams.get("threads") || "5";

  const scannerDir = path.resolve(process.cwd(), "..", "scanner");

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    start(controller) {
      const args = ["main.py", "--target", target, "--modules", modules, "--format", "both", "--threads", threads];
      
      const child = spawn("python", args, {
        cwd: scannerDir,
        env: { ...process.env, PYTHONIOENCODING: "utf-8" },
      });

      child.stdout.on("data", (data) => {
        const text = data.toString();
        const lines = text.split('\n');
        
        for (const line of lines) {
          if (!line.trim()) continue;
          
          let eventType = "log";
          let payload: any = { message: line };

          // Parse Python scanner output for structured events
          if (line.includes("Starting ") && line.includes(" scanner modules...")) {
            eventType = "start";
            const match = line.match(/Starting (\d+)/);
            if (match) payload.totalModules = parseInt(match[1]);
          } else if (line.match(/\[\d+\/\d+\] (OK|FAIL)/)) {
            eventType = "module_complete";
            const match = line.match(/\[(\d+)\/(\d+)\] (OK|FAIL) (.*?): (\d+) findings \(([\d\.]+)s\)/);
            if (match) {
              payload = {
                current: parseInt(match[1]),
                total: parseInt(match[2]),
                status: match[3],
                module: match[4],
                findingsCount: parseInt(match[5]),
                duration: parseFloat(match[6])
              };
            }
          } else if (line.includes("SCAN COMPLETE")) {
            eventType = "complete";
          }

          controller.enqueue(encoder.encode(`event: ${eventType}\ndata: ${JSON.stringify(payload)}\n\n`));
        }
      });

      child.stderr.on("data", (data) => {
        const text = data.toString();
        controller.enqueue(encoder.encode(`event: error\ndata: ${JSON.stringify({ message: text })}\n\n`));
      });

      child.on("close", (code) => {
        controller.enqueue(encoder.encode(`event: done\ndata: ${JSON.stringify({ code })}\n\n`));
        controller.close();
      });
      
      child.on("error", (error) => {
        controller.enqueue(encoder.encode(`event: error\ndata: ${JSON.stringify({ message: error.message })}\n\n`));
        controller.close();
      });

      // Handle client disconnect
      request.signal.addEventListener("abort", () => {
        child.kill();
        controller.close();
      });
    },
  });

  return new NextResponse(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
    },
  });
}
