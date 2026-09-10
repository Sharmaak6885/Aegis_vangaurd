import { NextResponse } from "next/server";
import fs from "fs";
import path from "path";

export async function GET() {
  try {
    const reportPath = path.resolve(process.cwd(), "..", "results", "report.html");
    
    if (!fs.existsSync(reportPath)) {
      return new NextResponse("Report not found. Please run a scan first.", { status: 404 });
    }

    const fileBuffer = fs.readFileSync(reportPath);

    return new NextResponse(fileBuffer, {
      headers: {
        "Content-Disposition": 'attachment; filename="Aegis_Vanguard_Security_Report.html"',
        "Content-Type": "text/html",
      },
    });
  } catch (error) {
    return new NextResponse("Error downloading report.", { status: 500 });
  }
}
