import json

with open("../results/findings.json", encoding="utf-8") as f:
    data = json.load(f)

# Filter out false positive file exposure findings and assign unique IDs
import uuid
cleaned = []
for finding in data["findings"]:
    if finding["category"] == "Information Disclosure" and "Accessible file:" in finding["title"]:
        evidence = finding.get("evidence", "")
        if "\ufffd" in evidence or "\x00" in evidence or "Content length: 2030" in evidence:
            continue
    # Ensure unique ID to fix React key duplicate errors
    finding["id"] = f"AS09-{str(uuid.uuid4())[:8]}"
    cleaned.append(finding)

data["findings"] = cleaned

# Recalculate
severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
deductions = 0
for f in cleaned:
    sev = f.get("severity", "info")
    counts[sev] = counts.get(sev, 0) + 1
    deductions += severity_weights.get(sev, 0)

score = max(0, 100 - deductions)
grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

data["executive_summary"]["security_score"] = {
    "score": score, "grade": grade, "total_findings": len(cleaned),
    "severity_counts": counts, "deductions": deductions
}

data["hardening"] = {"immediate": [], "short_term": [], "long_term": []}
data["executive_summary"]["key_risks"] = []

for f in sorted(cleaned, key=lambda x: ["critical","high","medium","low","info"].index(x.get("severity","info"))):
    sev = f.get("severity","info")
    if sev in ("critical","high"):
        data["executive_summary"]["key_risks"].append({"title":f["title"],"severity":sev,"category":f["category"]})
        data["hardening"]["immediate"].append({"finding_id":f["id"],"title":f["title"],"action":f["remediation"],"priority":"P0" if sev=="critical" else "P1"})
    elif sev == "medium":
        data["hardening"]["short_term"].append({"finding_id":f["id"],"title":f["title"],"action":f["remediation"],"priority":"P2"})
    else:
        data["hardening"]["long_term"].append({"finding_id":f["id"],"title":f["title"],"action":f["remediation"],"priority":"P3" if sev=="low" else "P4"})

for path in ["../results/findings.json", "../dashboard/public/data/findings.json"]:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

print(f"Cleaned: {86 - len(cleaned)} false positives removed")
print(f"Remaining: {len(cleaned)} findings")
print(f"Score: {score}/100 ({grade})")
cr = counts["critical"]
hi = counts["high"]
me = counts["medium"]
lo = counts["low"]
inf = counts["info"]
print(f"Critical: {cr}, High: {hi}, Medium: {me}, Low: {lo}, Info: {inf}")
