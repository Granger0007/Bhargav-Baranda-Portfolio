"""Lab 013: prioritise Trivy findings with CISA KEV and FIRST EPSS.
Reads a Trivy JSON report and a local copy of the KEV catalogue.
Only network call: the FIRST EPSS API (scores only, no data about you is sent beyond CVE IDs)."""
import json, sys, urllib.request, urllib.error

trivy_file, kev_file = sys.argv[1], sys.argv[2]
use_epss = "--no-epss" not in sys.argv

report = json.load(open(trivy_file))
kev = {v["cveID"]: v for v in json.load(open(kev_file))["vulnerabilities"]}

findings = {}
for result in report.get("Results", []):
    for v in result.get("Vulnerabilities") or []:
        cve = v["VulnerabilityID"]
        f = findings.setdefault(cve, {"cve": cve, "severity": v.get("Severity", "UNKNOWN"),
                                       "packages": set(), "fixed": set(), "title": v.get("Title", "")})
        f["packages"].add(f'{v["PkgName"]} {v["InstalledVersion"]}')
        if v.get("FixedVersion"):
            f["fixed"].add(v["FixedVersion"])

epss = {}
if use_epss:
    cves = [c for c in findings if c.startswith("CVE-")]
    for i in range(0, len(cves), 50):
        url = "https://api.first.org/data/v1/epss?cve=" + ",".join(cves[i:i + 50])
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                for row in json.load(r).get("data", []):
                    epss[row["cve"]] = float(row["epss"])
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            print(f"EPSS lookup failed ({e}); continuing without EPSS", file=sys.stderr)
            break

def priority(f):
    if f["cve"] in kev:
        return "P1"
    if epss.get(f["cve"], 0) >= 0.50:
        return "P2"
    high = f["severity"] in ("CRITICAL", "HIGH")
    if high and epss.get(f["cve"], 0) >= 0.10:
        return "P2"
    if high:
        return "P3"
    return "P4"

order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
rows = sorted(findings.values(), key=lambda f: (order[priority(f)], -epss.get(f["cve"], 0)))
counts = {}
for f in rows:
    counts[priority(f)] = counts.get(priority(f), 0) + 1

print(f"Unique vulnerabilities: {len(rows)} | " + " | ".join(f"{p}: {counts.get(p, 0)}" for p in order))
print(f"{'PRI':<4} {'CVE':<20} {'SEV':<9} {'EPSS':>6} {'KEV':<4} {'FIX':<4} PACKAGE")
for f in rows:
    p = priority(f)
    if p == "P4" and "--all" not in sys.argv:
        continue
    e = epss.get(f["cve"])
    print(f"{p:<4} {f['cve']:<20} {f['severity']:<9} {('%.3f' % e) if e is not None else '  n/a':>6} "
          f"{'YES' if f['cve'] in kev else '-':<4} {'yes' if f['fixed'] else 'NO':<4} {', '.join(sorted(f['packages']))}")
