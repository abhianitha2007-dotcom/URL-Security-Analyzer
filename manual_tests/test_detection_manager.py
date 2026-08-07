from pprint import pprint

from analyzer.detection_manager import run_all_checks
from analyzer.risk_engine import calculate_risk


url ="https://google.com"

results = run_all_checks(url)

risk_score, verdict, reasons = calculate_risk(results)

print("\nRisk Score:", risk_score)
print("Verdict:", verdict)
print("Reasons:")

for reason in reasons:
    print("-", reason)

print("\nComplete Results:")
pprint(results)