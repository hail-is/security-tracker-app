# For reference only: the original script that generated the alerts.csv file.
# For the current script that is wired into the CLI, see trivy/alerts.py

# import csv
# import json
# import jq
# from datetime import datetime, timedelta


# def date_plus(iso_date_string, days_to_add):
#     """
#     Parses an ISO date string, adds days, and formats it to a custom date string.

#     Args:
#         iso_date_string: The ISO date string to parse (e.g., "2023-10-26T12:00:00Z").
#         days_to_add: The number of days to add (can be positive or negative).
#         output_format: The desired output date format string (e.g., "%Y-%m-%d").

#     Returns:
#         The formatted date string, or None if parsing fails.
#     """
#     try:
#         date_object = datetime.fromisoformat(iso_date_string.replace("Z", "+00:00"))
#     except ValueError:
#         print("Error: Invalid ISO date string format.")
#         return None

#     modified_date = date_object + timedelta(days=days_to_add)
#     formatted_date = modified_date.strftime("%m/%d/%y")
#     return formatted_date


# fieldnames = [
#     "Alert ID",
#     "Controls",
#     "Weakness Name",
#     "Weakness Description",
#     "Weakness Detector Source",
#     "Weakness Source Identifier",
#     "Asset Identifier",
#     "Point of Contact",
#     "Resources Required",
#     "Overall Remediation Plan",
#     "Original Detection Date",
#     "Scheduled Completion Date",
#     "AGENCY Scheduled Completion Date",
#     "Planned Milestones",
#     "Milestone Changes",
#     "Status Date",
#     "Vendor Dependency",
#     "Last Vendor Check-in Date",
#     "Vendor Dependent Product Name",
#     "Original Risk Rating",
#     "Adjusted Risk Rating",
#     "Risk Adjustment",
#     "False Positive",
#     "Operational Requirement",
#     "Deviation Rationale",
#     "Supporting Documents",
#     "Comments",
#     "Auto-Approve",
#     "Binding Operational Directive 22-01 tracking",
#     "Binding Operational Directive 22-01 Due Date",
#     "CVE",
#     "Service Name",
# ]

# with open("alerts.json") as inf:
#     alerts_data = json.load(inf)

# alerts_jq = jq.compile("""
# .[] | { 
#     "_state": .state,
#     "POAM ID": .number, 
#     "Controls": "RA-5",
#     "Weakness Name": .rule.description,
#     "Weakness Description": .rule.full_description,
#     "Weakness Detector Source": .html_url,
#     "Weakness Source Identifier": (.tool.name + " " + .tool.version),
#     "Asset Identifier": .rule.most_recent_instance.location.path,
#     "Point of Contact": "Chris Llanwarne",
#     "Resources Required": "None",
#     "Overall Remediation Plan": "Perform necessary updates to resolve the vulnerability",
#     "Original Detection Date": .created_at,
#     "Status Date": .updated_at,
#     "Last Vendor Check-in Date": .rule.updated_at,
#     "Scheduled Completion Date": "DATE",
#     "AGENCY Scheduled Completion Date": "DATE",
#     "Planned Milestones": "DATE: Perform necessary updates to resolve the vulnerability",
#     "Milestone Changes": "",
#     "Vendor Dependency": "Yes",
#     "Vendor Dependent Product Name": "Ubuntu",
#     "Original Risk Rating": .rule.security_severity_level,
#     "Adjusted Risk Rating": "",
#     "Risk Adjustment": "",
#     "False Positive": "No",
#     "Operational Requirement": "No",
#     "Deviation Rationale": "",
#     "Supporting Documents": "",
#     "Comments": .most_recent_instance.message.text,
#     "Auto-Approve": "No",
#     "Binding Operational Directive 22-01 tracking": "",
#     "Binding Operational Directive 22-01 Due Date": "",
#     "CVE": .rule.id,
#     "Service Name": "Hail Batch"
# }""")

# jq_results = alerts_jq.input_value(alerts_data)
# rows: list[dict] = []

# for row in jq_results.all():
#     if row["Weakness Source Identifier"][:5] != "Trivy":
#         continue
#     state = row["_state"]
#     del row["_state"]
#     if state != "open":
#         continue
#     message = {
#         kv[0]: (kv[1] if len(kv) > 1 else "")
#         for kv in [line.split(": ") for line in row["Comments"].split("\n")]
#     }
#     if "Image" not in message:
#         print(message)
#         print(repr(row))
#     row["Asset Identifier"] = f"{message['Image']} ({message['Package']})"
#     orig_date = row["Original Detection Date"]
#     status_date = row["Status Date"]
#     sev = row["Original Risk Rating"]
#     fix_intervals = {"high": 14, "medium": 90, "low": 180}
#     fix_interval = fix_intervals.get(sev) or 0
#     fix_date = date_plus(orig_date, fix_interval)
#     row["Original Detection Date"] = date_plus(orig_date, 0)
#     row["Status Date"] = date_plus(status_date, 0)
#     row["Last Vendor Check-in Date"] = date_plus(status_date, 0)
#     row["Scheduled Completion Date"] = date_plus(orig_date, 0)
#     row["Original Detection Date"] = date_plus(orig_date, 0)
#     row["Scheduled Completion Date"] = fix_date
#     row["AGENCY Scheduled Completion Date"] = fix_date
#     row["Planned Milestones"] = row["Planned Milestones"].replace("DATE", fix_date)

#     rows.append(row)

# with open("gh-alerts.csv", "w", newline="") as csvfile:
#     writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
#     writer.writeheader()
#     writer.writerows(rows)
