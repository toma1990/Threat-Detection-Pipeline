# Cloud Threat Detection Pipeline

A Python tool that monitors AWS CloudTrail logs in real time and 
flags suspicious activity across an AWS account.

## What it does

Connects to CloudWatch Logs and analyses CloudTrail events from 
the last 24 hours, looking for activity that shouldn't be happening 
in a normal account:

- Root account usage - should never happen in day to day operations
- Privilege escalation attempts - new users, policy attachments
- Audit trail tampering - anyone trying to delete or stop logging
- Unusual API call patterns - rapid fire calls suggesting automation

Generates timestamped JSON and HTML reports. The HTML report includes 
AI-powered threat analysis via AWS Bedrock that assesses whether 
findings represent a genuine threat and gives prioritised remediation 
steps.

## Why I built this

Alert fatigue is one of the biggest problems in security operations. 
I wanted to build something that not only detects suspicious activity 
but uses AI to give context around whether it's a real threat or 
just noise - something  that would actually help a SOC analyst 
triage faster.

## Tech used

- Python 3
- boto3 (AWS SDK)
- AWS CloudTrail
- AWS CloudWatch Logs
- AWS Bedrock (Claude Haiku) for AI threat analysis

## How to run it

Configure AWS CLI with credentials that have CloudTrail and 
CloudWatch Logs read access, then:

pip install boto3 markdown
python3 threat_detector.py

Reports are saved to the reports/ folder. The HTML report includes 
full AI threat analysis for any findings.

## What's next

Planning to add SNS alerting so findings trigger email notifications 
automatically, and Lambda integration so the tool runs on a schedule 
without needing to be triggered manually.
