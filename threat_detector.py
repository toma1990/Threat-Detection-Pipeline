import boto3
import json
from datetime import datetime, timezone, timedelta

# Connect to CloudWatch Logs where CloudTrail sends events
logs = boto3.client('logs', region_name='eu-west-2')
sns = boto3.client('sns', region_name='eu-west-2')

# The log group we created in CloudTrail setup
LOG_GROUP = '/aws/cloudtrail/security-v2'

# How far back to look for suspicious activity (in hours)
LOOKBACK_HOURS = 24

# Events that should never happen in a normal account
SUSPICIOUS_EVENTS = [
    'DeleteTrail',
    'StopLogging', 
    'DeleteFlowLogs',
    'ConsoleLoginFailure',
    'CreateUser',
    'AttachUserPolicy',
    'PutUserPolicy',
    'CreateAccessKey',
    'UpdateLoginProfile',
]

def get_recent_logs():
    # Calculate time window to search
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=LOOKBACK_HOURS)
    
    # Convert to milliseconds for CloudWatch API
    start_ms = int(start_time.timestamp() * 1000)
    end_ms = int(end_time.timestamp() * 1000)
    
    events = []
    
    try:
        # Get all log streams in the group
        streams = logs.describe_log_streams(
            logGroupName=LOG_GROUP,
            orderBy='LastEventTime',
            descending=True,
            limit=10
        )
        
        for stream in streams['logStreams']:
            response = logs.get_log_events(
                logGroupName=LOG_GROUP,
                logStreamName=stream['logStreamName'],
                startTime=start_ms,
                endTime=end_ms,
                limit=100
            )
            events.extend(response['events'])
            
    except Exception as e:
        print(f"Error retrieving logs: {e}")
        
    return events

def analyse_events(events):
    # Look through logs for anything suspicious
    findings = []
    
    for event in events:
        try:
            # CloudTrail logs are JSON inside the CloudWatch message
            message = json.loads(event['message'])
            
            # Handle both single events and batched records
            records = message.get('Records', [message])
            
            for record in records:
                event_name = record.get('eventName', '')
                event_time = record.get('eventTime', '')
                username = record.get('userIdentity', {}).get('userName', 'unknown')
                source_ip = record.get('sourceIPAddress', 'unknown')
                
                # Check if this event is on our suspicious list
                if event_name in SUSPICIOUS_EVENTS:
                    findings.append({
                        'EventName': event_name,
                        'Time': event_time,
                        'User': username,
                        'SourceIP': source_ip,
                        'Severity': get_severity(event_name)
                    })
                    
                # Root account usage is always suspicious
                if record.get('userIdentity', {}).get('type') == 'Root':
                    findings.append({
                        'EventName': f"ROOT_ACCOUNT_USED: {event_name}",
                        'Time': event_time,
                        'User': 'root',
                        'SourceIP': source_ip,
                        'Severity': 'CRITICAL'
                    })
                    
        except json.JSONDecodeError:
            # Skip any malformed log entries
            continue
            
    return findings

def get_severity(event_name):
    # Rank events by how dangerous they are
    critical = ['DeleteTrail', 'StopLogging', 'DeleteFlowLogs']
    high = ['CreateUser', 'AttachUserPolicy', 'PutUserPolicy', 'CreateAccessKey']
    
    if event_name in critical:
        return 'CRITICAL'
    elif event_name in high:
        return 'HIGH'
    else:
        return 'MEDIUM'

def generate_report(findings):
    # Save findings to JSON with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"threat_report_{timestamp}.json"
    
    report = {
        'ScanTime': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'LookbackHours': LOOKBACK_HOURS,
        'TotalFindings': len(findings),
        'Findings': findings
    }
    
    with open(filename, 'w') as f:
        json.dump(report, f, indent=4)
    
    print(f"\n=== Threat Detection Report ===")
    print(f"Scan time: {report['ScanTime']}")
    print(f"Period covered: last {LOOKBACK_HOURS} hours")
    print(f"Total findings: {len(findings)}")
    
    if findings:
        print("\nFindings:")
        for finding in findings:
            print(f"  [{finding['Severity']}] {finding['EventName']}")
            print(f"    User: {finding['User']}")
            print(f"    IP: {finding['SourceIP']}")
            print(f"    Time: {finding['Time']}")
    else:
        print("\nNo suspicious activity detected in the last 24 hours")
    
    print(f"\nFull report saved to: {filename}")

def get_ai_analysis(findings):
    # Use Bedrock to analyse findings and give threat context
    if not findings:
        return "No suspicious activity detected - nothing to analyse."
    
    bedrock = boto3.client('bedrock-runtime', region_name='eu-west-2')
    
    # Build summary of findings for the model
    findings_summary = []
    for f in findings:
        findings_summary.append(
            f"[{f['Severity']}] {f['EventName']} by {f['User']} from {f['SourceIP']} at {f['Time']}"
        )
    
    prompt = f"""You are a cloud security analyst reviewing AWS CloudTrail threat detection findings.

These suspicious events were detected in the last 24 hours:

{chr(10).join(findings_summary)}

Provide:
1. A brief threat assessment of what these findings indicate
2. Whether this looks like normal admin activity or a genuine threat
3. Specific recommended actions in priority order

Be concise and direct."""

    response = bedrock.invoke_model(
        modelId='eu.anthropic.claude-haiku-4-5-20251001-v1:0',
        body=json.dumps({
            'anthropic_version': 'bedrock-2023-05-31',
            'max_tokens': 1000,
            'messages': [{'role': 'user', 'content': prompt}]
        })
    )
    
    import re
    import markdown
    result = json.loads(response['body'].read())
    clean_text = re.sub(r'[^\x00-\x7F]+', '', result['content'][0]['text'])
    return markdown.markdown(clean_text)


def generate_html_report(findings, ai_analysis=""):
    # HTML version of the report - easier to read than JSON
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"threat_report_{timestamp}.html"
    
    html = f"""
<html>
<head>
    <title>Threat Detection Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #232f3e; }}
        .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; }}
        .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .CRITICAL {{ border-left: 5px solid #d13212; }}
        .HIGH {{ border-left: 5px solid #ff9900; }}
        .MEDIUM {{ border-left: 5px solid #f0b400; }}
        .severity-CRITICAL {{ color: #d13212; font-weight: bold; }}
        .severity-HIGH {{ color: #ff9900; font-weight: bold; }}
        .severity-MEDIUM {{ color: #f0b400; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>Threat Detection Report</h1>
    <div class="summary">
        <p>Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Period covered: last {LOOKBACK_HOURS} hours</p>
        <p>Total findings: {len(findings)}</p>
    </div>
"""

    if findings:
        for finding in findings:
            severity = finding['Severity']
            html += f"""
    <div class="finding {severity}">
        <span class="severity-{severity}">[{severity}]</span>
        <strong>{finding['EventName']}</strong>
        <p>User: {finding['User']}</p>
        <p>Source IP: {finding['SourceIP']}</p>
        <p>Time: {finding['Time']}</p>
    </div>
"""
    else:
        html += "<p>No suspicious activity detected in the last 24 hours</p>"

    if ai_analysis:
        html += f"""
    <div style="background:#eaf4fb;border-left:4px solid #2874a6;padding:15px;margin-top:20px;">
        <h2>AI Threat Analysis</h2>
        <div>{ai_analysis}</div>
    </div>
"""

    html += "</body></html>"

    with open(filename, 'w') as f:
        f.write(html)

    print(f"HTML report saved to: {filename}")

if __name__ == "__main__":
    print("Starting threat detection scan...")
    print(f"Checking CloudTrail logs for last {LOOKBACK_HOURS} hours\n")
    
    events = get_recent_logs()
    print(f"Retrieved {len(events)} log events")
    
    findings = analyse_events(events)
    ai_analysis = get_ai_analysis(findings)
    print("\n=== AI Threat Analysis ===")
    print(ai_analysis)
    generate_report(findings)
    generate_html_report(findings, ai_analysis)
