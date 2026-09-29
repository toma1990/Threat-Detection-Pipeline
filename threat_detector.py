import boto3
import json
from datetime import datetime, timezone, timedelta

# Connect to CloudWatch Logs where CloudTrail sends events
logs = boto3.client('logs', region_name='eu-west-2')
sns = boto3.client('sns', region_name='eu-west-2')

# The log group we created in CloudTrail setup
LOG_GROUP = '/aws/cloudtrail/security'

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

if __name__ == "__main__":
    print("Starting threat detection scan...")
    print(f"Checking CloudTrail logs for last {LOOKBACK_HOURS} hours\n")
    
    events = get_recent_logs()
    print(f"Retrieved {len(events)} log events")
    
    findings = analyse_events(events)
    generate_report(findings)
