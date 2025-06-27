import asyncio
import json
import boto3
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from ai21 import AsyncAI21Client
from strands import Agent, tool
from strands.models import BedrockModel
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# AI21 Configuration
API_KEY = os.getenv("AI21_API_KEY")
if not API_KEY:
    raise ValueError("AI21_API_KEY environment variable is required")
ai21_client = AsyncAI21Client(api_key=API_KEY)

# Define the prompts for different analysis types
security_hub_prompt = """You are an expert security analyst specializing in AWS Security Hub findings analysis and report generation.

You are given structured security findings data from AWS Security Hub. Extract and return a comprehensive security report with the following sections:

Executive Summary: Brief overview of the security posture
Severity Analysis: Breakdown of findings by severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)
Top Affected Resources: List of AWS resources with the most security findings
Common Issue Types: Most frequent types of security issues identified
Recent Activity: Analysis of new findings vs resolved findings
Recommended Actions: Prioritized list of remediation steps
Risk Assessment: Overall risk level and key concerns
"""

cloudtrail_prompt = """You are an expert security analyst specializing in AWS CloudTrail log analysis and threat detection.

You are given structured CloudTrail event data focusing on security-relevant activities. Extract and return a comprehensive security insights report with the following sections:

Executive Summary: Brief overview of account activity and security posture
High-Risk Activities: Analysis of potentially suspicious or high-risk events
User Activity Analysis: Breakdown of activities by users and roles
API Usage Patterns: Most frequent API calls and unusual patterns
Geographic Analysis: Login locations and geographic anomalies
Failed Operations: Analysis of failed API calls and authentication attempts
Recommended Actions: Security recommendations based on observed patterns
Threat Assessment: Overall threat level and areas of concern
"""

# Requirements for different analysis types
security_hub_requirements = [
    {"name": "markdown_format", "description": "Use proper markdown formatting with headers (##), bullet points, and code blocks for ARNs."},
    {"name": "include_all_metrics", "description": "Include all provided numerical data (severity counts, resource counts, finding types) in the analysis."},
    {"name": "prioritize_critical", "description": "Emphasize CRITICAL and HIGH severity findings as top priority items requiring immediate attention."},
    {"name": "actionable_recommendations", "description": "Provide specific, actionable remediation steps rather than generic advice."},
    {"name": "professional_tone", "description": "Use professional security analyst language appropriate for executive and technical audiences."},
    {"name": "structured_sections", "description": "Organize content into clear sections: Executive Summary, Severity Analysis, Top Resources, Issue Types, Recent Activity, Recommendations, Risk Assessment."},
    {"name": "concise_length", "description": "Keep the entire report under 300 words while maintaining completeness."},
    {"name": "no_assumptions", "description": "Base analysis strictly on the provided data without making assumptions about unlisted information."}
]

cloudtrail_requirements = [
    {"name": "markdown_format", "description": "Use proper markdown formatting with headers (##), bullet points, and numbered lists."},
    {"name": "highlight_risks", "description": "Emphasize high-risk activities and suspicious patterns that require immediate investigation."},
    {"name": "user_behavior_analysis", "description": "Analyze user activity patterns and identify any unusual or suspicious behavior."},
    {"name": "geographic_insights", "description": "Highlight any geographic anomalies or unusual login locations."},
    {"name": "failure_analysis", "description": "Focus on failed operations and authentication attempts as potential security indicators."},
    {"name": "actionable_security_steps", "description": "Provide specific security recommendations based on observed CloudTrail patterns."},
    {"name": "threat_assessment", "description": "Assess overall threat level based on the activity patterns and provide risk rating."},
    {"name": "concise_insights", "description": "Keep the report under 350 words while covering all key security insights."}
]

def get_all_findings(filters=None):
    """Retrieve all Security Hub findings with pagination support"""
    client = boto3.client("securityhub")
    findings = []
    kwargs = {'Filters': filters} if filters else {}
    
    resp = client.get_findings(**kwargs)
    findings.extend(resp['Findings'])
    
    while resp.get('NextToken'):
        resp = client.get_findings(**kwargs, NextToken=resp['NextToken'])
        findings.extend(resp['Findings'])
        
    return findings

def summarize_findings(findings):
    """Process and summarize Security Hub findings"""
    severity = Counter(f['Severity']['Label'] for f in findings)
    resources = Counter(f['Resources'][0]['Id'] for f in findings if f.get('Resources'))
    types = Counter(t for f in findings for t in f.get('FindingProviderFields', {}).get('Types', []))
    
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    recent = sum(datetime.fromisoformat(f['CreatedAt'][:-1]).replace(tzinfo=timezone.utc) > cutoff for f in findings)
    resolved = sum(f.get('Workflow', {}).get('Status') == 'RESOLVED' for f in findings)
    
    return {
        "severity": dict(severity),
        "top_resources": resources.most_common(5),
        "top_types": types.most_common(5),
        "recent_count": recent,
        "resolved_count": resolved
    }

def get_cloudtrail_events(hours_back=24):
    """Retrieve CloudTrail events for security analysis"""
    client = boto3.client("cloudtrail")
    events = []
    
    # Calculate time range using timezone-aware datetime
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours_back)
    
    # Get events with pagination
    kwargs = {
        'StartTime': start_time,
        'EndTime': end_time
    }
    
    resp = client.lookup_events(**kwargs)
    events.extend(resp['Events'])
    
    # Limit to 1000 events to avoid too much data
    while resp.get('NextToken') and len(events) < 1000:
        kwargs['NextToken'] = resp['NextToken']
        resp = client.lookup_events(**kwargs)
        events.extend(resp['Events'])
        # Remove NextToken for next iteration
        kwargs.pop('NextToken', None)
    
    return events[:1000]  # Ensure we don't exceed 1000 events

def analyze_cloudtrail_events(events):
    """Analyze CloudTrail events for security insights"""
    # High-risk event names to monitor
    high_risk_events = {
        'CreateUser', 'DeleteUser', 'AttachUserPolicy', 'DetachUserPolicy',
        'CreateRole', 'DeleteRole', 'AttachRolePolicy', 'DetachRolePolicy',
        'CreateAccessKey', 'DeleteAccessKey', 'CreateLoginProfile',
        'DeleteLoginProfile', 'ConsoleLogin', 'AssumeRole', 'GetSessionToken',
        'CreateBucket', 'DeleteBucket', 'PutBucketPolicy', 'DeleteBucketPolicy',
        'ModifyDBInstance', 'DeleteDBInstance', 'CreateDBInstance',
        'StopInstances', 'TerminateInstances', 'RunInstances'
    }
    
    # Count events by type
    event_names = Counter(event['EventName'] for event in events)
    
    # Count high-risk activities
    high_risk_activities = Counter(
        event['EventName'] for event in events 
        if event['EventName'] in high_risk_events
    )
    
    # Count activities by user
    user_activities = Counter(
        event.get('Username', 'Unknown') for event in events
    )
    
    # Count failed events
    failed_events = Counter(
        event['EventName'] for event in events 
        if event.get('ErrorCode') or event.get('ErrorMessage')
    )
    
    # Geographic analysis (source IP countries)
    source_ips = Counter(
        event.get('SourceIPAddress', 'Unknown') for event in events
        if event.get('SourceIPAddress') and not event.get('SourceIPAddress', '').startswith('AWS')
    )
    
    # Console logins analysis
    console_logins = [
        event for event in events 
        if event['EventName'] == 'ConsoleLogin'
    ]
    
    successful_logins = sum(1 for login in console_logins 
                          if login.get('ResponseElements', {}).get('ConsoleLogin') == 'Success')
    failed_logins = len(console_logins) - successful_logins
    
    return {
        "total_events": len(events),
        "high_risk_activities": dict(high_risk_activities.most_common(10)),
        "top_event_types": dict(event_names.most_common(10)),
        "top_users": dict(user_activities.most_common(10)),
        "failed_operations": dict(failed_events.most_common(10)),
        "top_source_ips": dict(source_ips.most_common(10)),
        "console_login_stats": {
            "successful": successful_logins,
            "failed": failed_logins,
            "total": len(console_logins)
        },
        "time_range_hours": 24
    }

def call_ai21_maestro_simple(prompt, requirements, data):
    """Simple synchronous call to AI21 Maestro"""
    requirements_str = "Requirements:\n" + "\n".join(["- " + req["description"] for req in requirements])
    run_input = f"""{prompt}

{requirements_str}

{data}"""
    
    # Use asyncio.run for simple execution
    async def run_maestro():
        run_result = await ai21_client.beta.maestro.runs.create_and_poll(
            input=run_input,
            models=["jamba-mini-1.6"],
            budget="low",
        )
        return run_result.result
    
    return asyncio.run(run_maestro())

@tool
def analyze_aws_security_hub() -> str:
    """
    Analyze AWS Security Hub findings and generate an AI-powered security report.
    
    This tool retrieves active security findings from AWS Security Hub, processes them,
    and uses AI21 Maestro to generate a comprehensive security analysis report.
    
    Returns:
        str: A comprehensive security analysis report in markdown format
    """
    try:
        # Get active findings from Security Hub
        findings = get_all_findings(filters={
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
        })
        
        # Process and summarize findings
        summary = summarize_findings(findings)
        
        # Format the input for Maestro
        findings_data = f"""Security Hub Findings Data:
{json.dumps(summary, indent=2)}"""
        
        # Call AI21 Maestro
        result = call_ai21_maestro_simple(security_hub_prompt, security_hub_requirements, findings_data)
        return f"## AWS Security Hub Analysis Report\n\n{result}"
        
    except Exception as e:
        return f"Error analyzing Security Hub findings: {str(e)}"

@tool
def analyze_aws_cloudtrail() -> str:
    """
    Analyze AWS CloudTrail events and generate an AI-powered security insights report.
    
    This tool retrieves CloudTrail events from the last 24 hours, analyzes them for
    security patterns, and uses AI21 Maestro to generate comprehensive security insights.
    
    Returns:
        str: A comprehensive CloudTrail security insights report in markdown format
    """
    try:
        # Get CloudTrail events from last 24 hours
        events = get_cloudtrail_events(hours_back=24)
        
        # Analyze events for security insights
        analysis = analyze_cloudtrail_events(events)
        
        # Format the input for Maestro
        cloudtrail_data = f"""CloudTrail Security Analysis Data:
{json.dumps(analysis, indent=2)}"""
        
        # Call AI21 Maestro
        result = call_ai21_maestro_simple(cloudtrail_prompt, cloudtrail_requirements, cloudtrail_data)
        return f"## AWS CloudTrail Security Insights Report\n\n{result}"
        
    except Exception as e:
        return f"Error analyzing CloudTrail events: {str(e)}"

# Create a Bedrock model instance
bedrock_model = BedrockModel(
    model_id="us.amazon.nova-premier-v1:0",
    region_name="us-east-1",
    temperature=0.1,
)

# Create the Strands agent with AWS security analysis tools
agent = Agent(
    tools=[
        analyze_aws_security_hub,
        analyze_aws_cloudtrail
    ],
    model=bedrock_model,
    system_prompt="""You are an expert AWS security analyst assistant powered by AI21 Maestro and Amazon Bedrock.

You have access to two powerful security analysis tools:
1. Analyze AWS Security Hub findings to assess security posture
2. Analyze CloudTrail events to detect suspicious activities and patterns

When users ask about AWS security, use the appropriate tool to provide detailed, actionable insights. Always explain what the analysis covers and provide specific recommendations based on the findings.

You can help with:
- Security Hub findings analysis and remediation guidance
- CloudTrail activity monitoring and threat detection
- Security best practices and recommendations
- Incident response guidance based on findings

Be proactive in suggesting which analysis would be most helpful based on the user's questions."""
)

if __name__ == "__main__":
    # Example usage with clean output handling
    print("AWS Security Analysis Agent powered by AI21 Maestro and Amazon Bedrock")
    print("Available commands:")
    print("- 'Analyze my Security Hub findings'")
    print("- 'Check CloudTrail for suspicious activity'") 
    print("- 'What security issues should I prioritize?'")
    print("\nType 'exit' to quit\n")
    
    while True:
        try:
            user_input = input("Security Analyst> ").strip()
            if user_input.lower() in ['exit', 'quit']:
                break
            if user_input:
                # Get the raw response from agent
                raw_response = agent(user_input)
                
                # Handle the response properly - extract only the text content
                if isinstance(raw_response, dict) and 'content' in raw_response:
                    content_list = raw_response['content']
                    if isinstance(content_list, list) and len(content_list) > 0:
                        first_item = content_list[0]
                        if isinstance(first_item, dict) and 'text' in first_item:
                            text = first_item['text']
                            # Remove thinking tags if present
                            if '<thinking>' in text and '</thinking>' in text:
                                text = text.split('</thinking>')[-1].strip()
                            print(f"\n{text}\n")
                        else:
                            print(f"\n{str(first_item)}\n")
                    else:
                        print(f"\n{str(content_list)}\n")
                elif hasattr(raw_response, 'message'):
                    print(f"\n{raw_response.message}\n")
                else:
                    print(f"\n{str(raw_response)}\n")
                    
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")
