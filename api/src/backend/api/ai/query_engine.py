"""AI-Native Security Query Engine.

Translates natural language security questions into Cypher queries,
executes them against the Neo4j security graph, and returns
AI-explained results with actionable recommendations.
"""

from dataclasses import dataclass, field
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@dataclass
class SecurityQuery:
    natural_language: str
    generated_cypher: str
    explanation: str
    results: list[dict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    risk_summary: str = ""


# Pre-built query templates for common security questions
QUERY_TEMPLATES = {
    "internet_to_database": {
        "patterns": ["path from internet to database", "internet.*database", "public.*rds", "exposed.*db"],
        "cypher": """
            MATCH path = (internet:Internet)-[*1..5]->(db)
            WHERE db:RDSInstance OR db:AzureSQLServer OR db:GCPCloudSQLInstance
            RETURN path, db.id AS database_id, length(path) AS hops
            ORDER BY hops ASC LIMIT 10
        """,
        "explanation": "Shows all network paths from the internet that can reach database instances.",
    },
    "admin_unused": {
        "patterns": ["admin.*unused", "admin.*not used", "inactive.*admin", "stale.*privileged"],
        "cypher": """
            MATCH (u:AWSUser)-[:POLICY|MEMBER_AWS_GROUP*1..2]->(p:AWSPolicy)-[:STATEMENT]->(s:AWSPolicyStatement)
            WHERE s.effect = 'Allow' AND '*' IN s.action
            OPTIONAL MATCH (u)-[:AWS_ACCESS_KEY]->(k:AccountAccessKey)
            WHERE k.last_used_date < datetime() - duration('P90D')
            RETURN u.name AS user, u.arn AS arn, k.last_used_date AS last_active
            ORDER BY last_active ASC
        """,
        "explanation": "Identifies admin-level users whose credentials haven't been used in 90+ days.",
    },
    "public_sensitive_data": {
        "patterns": ["public.*sensitive", "exposed.*pii", "public.*data", "open.*bucket.*sensitive"],
        "cypher": """
            MATCH (s3:S3Bucket)-[:TAGGED]->(t:AWSTag)
            WHERE s3.anonymous_access = true
              AND toLower(t.key) IN ['classification', 'dataclassification', 'sensitivity']
              AND toLower(t.value) IN ['sensitive', 'confidential', 'pii', 'phi', 'pci']
            RETURN s3.name AS bucket, t.key + '=' + t.value AS classification,
                   s3.region AS region
        """,
        "explanation": "Finds publicly accessible storage containing tagged sensitive data.",
    },
    "lateral_movement": {
        "patterns": ["lateral movement", "role chain", "privilege escalation path", "hop.*role"],
        "cypher": """
            MATCH path = (ec2:EC2Instance)-[:STS_ASSUMEROLE_ALLOW*2..5]->(target:AWSRole)
            WHERE ec2.exposed_internet = true
            RETURN ec2.instanceid AS source,
                   [n IN nodes(path) | n.name] AS chain,
                   target.arn AS destination,
                   length(path) AS hops
            ORDER BY hops DESC LIMIT 20
        """,
        "explanation": "Maps multi-hop role assumption chains from internet-exposed instances.",
    },
    "blast_radius": {
        "patterns": ["blast radius", "impact.*compromise", "what.*access", "damage.*if"],
        "cypher": """
            MATCH (target)-[r*1..3]->(resource)
            WHERE target.id = $resource_id
            RETURN labels(resource)[0] AS resource_type,
                   count(resource) AS count,
                   collect(resource.id)[..5] AS examples
            ORDER BY count DESC
        """,
        "explanation": "Shows all resources reachable from a compromised resource within 3 hops.",
    },
    "compliance_gaps": {
        "patterns": ["compliance", "cis.*fail", "non-compliant", "violation"],
        "cypher": """
            MATCH (pf:ProwlerFinding {status: 'FAIL'})
            RETURN pf.check_id AS check,
                   pf.severity AS severity,
                   count(*) AS count
            ORDER BY count DESC LIMIT 20
        """,
        "explanation": "Lists the most common compliance failures across your environment.",
    },
}


def match_query_template(question: str) -> dict | None:
    """Match a natural language question to a pre-built template."""
    import re
    question_lower = question.lower()
    for template_id, template in QUERY_TEMPLATES.items():
        for pattern in template["patterns"]:
            if re.search(pattern, question_lower):
                return template
    return None


def build_llm_prompt(question: str, schema_context: str = "") -> str:
    """Build prompt for LLM to generate Cypher query."""
    return f"""You are a cloud security expert. Generate a Neo4j Cypher query to answer this security question.

Graph Schema (key node types and relationships):
- (AWSAccount)-[:RESOURCE]->(EC2Instance, S3Bucket, RDSInstance, AWSRole, AWSUser)
- (EC2Instance)-[:STS_ASSUMEROLE_ALLOW]->(AWSRole)
- (EC2Instance)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(EC2SecurityGroup)
- (AWSRole)-[:POLICY]->(AWSPolicy)-[:STATEMENT]->(AWSPolicyStatement)
- (S3Bucket)-[:TAGGED]->(AWSTag)
- (Internet)-[:CAN_ACCESS]->(EC2Instance) [when exposed_internet=true]
- (ProwlerFinding)-[:AFFECTS]->(any resource) [status: PASS/FAIL]
- (AzureSubscription)-[:RESOURCE]->(VirtualMachine, AzureSQLServer, AzureStorageAccount)
- (GCPProject)-[:RESOURCE]->(GCPInstance, GCPBucket, GKECluster)

Key properties:
- EC2Instance: instanceid, exposed_internet, region
- S3Bucket: name, anonymous_access, region
- AWSRole: arn, name
- ProwlerFinding: check_id, severity, status, resource_uid

Question: {question}

Rules:
1. Use MATCH with specific node labels
2. Always LIMIT results (max 50)
3. Return human-readable field names
4. Never use DETACH DELETE or any write operations
5. Prefer paths for attack chain questions

Respond with ONLY the Cypher query, no explanation."""


def generate_risk_summary(results: list[dict], question: str) -> str:
    """Generate a human-readable risk summary from query results."""
    if not results:
        return "No findings match your query. Your environment appears secure for this specific check."

    count = len(results)
    return f"Found {count} result(s) matching your security query. Review the details below for actionable insights."


def generate_recommendations(results: list[dict], query_type: str) -> list[str]:
    """Generate actionable recommendations based on query results."""
    recs = []
    if not results:
        return ["No immediate action required for this query."]

    if query_type == "internet_to_database":
        recs.append("Remove direct internet paths to databases — use private subnets + bastion/VPN")
        recs.append("Enable RDS/SQL encryption in transit (require SSL)")
    elif query_type == "admin_unused":
        recs.append("Disable or delete credentials unused for 90+ days")
        recs.append("Implement automated credential rotation policy")
    elif query_type == "public_sensitive_data":
        recs.append("URGENT: Remove public access from buckets containing sensitive data")
        recs.append("Enable S3 Block Public Access at account level")
    elif query_type == "lateral_movement":
        recs.append("Break role assumption chains — apply permission boundaries")
        recs.append("Restrict AssumeRole to specific source ARNs")
    else:
        recs.append("Review findings and apply least-privilege principle")

    return recs
