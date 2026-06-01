from dataclasses import dataclass, field
from api.attack_paths.queries.types import AttackPathsQueryDefinition
from tasks.jobs.attack_paths.config import PROWLER_FINDING_LABEL


@dataclass
class ToxicCombination:
    id: str
    name: str
    description: str
    severity: str  # critical, high, medium
    providers: list[str]
    conditions: list[str]  # human-readable conditions
    cypher: str
    score_formula: str = "exploitability * impact * exposure"


# Toxic Combination Definitions

TC_PUBLIC_VULNERABLE_PRIVILEGED_AWS = ToxicCombination(
    id="tc-aws-public-vuln-privileged",
    name="Public + Vulnerable + High Privileges (AWS)",
    description="EC2 instance exposed to internet with known vulnerabilities and high-privilege IAM role attached. An attacker can exploit the vulnerability, gain access, then use the role for lateral movement.",
    severity="critical",
    providers=["aws"],
    conditions=["Internet-exposed (public IP or LB)", "Has Prowler FAIL findings", "Can assume high-privilege role"],
    cypher=f"""
        MATCH (aws:AWSAccount {{id: $provider_uid}})-[:RESOURCE]->(ec2:EC2Instance)
        WHERE ec2.exposed_internet = true
        MATCH (ec2)-[:STS_ASSUMEROLE_ALLOW]->(role:AWSRole)
        MATCH (role)-[:POLICY]->(pol:AWSPolicy)-[:STATEMENT]->(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow' AND ANY(a IN stmt.action WHERE a IN ['*', 'iam:*', 'sts:*'])
        MATCH (ec2)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})
        RETURN ec2, role, pol, pf,
               ec2.instanceid AS resource_id,
               role.name AS role_name,
               count(pf) AS finding_count
        ORDER BY finding_count DESC
    """,
)

TC_PUBLIC_VULNERABLE_PRIVILEGED_AZURE = ToxicCombination(
    id="tc-azure-public-vuln-privileged",
    name="Public + Vulnerable + High Privileges (Azure)",
    description="Azure VM exposed to internet with security findings and high-privilege role assignment. Attacker can exploit, access VM, then use managed identity for privilege escalation.",
    severity="critical",
    providers=["azure"],
    conditions=["Internet-exposed VM", "Has Prowler FAIL findings", "Has Owner/Contributor role"],
    cypher=f"""
        MATCH (sub:AzureSubscription)-[:RESOURCE]->(vm:VirtualMachine)
        WHERE vm.exposed_internet = true
        MATCH (vm)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})
        OPTIONAL MATCH (ra:AzureRoleAssignment)-[:ROLE_ASSIGNED]->(rd:AzureRoleDefinition)
        WHERE ra.principal_type = 'ServicePrincipal'
          AND rd.role_name IN ['Owner', 'Contributor', 'User Access Administrator']
        RETURN vm, ra, rd, pf,
               vm.name AS resource_id,
               rd.role_name AS role_name,
               count(pf) AS finding_count
        ORDER BY finding_count DESC
    """,
)

TC_PUBLIC_VULNERABLE_PRIVILEGED_GCP = ToxicCombination(
    id="tc-gcp-public-vuln-privileged",
    name="Public + Vulnerable + High Privileges (GCP)",
    description="GCP instance with external IP, security findings, and attached service account with broad permissions.",
    severity="critical",
    providers=["gcp"],
    conditions=["Has external IP", "Has Prowler FAIL findings", "Service account with editor/owner role"],
    cypher=f"""
        MATCH (proj:GCPProject)-[:RESOURCE]->(inst:GCPInstance)
        WHERE inst.exposed_internet = true
        MATCH (inst)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})
        OPTIONAL MATCH (inst)-[:USES_SERVICE_ACCOUNT]->(sa:GCPServiceAccount)
        OPTIONAL MATCH (binding:GCPPolicyBinding)-[:GRANTS_ROLE]->(role:GCPRole)
        WHERE binding.member CONTAINS sa.email
          AND role.name IN ['roles/owner', 'roles/editor', 'roles/iam.serviceAccountAdmin']
        RETURN inst, sa, role, pf,
               inst.id AS resource_id,
               sa.email AS service_account,
               count(pf) AS finding_count
        ORDER BY finding_count DESC
    """,
)

TC_LATERAL_MOVEMENT_AWS = ToxicCombination(
    id="tc-aws-lateral-movement",
    name="Lateral Movement Path (AWS)",
    description="Chain of role assumptions from an internet-exposed instance that can reach cross-account roles or sensitive services.",
    severity="high",
    providers=["aws"],
    conditions=["Internet-exposed EC2", "Multi-hop role assumption chain", "Reaches cross-account or admin role"],
    cypher=f"""
        MATCH (aws:AWSAccount {{id: $provider_uid}})-[:RESOURCE]->(ec2:EC2Instance)
        WHERE ec2.exposed_internet = true
        MATCH path = (ec2)-[:STS_ASSUMEROLE_ALLOW*2..5]->(target_role:AWSRole)
        WHERE target_role.arn CONTAINS ':role/Admin'
           OR NOT target_role.arn STARTS WITH 'arn:aws:iam::' + $provider_uid
        RETURN ec2.instanceid AS source,
               target_role.arn AS target,
               length(path) AS hops,
               [n IN nodes(path) | n.name] AS path_names
        ORDER BY hops ASC
        LIMIT 20
    """,
)

TC_DATA_EXFIL_AWS = ToxicCombination(
    id="tc-aws-data-exfiltration",
    name="Data Exfiltration Path (AWS)",
    description="Identity with access to S3 buckets containing sensitive data that also has internet-facing exposure.",
    severity="high",
    providers=["aws"],
    conditions=["Internet-exposed resource", "Can access S3", "S3 has sensitive data tags"],
    cypher=f"""
        MATCH (aws:AWSAccount {{id: $provider_uid}})-[:RESOURCE]->(ec2:EC2Instance)
        WHERE ec2.exposed_internet = true
        MATCH (ec2)-[:STS_ASSUMEROLE_ALLOW*1..3]->(role:AWSRole)
        MATCH (role)-[:POLICY]->(pol:AWSPolicy)-[:STATEMENT]->(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
          AND ANY(a IN stmt.action WHERE toLower(a) =~ 's3:(getobject|listbucket|\\*).*')
        MATCH (aws)-[:RESOURCE]->(s3:S3Bucket)-[:TAGGED]->(tag:AWSTag)
        WHERE toLower(tag.key) IN ['classification', 'dataclassification', 'sensitivity']
          AND toLower(tag.value) IN ['sensitive', 'confidential', 'pii', 'phi', 'pci']
          AND ANY(r IN stmt.resource WHERE r CONTAINS s3.name OR r = '*')
        RETURN ec2.instanceid AS entry_point,
               role.name AS via_role,
               s3.name AS target_bucket,
               tag.key + '=' + tag.value AS classification
        LIMIT 20
    """,
)

TC_UNENCRYPTED_DATA_PUBLIC = ToxicCombination(
    id="tc-azure-unencrypted-public-storage",
    name="Unencrypted Public Storage (Azure)",
    description="Azure Storage Account with public blob containers that lack encryption, potentially exposing sensitive data.",
    severity="high",
    providers=["azure"],
    conditions=["Public blob container", "Storage account without HTTPS-only", "Has Prowler findings"],
    cypher=f"""
        MATCH (sub:AzureSubscription)-[:RESOURCE]->(sa:AzureStorageAccount)
              -[:USES]->(bs:AzureStorageBlobService)
              -[:CONTAINS]->(bc:AzureStorageBlobContainer)
        WHERE bc.publicaccess IS NOT NULL AND bc.publicaccess <> 'None'
          AND sa.supportshttpstrafficonly = false
        OPTIONAL MATCH (sa)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})
        RETURN sa.name AS storage_account,
               bc.name AS container,
               bc.publicaccess AS access_level,
               count(pf) AS finding_count
        ORDER BY finding_count DESC
    """,
)


# Registry of all toxic combinations
TOXIC_COMBINATIONS: list[ToxicCombination] = [
    TC_PUBLIC_VULNERABLE_PRIVILEGED_AWS,
    TC_PUBLIC_VULNERABLE_PRIVILEGED_AZURE,
    TC_PUBLIC_VULNERABLE_PRIVILEGED_GCP,
    TC_LATERAL_MOVEMENT_AWS,
    TC_DATA_EXFIL_AWS,
    TC_UNENCRYPTED_DATA_PUBLIC,
]


def get_toxic_combinations_for_provider(provider: str) -> list[ToxicCombination]:
    """Get all toxic combinations applicable to a provider."""
    return [tc for tc in TOXIC_COMBINATIONS if provider in tc.providers]


def get_toxic_combination_by_id(tc_id: str) -> ToxicCombination | None:
    """Get a specific toxic combination by ID."""
    return next((tc for tc in TOXIC_COMBINATIONS if tc.id == tc_id), None)
