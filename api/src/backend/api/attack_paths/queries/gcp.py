from api.attack_paths.queries.types import (
    AttackPathsQueryDefinition,
)
from tasks.jobs.attack_paths.config import PROWLER_FINDING_LABEL


# Attack Path Queries
# -------------------

GCP_PUBLIC_INSTANCE_DEFAULT_SERVICE_ACCOUNT = AttackPathsQueryDefinition(
    id="gcp-public-instance-default-service-account",
    name="Internet-Exposed Instance with Default Compute Service Account",
    short_description="Find GCP instances with external IPs using the default compute service account.",
    description="Detect GCP Compute instances exposed to the internet via external IP that are running with the default compute service account, granting broad project-level permissions.",
    provider="gcp",
    cypher=f"""
        MATCH path_instance = (proj:GCPProject)-[:RESOURCE]->(i:GCPInstance)
        WHERE i.exposed_internet = true

        MATCH path_sa = (i)-[:HAS_SERVICE_ACCOUNT]->(sa:GCPServiceAccount)
        WHERE sa.email ENDS WITH '-compute@developer.gserviceaccount.com'

        WITH collect(path_instance) + collect(path_sa) AS paths
        UNWIND paths AS p
        UNWIND nodes(p) AS n

        WITH paths, collect(DISTINCT n) AS unique_nodes
        UNWIND unique_nodes AS n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

        RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
)

GCP_FIREWALL_ALLOW_ALL_INGRESS = AttackPathsQueryDefinition(
    id="gcp-firewall-allow-all-ingress",
    name="Firewall Rule Allowing Internet Ingress to Sensitive Ports",
    short_description="Find firewall rules allowing 0.0.0.0/0 ingress to SSH, RDP, or database ports.",
    description="Detect GCP firewall rules that allow inbound traffic from 0.0.0.0/0 to sensitive ports (22, 3389, 3306, 5432), exposing instances to internet-based attacks.",
    provider="gcp",
    cypher=f"""
        MATCH path_fw = (proj:GCPProject)-[:RESOURCE]->(fw:GCPFirewall)
        WHERE fw.direction = 'INGRESS'
          AND '0.0.0.0/0' IN fw.source_ranges
          AND ANY(port IN fw.ports WHERE port IN ['22', '3389', '3306', '5432', 'all'])

        OPTIONAL MATCH path_vpc = (fw)-[:FIREWALL_RULE]->(vpc:GCPVpc)

        WITH collect(path_fw) + collect(path_vpc) AS paths
        UNWIND paths AS p
        UNWIND nodes(p) AS n

        WITH paths, collect(DISTINCT n) AS unique_nodes
        UNWIND unique_nodes AS n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

        RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
)

GCP_BUCKET_PUBLIC_ACCESS = AttackPathsQueryDefinition(
    id="gcp-bucket-public-access",
    name="GCS Bucket with Public Access",
    short_description="Find GCS buckets accessible to allUsers or allAuthenticatedUsers.",
    description="Detect GCS buckets with ACL entries granting access to allUsers or allAuthenticatedUsers, potentially exposing sensitive data to the public internet.",
    provider="gcp",
    cypher=f"""
        MATCH path = (proj:GCPProject)-[:RESOURCE]->(b:GCPBucket)
        WHERE ANY(acl IN b.acl WHERE acl IN ['allUsers', 'allAuthenticatedUsers'])

        WITH collect(path) AS paths
        UNWIND paths AS p
        UNWIND nodes(p) AS n

        WITH paths, collect(DISTINCT n) AS unique_nodes
        UNWIND unique_nodes AS n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

        RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
)

GCP_GKE_CLUSTER_PUBLIC_ENDPOINT = AttackPathsQueryDefinition(
    id="gcp-gke-cluster-public-endpoint",
    name="GKE Cluster with Public Endpoint",
    short_description="Find GKE clusters with internet-exposed API endpoints.",
    description="Detect GKE clusters with exposed_internet=true, indicating the Kubernetes API server is accessible from the public internet.",
    provider="gcp",
    cypher=f"""
        MATCH path = (proj:GCPProject)-[:RESOURCE]->(c:GKECluster)
        WHERE c.exposed_internet = true

        WITH collect(path) AS paths
        UNWIND paths AS p
        UNWIND nodes(p) AS n

        WITH paths, collect(DISTINCT n) AS unique_nodes
        UNWIND unique_nodes AS n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

        RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
)

GCP_SERVICE_ACCOUNT_KEY_INVENTORY = AttackPathsQueryDefinition(
    id="gcp-service-account-key-inventory",
    name="Service Accounts with User-Managed Keys",
    short_description="Find GCP service accounts that have user-managed keys.",
    description="Inventory of GCP service accounts with user-managed keys, which pose a credential leakage risk if not properly rotated or stored.",
    provider="gcp",
    cypher=f"""
        MATCH path = (proj:GCPProject)-[:RESOURCE]->(sa:GCPServiceAccount)
        WHERE sa.user_managed_keys_count > 0

        WITH collect(path) AS paths
        UNWIND paths AS p
        UNWIND nodes(p) AS n

        WITH paths, collect(DISTINCT n) AS unique_nodes
        UNWIND unique_nodes AS n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

        RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
)

GCP_INSTANCE_INVENTORY = AttackPathsQueryDefinition(
    id="gcp-instance-inventory",
    name="GCP Instances Inventory",
    short_description="List all GCP Compute instances.",
    description="Inventory of all GCP Compute instances within projects.",
    provider="gcp",
    cypher=f"""
        MATCH path = (proj:GCPProject)-[:RESOURCE]->(i:GCPInstance)

        WITH collect(path) AS paths
        UNWIND paths AS p
        UNWIND nodes(p) AS n

        WITH paths, collect(DISTINCT n) AS unique_nodes
        UNWIND unique_nodes AS n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

        RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
)


# Exported query list
GCP_QUERIES: list[AttackPathsQueryDefinition] = [
    GCP_PUBLIC_INSTANCE_DEFAULT_SERVICE_ACCOUNT,
    GCP_FIREWALL_ALLOW_ALL_INGRESS,
    GCP_BUCKET_PUBLIC_ACCESS,
    GCP_GKE_CLUSTER_PUBLIC_ENDPOINT,
    GCP_SERVICE_ACCOUNT_KEY_INVENTORY,
    GCP_INSTANCE_INVENTORY,
]
