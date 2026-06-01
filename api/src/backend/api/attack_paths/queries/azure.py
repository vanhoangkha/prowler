from api.attack_paths.queries.types import (
    AttackPathsQueryDefinition,
)
from tasks.jobs.attack_paths.config import PROWLER_FINDING_LABEL


# Attack Path Queries
# -------------------

AZURE_PUBLIC_VM_HIGH_PRIVILEGE_ROLE = AttackPathsQueryDefinition(
    id="azure-public-vm-high-privilege-role",
    name="Internet-Exposed VM with High-Privilege Role Assignment",
    short_description="Find VMs exposed to the internet whose identities have Owner/Contributor roles.",
    description="Detect Azure Virtual Machines exposed to the internet (via public IP or load balancer) that have managed identity role assignments granting Owner, Contributor, or User Access Administrator permissions.",
    provider="azure",
    cypher=f"""
        MATCH path_vm = (sub:AzureSubscription)-[:RESOURCE]->(vm:VirtualMachine)
        WHERE vm.exposed_internet = true

        MATCH path_nic = (nic:AzureNetworkInterface)-[:ATTACHED_TO]->(vm)
        MATCH path_pip = (nic)-[:ASSOCIATED_WITH]->(pip:AzurePublicIPAddress)

        OPTIONAL MATCH path_role = (ra:AzureRoleAssignment)-[:ROLE_ASSIGNED]->(rd:AzureRoleDefinition)
        WHERE ra.principal_id = vm.identity_type
          AND rd.role_name IN ['Owner', 'Contributor', 'User Access Administrator']

        WITH collect(path_vm) + collect(path_nic) + collect(path_pip) + collect(path_role) AS paths
        UNWIND paths AS p
        UNWIND nodes(p) AS n

        WITH paths, collect(DISTINCT n) AS unique_nodes
        UNWIND unique_nodes AS n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

        RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
)

AZURE_NSG_OPEN_MANAGEMENT_PORTS = AttackPathsQueryDefinition(
    id="azure-nsg-open-management-ports",
    name="NSG Allowing Internet Access to Management Ports",
    short_description="Find NSGs with inbound rules allowing internet access to SSH/RDP.",
    description="Detect Network Security Groups with Allow rules from internet sources (*, Internet, 0.0.0.0/0) to management ports (22, 3389) that are attached to subnets or NICs with VMs.",
    provider="azure",
    cypher=f"""
        MATCH path_rule = (rule:AzureNetworkSecurityRule)-[:MEMBER_OF_AZURE_NSG]->(nsg:AzureNetworkSecurityGroup)
        WHERE rule.access = 'Allow'
          AND rule.direction = 'Inbound'
          AND (rule.source_address_prefix IN ['*', 'Internet', '0.0.0.0/0']
               OR ANY(src IN rule.source_address_prefixes WHERE src IN ['*', 'Internet', '0.0.0.0/0']))
          AND (rule.destination_port_range IN ['22', '3389', '*']
               OR ANY(p IN rule.destination_port_ranges WHERE p IN ['22', '3389', '*']))

        OPTIONAL MATCH path_subnet = (subnet:AzureSubnet)-[:ASSOCIATED_WITH]->(nsg)
        OPTIONAL MATCH path_nic = (nic:AzureNetworkInterface)-[:ASSOCIATED_WITH]->(nsg)
        OPTIONAL MATCH path_vm = (nic)-[:ATTACHED_TO]->(vm:VirtualMachine)

        WITH collect(path_rule) + collect(path_subnet) + collect(path_nic) + collect(path_vm) AS paths
        UNWIND paths AS p
        UNWIND nodes(p) AS n

        WITH paths, collect(DISTINCT n) AS unique_nodes
        UNWIND unique_nodes AS n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

        RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
)

AZURE_STORAGE_PUBLIC_ACCESS = AttackPathsQueryDefinition(
    id="azure-storage-public-access",
    name="Storage Accounts with Public Blob Containers",
    short_description="Find storage accounts containing blob containers with public access enabled.",
    description="Detect Azure Storage Accounts that have blob containers configured with public access (Blob or Container level), potentially exposing sensitive data.",
    provider="azure",
    cypher=f"""
        MATCH path = (sub:AzureSubscription)-[:RESOURCE]->(sa:AzureStorageAccount)
                     -[:USES]->(bs:AzureStorageBlobService)
                     -[:CONTAINS]->(bc:AzureStorageBlobContainer)
        WHERE bc.publicaccess IS NOT NULL AND bc.publicaccess <> 'None'

        WITH collect(path) AS paths
        UNWIND paths AS p
        UNWIND nodes(p) AS n

        WITH paths, collect(DISTINCT n) AS unique_nodes
        UNWIND unique_nodes AS n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

        RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
)

AZURE_SQL_FIREWALL_OPEN = AttackPathsQueryDefinition(
    id="azure-sql-firewall-open-internet",
    name="SQL Server with Firewall Open to Internet",
    short_description="Find SQL Servers with firewall rules allowing access from any IP.",
    description="Detect Azure SQL Servers with firewall rules that allow connections from the entire internet (0.0.0.0 to 255.255.255.255).",
    provider="azure",
    cypher=f"""
        MATCH path = (fw:AzureSQLServerFirewallRule)-[:MEMBER_OF_AZURE_SQL_SERVER]->(sql:AzureSQLServer)
        WHERE fw.start_ip_address = '0.0.0.0' AND fw.end_ip_address = '255.255.255.255'

        WITH collect(path) AS paths
        UNWIND paths AS p
        UNWIND nodes(p) AS n

        WITH paths, collect(DISTINCT n) AS unique_nodes
        UNWIND unique_nodes AS n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

        RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
)

AZURE_KEY_VAULT_INVENTORY = AttackPathsQueryDefinition(
    id="azure-key-vault-inventory",
    name="Key Vault Inventory",
    short_description="List all Key Vaults with their secrets, keys, and certificates.",
    description="Inventory of Azure Key Vaults and their contained secrets, keys, and certificates.",
    provider="azure",
    cypher=f"""
        MATCH path = (sub:AzureSubscription)-[:RESOURCE]->(kv:AzureKeyVault)
                     -[:CONTAINS]->(item)
        WHERE item:AzureKeyVaultSecret OR item:AzureKeyVaultKey OR item:AzureKeyVaultCertificate

        WITH collect(path) AS paths
        UNWIND paths AS p
        UNWIND nodes(p) AS n

        WITH paths, collect(DISTINCT n) AS unique_nodes
        UNWIND unique_nodes AS n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

        RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
)

AZURE_VM_INVENTORY = AttackPathsQueryDefinition(
    id="azure-vm-inventory",
    name="Virtual Machines Inventory",
    short_description="List all Virtual Machines in the tenant.",
    description="List Azure Virtual Machines with their network interfaces and public IPs.",
    provider="azure",
    cypher=f"""
        MATCH path = (sub:AzureSubscription)-[:RESOURCE]->(vm:VirtualMachine)

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
AZURE_QUERIES: list[AttackPathsQueryDefinition] = [
    AZURE_PUBLIC_VM_HIGH_PRIVILEGE_ROLE,
    AZURE_NSG_OPEN_MANAGEMENT_PORTS,
    AZURE_STORAGE_PUBLIC_ACCESS,
    AZURE_SQL_FIREWALL_OPEN,
    AZURE_KEY_VAULT_INVENTORY,
    AZURE_VM_INVENTORY,
]
