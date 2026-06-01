import { Metadata } from "next";

export const metadata: Metadata = {
  title: "Toxic Combinations | Prowler",
  description: "Detect critical risk patterns across your cloud environment",
};

export default function ToxicCombinationsPage() {
  return (
    <div className="flex flex-col gap-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Toxic Combinations</h1>
        <p className="text-gray-600 dark:text-gray-400 mt-1">
          Critical risk patterns where multiple conditions combine to create
          severe security exposure.
        </p>
      </div>
      <ToxicCombinationsList />
    </div>
  );
}

function ToxicCombinationsList() {
  const combinations = [
    {
      id: "tc-aws-public-vuln-privileged",
      name: "Public + Vulnerable + High Privileges (AWS)",
      severity: "critical",
      providers: ["aws"],
      conditions: [
        "Internet-exposed",
        "Has vulnerabilities",
        "High-privilege role",
      ],
      description:
        "EC2 instance exposed to internet with known vulnerabilities and high-privilege IAM role.",
    },
    {
      id: "tc-azure-public-vuln-privileged",
      name: "Public + Vulnerable + High Privileges (Azure)",
      severity: "critical",
      providers: ["azure"],
      conditions: [
        "Internet-exposed VM",
        "Has findings",
        "Owner/Contributor role",
      ],
      description:
        "Azure VM exposed to internet with security findings and high-privilege role assignment.",
    },
    {
      id: "tc-gcp-public-vuln-privileged",
      name: "Public + Vulnerable + High Privileges (GCP)",
      severity: "critical",
      providers: ["gcp"],
      conditions: [
        "External IP",
        "Has findings",
        "Editor/Owner service account",
      ],
      description:
        "GCP instance with external IP, findings, and broad service account permissions.",
    },
    {
      id: "tc-aws-lateral-movement",
      name: "Lateral Movement Path (AWS)",
      severity: "high",
      providers: ["aws"],
      conditions: [
        "Internet-exposed EC2",
        "Multi-hop role chain",
        "Reaches admin/cross-account",
      ],
      description:
        "Chain of role assumptions from internet-exposed instance reaching admin roles.",
    },
    {
      id: "tc-aws-data-exfiltration",
      name: "Data Exfiltration Path (AWS)",
      severity: "high",
      providers: ["aws"],
      conditions: [
        "Internet-exposed",
        "Can access S3",
        "S3 has sensitive data",
      ],
      description:
        "Identity with access to sensitive S3 buckets via internet-facing resource.",
    },
    {
      id: "tc-azure-unencrypted-public-storage",
      name: "Unencrypted Public Storage (Azure)",
      severity: "high",
      providers: ["azure"],
      conditions: ["Public blob container", "No HTTPS-only", "Has findings"],
      description: "Storage with public containers lacking encryption.",
    },
  ];

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
      {combinations.map((tc) => (
        <div
          key={tc.id}
          className="border rounded-lg p-4 hover:shadow-md transition-shadow bg-white dark:bg-gray-800"
        >
          <div className="flex items-center justify-between mb-2">
            <span
              className={`px-2 py-0.5 rounded text-xs font-medium text-white ${
                tc.severity === "critical" ? "bg-red-600" : "bg-orange-500"
              }`}
            >
              {tc.severity}
            </span>
            <div className="flex gap-1">
              {tc.providers.map((p) => (
                <span
                  key={p}
                  className="px-1.5 py-0.5 rounded text-[10px] bg-gray-100 dark:bg-gray-700 font-mono"
                >
                  {p}
                </span>
              ))}
            </div>
          </div>
          <h3 className="font-semibold text-sm mb-1">{tc.name}</h3>
          <p className="text-xs text-gray-600 dark:text-gray-400 mb-3">
            {tc.description}
          </p>
          <div className="flex flex-wrap gap-1">
            {tc.conditions.map((c, i) => (
              <span
                key={i}
                className="px-2 py-0.5 rounded-full text-[10px] bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800"
              >
                {c}
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
