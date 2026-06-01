import { Metadata } from "next";

export const metadata: Metadata = { title: "Threat Detection | Prowler" };

export default function ThreatsPage() {
  return (
    <div className="flex flex-col gap-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Threat Detection (CDR)</h1>
        <p className="text-gray-600 dark:text-gray-400 mt-1">Real-time cloud threat detection with MITRE ATT&CK mapping.</p>
      </div>
      <div className="grid grid-cols-4 gap-4">
        <div className="border rounded-lg p-4 bg-white dark:bg-gray-800">
          <p className="text-xs text-gray-500 uppercase">Active Rules</p>
          <p className="text-2xl font-bold mt-1">8</p>
        </div>
        <div className="border rounded-lg p-4 bg-white dark:bg-gray-800">
          <p className="text-xs text-gray-500 uppercase">Open Alerts</p>
          <p className="text-2xl font-bold mt-1 text-red-600">—</p>
        </div>
        <div className="border rounded-lg p-4 bg-white dark:bg-gray-800">
          <p className="text-xs text-gray-500 uppercase">Events/24h</p>
          <p className="text-2xl font-bold mt-1">—</p>
        </div>
        <div className="border rounded-lg p-4 bg-white dark:bg-gray-800">
          <p className="text-xs text-gray-500 uppercase">MITRE Coverage</p>
          <p className="text-2xl font-bold mt-1">6 tactics</p>
        </div>
      </div>
      <div className="border rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 dark:bg-gray-800">
            <tr>
              <th className="px-4 py-2 text-left">Rule</th>
              <th className="px-4 py-2 text-left">Severity</th>
              <th className="px-4 py-2 text-left">MITRE Tactic</th>
              <th className="px-4 py-2 text-left">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y dark:divide-gray-700">
            {[
              { name: "Root Account Login", severity: "critical", tactic: "Initial Access" },
              { name: "CloudTrail Stopped", severity: "critical", tactic: "Defense Evasion" },
              { name: "KMS Key Deleted", severity: "critical", tactic: "Impact" },
              { name: "IAM User Created", severity: "high", tactic: "Persistence" },
              { name: "Security Group Opened", severity: "high", tactic: "Defense Evasion" },
              { name: "S3 Bucket Made Public", severity: "high", tactic: "Exfiltration" },
              { name: "Cryptomining Activity", severity: "high", tactic: "Impact" },
              { name: "Unusual Region API Call", severity: "medium", tactic: "Discovery" },
            ].map((rule) => (
              <tr key={rule.name} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                <td className="px-4 py-2 font-medium">{rule.name}</td>
                <td className="px-4 py-2">
                  <span className={`px-2 py-0.5 rounded text-xs text-white ${rule.severity === "critical" ? "bg-red-600" : rule.severity === "high" ? "bg-orange-500" : "bg-yellow-500"}`}>
                    {rule.severity}
                  </span>
                </td>
                <td className="px-4 py-2 text-gray-600 dark:text-gray-400">{rule.tactic}</td>
                <td className="px-4 py-2"><span className="text-green-600">●</span> Active</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
