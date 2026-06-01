import { Metadata } from "next";

export const metadata: Metadata = { title: "Identity Risk | Prowler" };

export default function IdentitiesPage() {
  return (
    <div className="flex flex-col gap-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Identity Risk (CIEM)</h1>
        <p className="text-gray-600 dark:text-gray-400 mt-1">Over-privileged identities, unused credentials, and blast radius analysis.</p>
      </div>
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Total Identities" value="—" />
        <StatCard label="Over-Privileged" value="—" color="red" />
        <StatCard label="Unused Credentials" value="—" color="orange" />
        <StatCard label="Critical Risk" value="—" color="red" />
      </div>
      <div className="border rounded-lg p-4 bg-white dark:bg-gray-800">
        <p className="text-sm text-gray-500">Connect a cloud provider to start identity analysis.</p>
      </div>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: string; color?: string }) {
  const textColor = color === "red" ? "text-red-600" : color === "orange" ? "text-orange-600" : "text-gray-900 dark:text-white";
  return (
    <div className="border rounded-lg p-4 bg-white dark:bg-gray-800">
      <p className="text-xs text-gray-500 uppercase">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${textColor}`}>{value}</p>
    </div>
  );
}
