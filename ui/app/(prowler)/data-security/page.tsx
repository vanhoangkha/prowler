import { Metadata } from "next";

export const metadata: Metadata = { title: "Data Security | Prowler" };

export default function DataSecurityPage() {
  return (
    <div className="flex flex-col gap-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Data Security (DSPM)</h1>
        <p className="text-gray-600 dark:text-gray-400 mt-1">Discover, classify, and protect sensitive data across cloud storage.</p>
      </div>
      <div className="grid grid-cols-4 gap-4">
        <div className="border rounded-lg p-4 bg-white dark:bg-gray-800">
          <p className="text-xs text-gray-500 uppercase">Data Stores</p>
          <p className="text-2xl font-bold mt-1">—</p>
        </div>
        <div className="border rounded-lg p-4 bg-white dark:bg-gray-800">
          <p className="text-xs text-gray-500 uppercase">Sensitive Data Found</p>
          <p className="text-2xl font-bold mt-1 text-red-600">—</p>
        </div>
        <div className="border rounded-lg p-4 bg-white dark:bg-gray-800">
          <p className="text-xs text-gray-500 uppercase">Public + Sensitive</p>
          <p className="text-2xl font-bold mt-1 text-red-600">—</p>
        </div>
        <div className="border rounded-lg p-4 bg-white dark:bg-gray-800">
          <p className="text-xs text-gray-500 uppercase">Unencrypted</p>
          <p className="text-2xl font-bold mt-1 text-orange-600">—</p>
        </div>
      </div>
      <div className="border rounded-lg p-4 bg-white dark:bg-gray-800">
        <p className="text-sm text-gray-500">Run a data classification scan to discover sensitive data in your cloud storage.</p>
      </div>
    </div>
  );
}
