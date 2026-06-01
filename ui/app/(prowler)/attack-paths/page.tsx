import { Metadata } from "next";
import { AttackPathGraphWrapper } from "./AttackPathGraphWrapper";

export const metadata: Metadata = {
  title: "Attack Paths | Prowler",
  description: "Visualize attack paths across your cloud infrastructure",
};

export default function AttackPathsPage() {
  return (
    <div className="flex flex-col gap-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Attack Paths</h1>
        <p className="text-gray-600 dark:text-gray-400 mt-1">
          Interactive visualization of attack paths discovered in your cloud environment.
        </p>
      </div>
      <div className="flex gap-2 text-sm">
        <button className="px-3 py-1.5 rounded-md bg-blue-600 text-white">All Providers</button>
        <button className="px-3 py-1.5 rounded-md bg-gray-100 dark:bg-gray-800">AWS</button>
        <button className="px-3 py-1.5 rounded-md bg-gray-100 dark:bg-gray-800">Azure</button>
        <button className="px-3 py-1.5 rounded-md bg-gray-100 dark:bg-gray-800">GCP</button>
      </div>
      <AttackPathGraphWrapper />
    </div>
  );
}
