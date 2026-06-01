import { Metadata } from "next";
import { AISecurityChat } from "./AISecurityChat";

export const metadata: Metadata = {
  title: "AI Security Assistant | Prowler",
  description: "Ask security questions in natural language",
};

export default function AISecurityPage() {
  return (
    <div className="flex flex-col gap-6 p-6 h-[calc(100vh-4rem)]">
      <div>
        <h1 className="text-2xl font-bold">AI Security Assistant</h1>
        <p className="text-gray-600 dark:text-gray-400 mt-1">
          Ask questions about your cloud security posture in natural language.
        </p>
      </div>
      <AISecurityChat />
    </div>
  );
}
