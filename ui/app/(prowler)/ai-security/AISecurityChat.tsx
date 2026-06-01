"use client";

import { useState, useRef, useEffect } from "react";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  cypher?: string;
  recommendations?: string[];
  timestamp: string;
}

const EXAMPLE_QUESTIONS = [
  "Show all paths from internet to our databases",
  "Which admin identities haven't been used in 90 days?",
  "Find public buckets with sensitive data",
  "What's the blast radius if EC2 i-abc123 is compromised?",
  "Show lateral movement paths from exposed instances",
  "List our top compliance gaps",
];

export function AISecurityChat() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSubmit = async (question: string) => {
    if (!question.trim()) return;
    const userMsg: Message = {
      id: crypto.randomUUID(),
      role: "user",
      content: question,
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    // Simulate AI response (replace with real API call)
    setTimeout(() => {
      const response = generateMockResponse(question);
      setMessages((prev) => [...prev, response]);
      setLoading(false);
    }, 1000);
  };

  return (
    <div className="flex flex-col flex-1 border rounded-lg overflow-hidden bg-white dark:bg-gray-900">
      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.length === 0 && (
          <div className="text-center py-12">
            <p className="text-gray-500 mb-6">Ask a security question to get started</p>
            <div className="grid grid-cols-2 gap-2 max-w-lg mx-auto">
              {EXAMPLE_QUESTIONS.map((q) => (
                <button
                  key={q}
                  onClick={() => handleSubmit(q)}
                  className="text-left text-xs p-3 rounded-lg border hover:bg-blue-50 dark:hover:bg-blue-900/20 transition-colors"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}
        {messages.map((msg) => (
          <div key={msg.id} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
            <div className={`max-w-[80%] rounded-lg p-3 ${
              msg.role === "user"
                ? "bg-blue-600 text-white"
                : "bg-gray-100 dark:bg-gray-800"
            }`}>
              <p className="text-sm whitespace-pre-wrap">{msg.content}</p>
              {msg.cypher && (
                <pre className="mt-2 p-2 bg-gray-900 text-green-400 rounded text-xs overflow-x-auto">
                  {msg.cypher}
                </pre>
              )}
              {msg.recommendations && msg.recommendations.length > 0 && (
                <div className="mt-2 border-t pt-2">
                  <p className="text-xs font-semibold mb-1">Recommendations:</p>
                  <ul className="text-xs space-y-1">
                    {msg.recommendations.map((r, i) => (
                      <li key={i}>• {r}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        ))}
        {loading && (
          <div className="flex justify-start">
            <div className="bg-gray-100 dark:bg-gray-800 rounded-lg p-3">
              <div className="flex space-x-1">
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" />
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce [animation-delay:0.1s]" />
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce [animation-delay:0.2s]" />
              </div>
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>
      {/* Input */}
      <div className="border-t p-3">
        <form onSubmit={(e) => { e.preventDefault(); handleSubmit(input); }} className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask a security question..."
            className="flex-1 px-4 py-2 border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-800"
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium disabled:opacity-50 hover:bg-blue-700"
          >
            Ask
          </button>
        </form>
      </div>
    </div>
  );
}

function generateMockResponse(question: string): Message {
  const q = question.toLowerCase();
  let content = "";
  let cypher = "";
  let recommendations: string[] = [];

  if (q.includes("internet") && q.includes("database")) {
    content = "Found potential attack paths from internet to databases. Here's the Cypher query to execute:";
    cypher = `MATCH path = (internet:Internet)-[*1..5]->(db)\nWHERE db:RDSInstance OR db:AzureSQLServer\nRETURN path, db.id AS database_id\nORDER BY length(path) ASC LIMIT 10`;
    recommendations = ["Remove direct internet paths to databases", "Use private subnets + bastion/VPN", "Enable encryption in transit"];
  } else if (q.includes("admin") && (q.includes("unused") || q.includes("90"))) {
    content = "Searching for stale admin credentials (inactive 90+ days):";
    cypher = `MATCH (u:AWSUser)-[:POLICY*1..2]->(p:AWSPolicy)-[:STATEMENT]->(s)\nWHERE '*' IN s.action\nOPTIONAL MATCH (u)-[:AWS_ACCESS_KEY]->(k)\nWHERE k.last_used_date < datetime() - duration('P90D')\nRETURN u.name, k.last_used_date`;
    recommendations = ["Disable credentials unused for 90+ days", "Implement automated rotation"];
  } else if (q.includes("public") && q.includes("sensitive")) {
    content = "Checking for publicly accessible storage with sensitive data:";
    cypher = `MATCH (s3:S3Bucket)-[:TAGGED]->(t:AWSTag)\nWHERE s3.anonymous_access = true\n  AND toLower(t.value) IN ['sensitive','pii','phi']\nRETURN s3.name, t.key + '=' + t.value AS classification`;
    recommendations = ["URGENT: Remove public access from sensitive buckets", "Enable S3 Block Public Access at account level"];
  } else if (q.includes("blast radius") || q.includes("compromise")) {
    content = "Computing blast radius for the specified resource:";
    cypher = `MATCH (target)-[r*1..3]->(resource)\nWHERE target.id = $resource_id\nRETURN labels(resource)[0] AS type, count(*) AS count\nORDER BY count DESC`;
    recommendations = ["Reduce permissions on this resource", "Add network segmentation"];
  } else if (q.includes("lateral") || q.includes("movement")) {
    content = "Mapping lateral movement paths from exposed instances:";
    cypher = `MATCH path = (ec2:EC2Instance)-[:STS_ASSUMEROLE_ALLOW*2..5]->(role:AWSRole)\nWHERE ec2.exposed_internet = true\nRETURN ec2.instanceid, [n IN nodes(path) | n.name] AS chain\nLIMIT 20`;
    recommendations = ["Break role assumption chains", "Apply permission boundaries", "Restrict AssumeRole to specific ARNs"];
  } else if (q.includes("compliance") || q.includes("gap")) {
    content = "Top compliance failures in your environment:";
    cypher = `MATCH (pf:ProwlerFinding {status: 'FAIL'})\nRETURN pf.check_id, pf.severity, count(*) AS count\nORDER BY count DESC LIMIT 20`;
    recommendations = ["Focus on critical/high severity findings first", "Enable automated remediation for common misconfigurations"];
  } else {
    content = `I'll generate a custom query for: "${question}"\n\nThis question requires LLM processing. The prompt has been prepared for your AI model (Claude/GPT via Bedrock).`;
    recommendations = ["Try one of the pre-built query templates for faster results"];
  }

  return {
    id: crypto.randomUUID(),
    role: "assistant",
    content,
    cypher: cypher || undefined,
    recommendations,
    timestamp: new Date().toISOString(),
  };
}
