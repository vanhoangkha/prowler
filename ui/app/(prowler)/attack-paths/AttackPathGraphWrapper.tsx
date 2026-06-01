"use client";

import { AttackPathGraph } from "@/components/attack-paths/AttackPathGraph";

const SAMPLE_NODES = [
  { id: "internet", label: "Internet", type: "internet" as const, properties: {} },
  { id: "ec2-1", label: "web-server-prod", type: "resource" as const, properties: { instanceId: "i-0abc123", exposed_internet: true }, riskLevel: "critical" as const },
  { id: "role-1", label: "AdminRole", type: "identity" as const, properties: { arn: "arn:aws:iam::123:role/AdminRole" }, riskLevel: "high" as const },
  { id: "s3-1", label: "customer-data-prod", type: "resource" as const, properties: { bucket: "customer-data-prod", classification: "PII" }, riskLevel: "critical" as const },
  { id: "finding-1", label: "CVE-2024-1234", type: "finding" as const, properties: { severity: "CRITICAL", status: "FAIL" }, riskLevel: "critical" as const },
];

const SAMPLE_EDGES = [
  { id: "e1", source: "internet", target: "ec2-1", label: "SSH:22" },
  { id: "e2", source: "ec2-1", target: "role-1", label: "AssumeRole" },
  { id: "e3", source: "role-1", target: "s3-1", label: "s3:GetObject" },
  { id: "e4", source: "finding-1", target: "ec2-1", label: "AFFECTS" },
];

export function AttackPathGraphWrapper() {
  return (
    <AttackPathGraph
      nodes={SAMPLE_NODES}
      edges={SAMPLE_EDGES}
      title="Example: Internet → EC2 → AdminRole → Sensitive S3"
    />
  );
}
