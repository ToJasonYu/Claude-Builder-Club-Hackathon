export interface Target {
  name: string;
  domain: string;
  sector: 'humanitarian' | 'environmental';
  mission: string;
  subdomains: string[];
  endpoints: string[];
  techStack: {
    platform: string;
    framework: string | null;
    isVibeCoded: boolean;
  };
  securityHeaders: {
    score: number | null;
    missing: string[];
    present: string[];
  };
  vulnerabilities: Vulnerability[];
  scoring: {
    vibeRiskScore: number;
    riskLevel: string;
    criticalDataExposure: boolean;
  };
}

export interface Vulnerability {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  location: string;
  cwe: string;
}

export interface Stats {
  totalTargets: number;
  totalVulnerabilities: number;
  criticalFindings: number;
  highFindings: number;
  averageVibeRiskScore: number;
  criticalDataTargets: number;
}

export type TabId = 'targets' | 'vulnerabilities' | 'risk-map' | 'report';
export type SeverityFilter = 'all' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
