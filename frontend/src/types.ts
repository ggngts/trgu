export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface Summary {
  packet_count: number
  bytes_total: number
  duration_sec: number
  avg_packet_size: number
  pps: number
  unique_ips: number
  unique_ports: number
  tcp_count: number
  udp_count: number
  icmp_count: number
  dns_count: number
  http_count: number
  tls_count: number
}

export interface ProtocolStat {
  name: string
  packets: number
  bytes: number
  percentage: number
}

export interface Talker {
  ip: string
  packets: number
  bytes: number
  sent: number
  recv: number
}

export interface Conversation {
  src: string
  dst: string
  protocol: string
  packets: number
  bytes: number
  duration: number
}

export interface Threat {
  id: string
  category: string
  title: string
  description: string
  severity: Severity
  confidence: number
  indicators: string[]
  sources?: string[]
  targets?: string[]
  count?: number
}

export interface Analysis {
  id: string
  filename: string
  created_at: string
  summary: Summary
  protocols: ProtocolStat[]
  top_talkers: Talker[]
  conversations: Conversation[]
  threats: Threat[]
  threat_score: number
}

export interface LivePacket {
  Number: number
  TimeRel: number
  SrcIP: string
  DstIP: string
  SrcPort: number
  DstPort: number
  Protocol: string
  Length: number
}

export interface Health {
  ok: boolean
  tshark: boolean
  tshark_error?: string
}
