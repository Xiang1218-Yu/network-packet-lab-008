export type Protocol = 'HTTP' | 'TCP';
export type PacketScenario = 'request' | 'response' | 'handshake';

export interface HexRow {
  offset: string;
  bytes: string[];
  ascii: string;
}

export interface ProtocolField {
  id: string;
  key: string;
  value: string;
  description: string;
  children?: ProtocolField[];
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  label: string;
  phase: 'ingress' | 'parse' | 'transport' | 'application' | 'egress';
  detail: string;
}

export interface SimulatedPacket {
  id: string;
  protocol: Protocol;
  scenario: PacketScenario;
  summary: string;
  raw: string;
  hex: HexRow[];
  fields: ProtocolField[];
  timeline: TimelineEvent[];
  metadata: {
    capturedAt: string;
    source: string;
    destination: string;
    length: number;
    checksum: string;
  };
}

export interface ParseRequest {
  protocol: Protocol;
  scenario: PacketScenario;
  raw: string;
}

// ---------- TCP 流重建 ----------

export type CaptureScenario = 'standard' | 'loss' | 'wraparound' | 'mixed';

export interface CaptureSessionSegment {
  id: string;
  order: number;
  capturedAt: string;
  source: string;
  destination: string;
  seq: number;
  ack: number;
  flags: string[];
  payloadLength: number;
  raw: string;
}

export interface CaptureSession {
  id: string;
  scenario: CaptureScenario;
  title: string;
  description: string;
  segments: CaptureSessionSegment[];
}

export interface TcpStreamReassembleRequest {
  segments: Array<{
    id?: string;
    source: string;
    destination: string;
    seq: number;
    ack: number;
    flags: string[];
    payloadLength: number;
  }>;
}

export type TcpDirectionKey = 'A_TO_B' | 'B_TO_A';

export type TcpAnomaly = 'retransmission' | 'overlap' | 'gap-before' | 'duplicate-ack' | 'wrap-suspect';

export interface TcpAckAnalysis {
  ackOffset: number;
  unacknowledgedBytes: number;
  coversPreviousSegment: boolean | null;
  note: string;
}

export interface TcpSegmentAnalysis {
  id: string;
  captureIndex: number;
  source: string;
  destination: string;
  direction: TcpDirectionKey;
  seq: number;
  ack: number;
  flags: string[];
  payloadLength: number;
  seqSpaceLength: number;
  streamStart: number;
  streamEnd: number;
  anomalies: TcpAnomaly[];
  notes: string[];
  ackAnalysis: TcpAckAnalysis | null;
}

export interface TcpStreamGap {
  start: number;
  end: number;
  size: number;
}

export interface TcpDirectionSummary {
  key: TcpDirectionKey;
  from: string;
  to: string;
  baseSeq: number;
  baseSource: 'syn' | 'inferred';
  segmentIds: string[];
  coveredBytes: number;
  contiguousEnd: number;
  spanEnd: number;
  gaps: TcpStreamGap[];
  wraparound: boolean;
}

export type TcpStreamEventType = 'retransmission' | 'gap' | 'overlap' | 'direction-switch' | 'wraparound' | 'duplicate-ack';

export interface TcpStreamEvent {
  type: TcpStreamEventType;
  segmentId?: string;
  message: string;
}

export interface TcpIgnoredSegment {
  id: string;
  connection: string;
  reason: string;
}

export interface TcpStreamStats {
  selected: number;
  analyzed: number;
  retransmissions: number;
  gaps: number;
  overlaps: number;
  directionSwitches: number;
  duplicateAcks: number;
}

export interface TcpStreamReassembly {
  connection: { a: string; b: string };
  directions: TcpDirectionSummary[];
  segments: TcpSegmentAnalysis[];
  events: TcpStreamEvent[];
  warnings: string[];
  ignored: TcpIgnoredSegment[];
  stats: TcpStreamStats;
}
