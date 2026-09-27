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

// ---- TCP stream reassembly ----

export type TcpStreamScenario = 'textbook' | 'lossy' | 'wrap' | 'mixed';

export interface TcpSegmentInput {
  id?: string;
  source: string;
  destination: string;
  seq: number;
  ack?: number;
  flags?: string[];
  payloadLength: number;
  capturedAt?: string;
}

export interface CapturedTcpSegment extends TcpSegmentInput {
  id: string;
  capturedAt: string;
}

export interface TcpCaptureSession {
  id: string;
  scenario: TcpStreamScenario;
  label: string;
  description: string;
  teachingPoints: string[];
  segments: CapturedTcpSegment[];
}

export interface TcpReassembleRequest {
  segments: TcpSegmentInput[];
}

export type StreamSegmentStatus =
  | 'in-order'
  | 'out-of-order'
  | 'overlap'
  | 'retransmission'
  | 'duplicate'
  | 'control';

export type StreamAnomaly =
  | 'RETRANSMISSION'
  | 'DUPLICATE'
  | 'OVERLAP'
  | 'GAP_BEFORE'
  | 'WRAP_AROUND'
  | 'CONTROL_ONLY';

export interface AckCoverage {
  ack: number;
  ackedBytes: number;
  peerSentBytes: number;
  coversPeerStream: boolean;
  note: string;
}

export interface StreamSegmentAnalysis {
  id: string;
  inputIndex: number;
  captureOrder: number;
  source: string;
  destination: string;
  seq: number;
  seqEnd: number;
  payloadLength: number;
  flags: string[];
  streamOffset: number;
  rangeStart: number;
  rangeEnd: number;
  status: StreamSegmentStatus;
  anomalies: StreamAnomaly[];
  note: string;
  ackCoverage?: AckCoverage;
}

export interface StreamGap {
  start: number;
  end: number;
  length: number;
  openedBySegmentId?: string;
  filledBySegmentId?: string;
  filled: boolean;
  note: string;
}

export interface StreamOverlapRegion {
  start: number;
  end: number;
  length: number;
  segmentIds: string[];
}

export interface DirectionStream {
  key: string;
  source: string;
  destination: string;
  baseSeq: number;
  wrapAround: boolean;
  segments: StreamSegmentAnalysis[];
  coverage: { start: number; end: number }[];
  gaps: StreamGap[];
  overlaps: StreamOverlapRegion[];
  streamLength: number;
  uniqueBytes: number;
  missingBytes: number;
  retransmittedBytes: number;
  retransmittedSegments: number;
}

export interface DirectionSwitch {
  captureOrder: number;
  from: string;
  to: string;
}

export type StreamWarningCode =
  | 'MIXED_CONNECTIONS'
  | 'DIRECTION_SWITCH'
  | 'WRAP_AROUND'
  | 'CONTROL_ONLY';

export interface StreamWarning {
  code: StreamWarningCode;
  message: string;
}

export interface ConnectionReassembly {
  key: string;
  endpoints: [string, string];
  segmentCount: number;
  captureOrder: string[];
  directions: DirectionStream[];
  directionSwitches: DirectionSwitch[];
}

export interface TcpReassembleResponse {
  orderingBasis: 'capturedAt' | 'input';
  connections: ConnectionReassembly[];
  warnings: StreamWarning[];
  totals: {
    segments: number;
    connections: number;
    directions: number;
    gaps: number;
    missingBytes: number;
    overlaps: number;
    retransmittedSegments: number;
    retransmittedBytes: number;
    directionSwitches: number;
  };
}
