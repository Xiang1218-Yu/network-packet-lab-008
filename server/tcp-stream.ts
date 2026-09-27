import type {
  CaptureScenario,
  CaptureSession,
  TcpAckAnalysis,
  TcpAnomaly,
  TcpDirectionKey,
  TcpDirectionSummary,
  TcpSegmentAnalysis,
  TcpStreamEvent,
  TcpStreamGap,
  TcpStreamReassembly
} from '../shared/types.js';

const SEQ_SPACE = 0x1_0000_0000; // 2^32，TCP 序号空间大小
const HALF_SPACE = 0x8000_0000; // 2^31，RFC 1982 序号比较半径
const MAX_SEGMENTS = 500;

/** 模 2^32 折算，结果恒在 [0, 2^32) */
const modSeq = (value: number): number => ((value % SEQ_SPACE) + SEQ_SPACE) % SEQ_SPACE;
/** seq 相对基准序号的流内偏移（RFC 1982 模算术） */
const seqOffset = (base: number, seq: number): number => modSeq(seq - base);

interface NormalizedSegment {
  id: string;
  captureIndex: number;
  source: string;
  destination: string;
  seq: number;
  ack: number;
  flags: string[];
  payloadLength: number;
  hasSyn: boolean;
  hasFin: boolean;
  hasAck: boolean;
  /** 占用的序号空间长度：payload + SYN/FIN 各消耗 1 个序号 */
  seqSpaceLength: number;
  direction: TcpDirectionKey;
  streamStart: number;
  streamEnd: number;
  anomalies: TcpAnomaly[];
  notes: string[];
  ackAnalysis: TcpAckAnalysis | null;
}

interface DirectionState {
  key: TcpDirectionKey;
  from: string;
  to: string;
  baseSeq: number;
  baseSource: 'syn' | 'inferred';
  hasSegments: boolean;
  /** 已接收的序号空间区间（含 SYN/FIN 控制字节），保持合并有序 */
  intervals: Array<[number, number]>;
  /** 从基准起连续覆盖到的偏移 */
  contiguous: number;
  initContiguous: number;
  /** 尚未被填补的缺口（数据域，偏移 >= 0） */
  gaps: TcpStreamGap[];
  wraparound: boolean;
  lastAckOffset: number | null;
  lastDataSegment: NormalizedSegment | null;
}

// ---------- 捕获会话样本 ----------

interface SessionSegmentSpec {
  source: string;
  destination: string;
  seq: number;
  ack: number;
  flags: string[];
  payloadLength: number;
}

const CLIENT = '10.0.0.24:51842';
const SERVER = '10.0.0.8:443';
const OTHER_CLIENT = '10.0.0.99:63000';

const SESSION_SPECS: Record<CaptureScenario, { title: string; description: string; segments: SessionSegmentSpec[] }> = {
  standard: {
    title: '标准会话：握手 → 双向数据 → 挥手',
    description: '一条连接完整的生命周期。观察 SYN/FIN 各占用 1 个序号、ACK 号如何等于“下一个期望字节”。',
    segments: [
      { source: CLIENT, destination: SERVER, seq: 18492000, ack: 0, flags: ['SYN'], payloadLength: 0 },
      { source: SERVER, destination: CLIENT, seq: 77120000, ack: 18492001, flags: ['SYN', 'ACK'], payloadLength: 0 },
      { source: CLIENT, destination: SERVER, seq: 18492001, ack: 77120001, flags: ['ACK'], payloadLength: 0 },
      { source: CLIENT, destination: SERVER, seq: 18492001, ack: 77120001, flags: ['ACK', 'PSH'], payloadLength: 128 },
      { source: SERVER, destination: CLIENT, seq: 77120001, ack: 18492129, flags: ['ACK'], payloadLength: 0 },
      { source: SERVER, destination: CLIENT, seq: 77120001, ack: 18492129, flags: ['ACK', 'PSH'], payloadLength: 512 },
      { source: CLIENT, destination: SERVER, seq: 18492129, ack: 77120513, flags: ['ACK'], payloadLength: 0 },
      { source: CLIENT, destination: SERVER, seq: 18492129, ack: 77120513, flags: ['ACK', 'PSH'], payloadLength: 64 },
      { source: SERVER, destination: CLIENT, seq: 77120513, ack: 18492193, flags: ['ACK'], payloadLength: 0 },
      { source: CLIENT, destination: SERVER, seq: 18492193, ack: 77120513, flags: ['FIN', 'ACK'], payloadLength: 0 },
      { source: SERVER, destination: CLIENT, seq: 77120513, ack: 18492194, flags: ['ACK'], payloadLength: 0 }
    ]
  },
  loss: {
    title: '丢包与重传：缺口、重复 ACK、重叠、补洞',
    description: '中间段丢失引发缺口，接收方重复 ACK 催促，发送方重传补齐。捕获顺序 ≠ 流内顺序。',
    segments: [
      { source: CLIENT, destination: SERVER, seq: 5000, ack: 0, flags: ['SYN'], payloadLength: 0 },
      { source: SERVER, destination: CLIENT, seq: 9000, ack: 5001, flags: ['SYN', 'ACK'], payloadLength: 0 },
      { source: CLIENT, destination: SERVER, seq: 5001, ack: 9001, flags: ['ACK'], payloadLength: 0 },
      { source: CLIENT, destination: SERVER, seq: 5001, ack: 9001, flags: ['ACK', 'PSH'], payloadLength: 100 },
      { source: SERVER, destination: CLIENT, seq: 9001, ack: 5101, flags: ['ACK'], payloadLength: 0 },
      { source: CLIENT, destination: SERVER, seq: 5201, ack: 9001, flags: ['ACK', 'PSH'], payloadLength: 100 },
      { source: SERVER, destination: CLIENT, seq: 9001, ack: 5101, flags: ['ACK'], payloadLength: 0 },
      { source: SERVER, destination: CLIENT, seq: 9001, ack: 5101, flags: ['ACK'], payloadLength: 0 },
      { source: CLIENT, destination: SERVER, seq: 5141, ack: 9001, flags: ['ACK', 'PSH'], payloadLength: 80 },
      { source: CLIENT, destination: SERVER, seq: 5101, ack: 9001, flags: ['ACK', 'PSH'], payloadLength: 100 },
      { source: CLIENT, destination: SERVER, seq: 5141, ack: 9001, flags: ['ACK', 'PSH'], payloadLength: 80 },
      { source: SERVER, destination: CLIENT, seq: 9001, ack: 5301, flags: ['ACK'], payloadLength: 0 }
    ]
  },
  wraparound: {
    title: '序号回绕：跨越 2^32 边界',
    description: '初始序号接近 4294967295，传输中序号从 4294967277 回绕到 11。偏移必须按模 2^32 算术展开。',
    segments: [
      { source: CLIENT, destination: SERVER, seq: 4294967246, ack: 0, flags: ['SYN'], payloadLength: 0 },
      { source: SERVER, destination: CLIENT, seq: 1000, ack: 4294967247, flags: ['SYN', 'ACK'], payloadLength: 0 },
      { source: CLIENT, destination: SERVER, seq: 4294967247, ack: 1001, flags: ['ACK'], payloadLength: 0 },
      { source: CLIENT, destination: SERVER, seq: 4294967247, ack: 1001, flags: ['ACK', 'PSH'], payloadLength: 30 },
      { source: CLIENT, destination: SERVER, seq: 4294967277, ack: 1001, flags: ['ACK', 'PSH'], payloadLength: 30 },
      { source: CLIENT, destination: SERVER, seq: 11, ack: 1001, flags: ['ACK', 'PSH'], payloadLength: 40 },
      { source: SERVER, destination: CLIENT, seq: 1001, ack: 51, flags: ['ACK'], payloadLength: 0 }
    ]
  },
  mixed: {
    title: '混用连接：两条连接的段交错出现',
    description: '10.0.0.24 与 10.0.0.99 同时访问同一台服务器。流重建要求同一连接，跨连接的段会被识别并排除。',
    segments: [
      { source: CLIENT, destination: SERVER, seq: 30000, ack: 0, flags: ['SYN'], payloadLength: 0 },
      { source: OTHER_CLIENT, destination: SERVER, seq: 555000, ack: 0, flags: ['SYN'], payloadLength: 0 },
      { source: SERVER, destination: CLIENT, seq: 8000, ack: 30001, flags: ['SYN', 'ACK'], payloadLength: 0 },
      { source: CLIENT, destination: SERVER, seq: 30001, ack: 8001, flags: ['ACK'], payloadLength: 0 },
      { source: SERVER, destination: OTHER_CLIENT, seq: 444000, ack: 555001, flags: ['SYN', 'ACK'], payloadLength: 0 },
      { source: CLIENT, destination: SERVER, seq: 30001, ack: 8001, flags: ['ACK', 'PSH'], payloadLength: 50 },
      { source: OTHER_CLIENT, destination: SERVER, seq: 555001, ack: 444001, flags: ['ACK', 'PSH'], payloadLength: 20 },
      { source: SERVER, destination: CLIENT, seq: 8001, ack: 30051, flags: ['ACK'], payloadLength: 0 }
    ]
  }
};

export function isCaptureScenario(value: unknown): value is CaptureScenario {
  return value === 'standard' || value === 'loss' || value === 'wraparound' || value === 'mixed';
}

export function buildCaptureSession(scenario: CaptureScenario): CaptureSession {
  const spec = SESSION_SPECS[scenario];
  const segments = spec.segments.map((segment, index) => ({
    id: `seg-${String(index + 1).padStart(2, '0')}`,
    order: index + 1,
    capturedAt: `00:00:${String(index).padStart(2, '0')}.${String((index * 137 + 41) % 1000).padStart(3, '0')}`,
    ...segment,
    raw: `TCP ${segment.source} > ${segment.destination} | Seq=${segment.seq} Ack=${segment.ack} | Flags=${segment.flags.join(',')} | Win=64240 | Len=${segment.payloadLength}`
  }));
  return { id: `session-${scenario}`, scenario, title: spec.title, description: spec.description, segments };
}

// ---------- 流重建 ----------

function normalizeSegments(input: unknown): { segments: NormalizedSegment[] } | { error: string } {
  if (!Array.isArray(input)) return { error: 'segments 必须是数组' };
  if (input.length === 0) return { error: '未选择任何 TCP 段：流重建需要至少一个段' };
  if (input.length > MAX_SEGMENTS) return { error: `单次最多重建 ${MAX_SEGMENTS} 个段` };
  const segments: NormalizedSegment[] = [];
  for (let index = 0; index < input.length; index += 1) {
    const item = (input[index] ?? {}) as Record<string, unknown>;
    const source = typeof item.source === 'string' ? item.source.trim() : '';
    const destination = typeof item.destination === 'string' ? item.destination.trim() : '';
    if (!source || !destination) return { error: `第 ${index + 1} 个段缺少 source / destination 端点` };
    const seq = Number(item.seq);
    const ack = Number(item.ack);
    if (!Number.isInteger(seq) || seq < 0 || seq >= SEQ_SPACE) return { error: `第 ${index + 1} 个段的 Seq 非法（需为 0–4294967295 的整数）` };
    if (!Number.isInteger(ack) || ack < 0 || ack >= SEQ_SPACE) return { error: `第 ${index + 1} 个段的 Ack 非法（需为 0–4294967295 的整数）` };
    const payloadLength = Number(item.payloadLength ?? 0);
    if (!Number.isInteger(payloadLength) || payloadLength < 0) return { error: `第 ${index + 1} 个段的 payloadLength 非法` };
    const flags = Array.isArray(item.flags) ? item.flags.map((flag) => String(flag).toUpperCase()) : [];
    const hasSyn = flags.includes('SYN');
    const hasFin = flags.includes('FIN');
    segments.push({
      id: typeof item.id === 'string' && item.id ? item.id : `seg-${index + 1}`,
      captureIndex: index,
      source,
      destination,
      seq,
      ack,
      flags,
      payloadLength,
      hasSyn,
      hasFin,
      hasAck: flags.includes('ACK'),
      seqSpaceLength: payloadLength + (hasSyn ? 1 : 0) + (hasFin ? 1 : 0),
      direction: 'A_TO_B',
      streamStart: 0,
      streamEnd: 0,
      anomalies: [],
      notes: [],
      ackAnalysis: null
    });
  }
  return { segments };
}

/** [start, end) 与已接收区间集合的重叠总长度 */
function coveredLength(intervals: Array<[number, number]>, start: number, end: number): number {
  let covered = 0;
  for (const [lo, hi] of intervals) {
    const overlap = Math.min(hi, end) - Math.max(lo, start);
    if (overlap > 0) covered += overlap;
  }
  return covered;
}

function insertInterval(state: DirectionState, start: number, end: number): void {
  state.intervals.push([start, end]);
  state.intervals.sort((a, b) => a[0] - b[0]);
  const merged: Array<[number, number]> = [];
  for (const [lo, hi] of state.intervals) {
    const last = merged[merged.length - 1];
    if (last && lo <= last[1]) last[1] = Math.max(last[1], hi);
    else merged.push([lo, hi]);
  }
  state.intervals = merged;
  let cursor = state.initContiguous;
  for (const [lo, hi] of merged) {
    if (lo <= cursor && hi > cursor) cursor = hi;
    else if (lo > cursor) break;
  }
  state.contiguous = cursor;
}

/** 段数据落入先前记录的缺口时，从缺口中减去已覆盖部分 */
function fillGaps(state: DirectionState, segment: NormalizedSegment, start: number, end: number): void {
  const remaining: TcpStreamGap[] = [];
  for (const gap of state.gaps) {
    if (end <= gap.start || start >= gap.end) {
      remaining.push(gap);
      continue;
    }
    segment.notes.push(`回传数据落入先前缺口 ${gap.start}–${gap.end - 1}（${gap.size} 字节），属于对丢失段的补救`);
    if (start > gap.start) {
      const hi = Math.min(start, gap.end);
      remaining.push({ start: gap.start, end: hi, size: hi - gap.start });
    }
    if (end < gap.end) {
      const lo = Math.max(end, gap.start);
      remaining.push({ start: lo, end: gap.end, size: gap.end - lo });
    }
  }
  state.gaps = remaining;
}

export function reassembleTcpStream(input: unknown): { data: TcpStreamReassembly } | { error: string } {
  const normalized = normalizeSegments(input);
  if ('error' in normalized) return normalized;
  const allSegments = normalized.segments;

  // 1. 按连接（无序端点对）分组，混用连接时只分析段数最多的一条
  const groups = new Map<string, NormalizedSegment[]>();
  for (const segment of allSegments) {
    const key = [segment.source, segment.destination].sort().join(' ⇄ ');
    const list = groups.get(key) ?? [];
    list.push(segment);
    groups.set(key, list);
  }
  const sortedGroups = [...groups.entries()].sort(
    (a, b) => b[1].length - a[1].length || a[1][0].captureIndex - b[1][0].captureIndex
  );
  const [mainKey, mainSegments] = sortedGroups[0];
  const warnings: string[] = [];
  const ignored = sortedGroups.slice(1).flatMap(([key, list]) =>
    list.map((segment) => ({ id: segment.id, connection: key, reason: `属于另一条连接（${key}），流重建要求同一连接，已排除` }))
  );
  if (ignored.length > 0) {
    warnings.push(`检测到 ${sortedGroups.length} 条不同连接的段混选：已分析段数最多的连接（${mainKey}），其余 ${ignored.length} 个段被排除。`);
  }

  // 2. 确定端点角色与方向：优先以 SYN（不带 ACK）的发送方为发起端
  const initiatorSegment = mainSegments.find((segment) => segment.hasSyn && !segment.hasAck);
  const endpointA = initiatorSegment ? initiatorSegment.source : mainSegments[0].source;
  const endpointB = initiatorSegment ? initiatorSegment.destination : mainSegments[0].destination;
  for (const segment of mainSegments) segment.direction = segment.source === endpointA ? 'A_TO_B' : 'B_TO_A';

  const directionKeys: TcpDirectionKey[] = ['A_TO_B', 'B_TO_A'];
  const byDirection: Record<TcpDirectionKey, NormalizedSegment[]> = {
    A_TO_B: mainSegments.filter((segment) => segment.direction === 'A_TO_B'),
    B_TO_A: mainSegments.filter((segment) => segment.direction === 'B_TO_A')
  };

  // 3. 每个方向独立的字节流：确定基准序号并折算流内偏移
  const states = {} as Record<TcpDirectionKey, DirectionState>;
  for (const key of directionKeys) {
    const segments = byDirection[key];
    const syn = segments.find((segment) => segment.hasSyn);
    let baseSeq = 0;
    let baseSource: DirectionState['baseSource'] = 'inferred';
    let wraparound = false;
    if (syn) {
      baseSeq = modSeq(syn.seq + 1); // SYN 消耗 1 个序号，数据流从 ISN+1 开始
      baseSource = 'syn';
    } else if (segments.length > 0) {
      const seqs = segments.map((segment) => segment.seq);
      const min = Math.min(...seqs);
      const max = Math.max(...seqs);
      if (max - min > HALF_SPACE) {
        // 观测值散布在 0 与 2^32 两端：按回绕处理，基准取高端簇的最小值
        baseSeq = Math.min(...seqs.filter((value) => value >= HALF_SPACE));
        wraparound = true;
      } else {
        baseSeq = min;
      }
    }
    const state: DirectionState = {
      key,
      from: key === 'A_TO_B' ? endpointA : endpointB,
      to: key === 'A_TO_B' ? endpointB : endpointA,
      baseSeq,
      baseSource,
      hasSegments: segments.length > 0,
      intervals: [],
      contiguous: syn ? -1 : 0,
      initContiguous: syn ? -1 : 0,
      gaps: [],
      wraparound,
      lastAckOffset: null,
      lastDataSegment: null
    };
    for (const segment of segments) {
      segment.streamStart = segment.hasSyn ? -1 : seqOffset(baseSeq, segment.seq);
      segment.streamEnd = segment.streamStart + segment.seqSpaceLength;
      if (!segment.hasSyn && segment.seqSpaceLength > 0) {
        if (segment.streamStart > HALF_SPACE) {
          segment.anomalies.push('wrap-suspect');
          segment.notes.push('序号按模 2^32 折算后落在基准之前（偏移超过 2^31），可能是回绕前的旧段，或基准序号推断有误');
        }
        if (segment.seq < baseSeq) state.wraparound = true; // 序号小于基准：发生了回绕
        if (segment.seq + segment.seqSpaceLength > SEQ_SPACE) {
          state.wraparound = true;
          segment.notes.push(`该段自身跨越 2^32 回绕点：Seq ${segment.seq} + ${segment.seqSpaceLength} → ${modSeq(segment.seq + segment.seqSpaceLength)}`);
        }
      }
    }
    states[key] = state;
  }

  const dirLabel = (key: TcpDirectionKey): string => `${states[key].from} → ${states[key].to}`;
  const events: Array<TcpStreamEvent & { captureIndex: number }> = [];

  // 4. 按捕获顺序重放：维护每个方向的接收状态，识别缺口 / 重传 / 重叠 / ACK 覆盖
  const ordered = [...mainSegments].sort((a, b) => a.captureIndex - b.captureIndex);
  for (const segment of ordered) {
    const state = states[segment.direction];
    const oppositeKey: TcpDirectionKey = segment.direction === 'A_TO_B' ? 'B_TO_A' : 'A_TO_B';
    const opposite = states[oppositeKey];

    if (segment.seqSpaceLength > 0) {
      const { streamStart: start, streamEnd: end } = segment;
      // 先让数据填补旧缺口，再登记本段到达时仍存在的缺口（避免同一缺口重复登记）
      fillGaps(state, segment, start, end);
      const gapProbe = Math.max(state.contiguous, 0);
      if (start > gapProbe) {
        const gap: TcpStreamGap = { start: gapProbe, end: start, size: start - gapProbe };
        if (!state.gaps.some((known) => known.start === gap.start && known.end === gap.end)) state.gaps.push(gap);
        segment.anomalies.push('gap-before');
        segment.notes.push(`到达时存在缺口：偏移 ${gap.start}–${gap.end - 1} 共 ${gap.size} 字节尚未出现`);
        events.push({ type: 'gap', segmentId: segment.id, captureIndex: segment.captureIndex, message: `缺口 · ${dirLabel(segment.direction)} 段 #${segment.captureIndex + 1} 到达时，偏移 ${gap.start}–${gap.end - 1} 缺失 ${gap.size} 字节` });
      }
      const already = coveredLength(state.intervals, start, end);
      if (already >= end - start) {
        segment.anomalies.push('retransmission');
        segment.notes.push(`完整重传：序号空间 [${start}, ${end}) 此前已全部接收`);
        events.push({ type: 'retransmission', segmentId: segment.id, captureIndex: segment.captureIndex, message: `重传 · ${dirLabel(segment.direction)} 段 #${segment.captureIndex + 1} 的 [${start}, ${end}) 已完整接收过` });
      } else if (already > 0) {
        segment.anomalies.push('overlap');
        segment.notes.push(`部分重叠：${already} / ${end - start} 字节与已接收数据重复`);
        events.push({ type: 'overlap', segmentId: segment.id, captureIndex: segment.captureIndex, message: `重叠 · ${dirLabel(segment.direction)} 段 #${segment.captureIndex + 1} 有 ${already} 字节与先前段重复` });
      }
      insertInterval(state, start, end);
      state.lastDataSegment = segment;
    }

    if (segment.hasAck && opposite.hasSegments) {
      const ackOffset = seqOffset(opposite.baseSeq, segment.ack);
      const unacknowledged = Math.max(0, opposite.contiguous - ackOffset);
      const parts: string[] = [];
      const oppositeHasSyn = byDirection[oppositeKey].some((item) => item.hasSyn);
      if (ackOffset === 0 && oppositeHasSyn) parts.push('ACK = 对端 ISN+1，确认 SYN 本身');
      else parts.push(`ACK 对应对端流偏移 ${ackOffset}`);
      if (ackOffset > opposite.contiguous) parts.push(`超出对端已连续接收范围 ${ackOffset - opposite.contiguous} 字节（可能有段未被捕获）`);
      else if (unacknowledged > 0) parts.push(`对端还有 ${unacknowledged} 字节连续数据未获确认`);
      else if (ackOffset > 0) parts.push(`已确认对端全部 ${ackOffset} 字节 ✓`);
      const previous = opposite.lastDataSegment;
      let coversPrevious: boolean | null = null;
      if (previous) {
        coversPrevious = ackOffset >= previous.streamEnd;
        parts.push(coversPrevious ? `覆盖对端上一段 [${previous.streamStart}, ${previous.streamEnd}) ✓` : `尚未覆盖对端上一段 [${previous.streamStart}, ${previous.streamEnd})`);
      }
      const oppositeFin = byDirection[oppositeKey].find((item) => item.hasFin);
      if (oppositeFin && ackOffset >= oppositeFin.streamEnd) parts.push('确认范围包含对端 FIN 占用的序号');
      segment.ackAnalysis = { ackOffset, unacknowledgedBytes: unacknowledged, coversPreviousSegment: coversPrevious, note: parts.join('；') };
      if (segment.seqSpaceLength === 0 && state.lastAckOffset !== null && state.lastAckOffset === ackOffset) {
        segment.anomalies.push('duplicate-ack');
        segment.notes.push('重复 ACK：确认号与上一段相同，通常提示对端数据丢失或乱序');
        events.push({ type: 'duplicate-ack', segmentId: segment.id, captureIndex: segment.captureIndex, message: `重复 ACK · ${dirLabel(segment.direction)} 段 #${segment.captureIndex + 1} 确认号 ${segment.ack} 与上一段相同` });
      }
      state.lastAckOffset = ackOffset;
    }
  }

  // 5. 方向切换（按捕获顺序观察）
  let previousDirection: TcpDirectionKey | null = null;
  for (const segment of ordered) {
    if (previousDirection && segment.direction !== previousDirection) {
      events.push({ type: 'direction-switch', segmentId: segment.id, captureIndex: segment.captureIndex, message: `方向切换 · ${dirLabel(previousDirection)} ⇒ ${dirLabel(segment.direction)}（段 #${segment.captureIndex + 1}）` });
    }
    previousDirection = segment.direction;
  }

  // 6. 方向级提示
  for (const key of directionKeys) {
    const state = states[key];
    if (state.hasSegments && state.wraparound) {
      events.push({ type: 'wraparound', captureIndex: -1, message: `序号回绕 · ${dirLabel(key)} 的序号跨越 2^32 边界，流偏移已按模 2^32（RFC 1982）展开` });
      warnings.push(`方向 ${dirLabel(key)} 检测到序号回绕：序列号跨越 4294967295 → 0 边界，流偏移按模 2^32 算术计算。`);
    }
  }
  if (!states.A_TO_B.hasSegments || !states.B_TO_A.hasSegments) {
    warnings.push('只观测到一个方向的段：ACK 覆盖分析需要双向流量，当前结果仅反映单向序号布局。');
  }
  if (!mainSegments.some((segment) => segment.hasSyn)) {
    warnings.push('未观测到 SYN 握手段：基准序号按最小观测序号推断，绝对偏移可能不代表连接真实起点。');
  }

  // 7. 汇总输出
  const directions: TcpDirectionSummary[] = directionKeys.map((key) => {
    const state = states[key];
    const segments = byDirection[key];
    const segmentIds = [...segments]
      .sort((a, b) => a.streamStart - b.streamStart || a.captureIndex - b.captureIndex)
      .map((segment) => segment.id);
    const coveredBytes = state.intervals.reduce((sum, [lo, hi]) => {
      const start = Math.max(lo, 0);
      return hi > start ? sum + (hi - start) : sum;
    }, 0);
    const spanEnd = segments.reduce((max, segment) => Math.max(max, segment.streamEnd), 0);
    return {
      key,
      from: state.from,
      to: state.to,
      baseSeq: state.baseSeq,
      baseSource: state.baseSource,
      segmentIds,
      coveredBytes,
      contiguousEnd: Math.max(state.contiguous, 0),
      spanEnd,
      gaps: state.gaps,
      wraparound: state.wraparound
    };
  });

  const segments: TcpSegmentAnalysis[] = ordered.map((segment) => ({
    id: segment.id,
    captureIndex: segment.captureIndex,
    source: segment.source,
    destination: segment.destination,
    direction: segment.direction,
    seq: segment.seq,
    ack: segment.ack,
    flags: segment.flags,
    payloadLength: segment.payloadLength,
    seqSpaceLength: segment.seqSpaceLength,
    streamStart: segment.streamStart,
    streamEnd: segment.streamEnd,
    anomalies: segment.anomalies,
    notes: segment.notes,
    ackAnalysis: segment.ackAnalysis
  }));

  const countAnomaly = (anomaly: TcpAnomaly): number => segments.filter((segment) => segment.anomalies.includes(anomaly)).length;
  const countEvent = (type: TcpStreamEvent['type']): number => events.filter((event) => event.type === type).length;

  return {
    data: {
      connection: { a: endpointA, b: endpointB },
      directions,
      segments,
      events: events.sort((a, b) => a.captureIndex - b.captureIndex).map(({ type, segmentId, message }) => ({ type, ...(segmentId ? { segmentId } : {}), message })),
      warnings,
      ignored,
      stats: {
        selected: allSegments.length,
        analyzed: mainSegments.length,
        retransmissions: countAnomaly('retransmission'),
        gaps: countEvent('gap'),
        overlaps: countAnomaly('overlap'),
        directionSwitches: countEvent('direction-switch'),
        duplicateAcks: countAnomaly('duplicate-ack')
      }
    }
  };
}
