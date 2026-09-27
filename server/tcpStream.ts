import type {
  AckCoverage,
  CapturedTcpSegment,
  ConnectionReassembly,
  DirectionStream,
  DirectionSwitch,
  StreamAnomaly,
  StreamGap,
  StreamOverlapRegion,
  StreamSegmentAnalysis,
  StreamSegmentStatus,
  StreamWarning,
  TcpCaptureSession,
  TcpReassembleResponse,
  TcpSegmentInput,
  TcpStreamScenario
} from '../shared/types.js';

const UINT32 = 0x100000000; // 2^32，序号空间大小
const UINT31 = 0x80000000; // 2^31，回绕判定阈值
const MAX_SEGMENTS = 200;
const MAX_PAYLOAD_LENGTH = 1_000_000;

interface WorkingSegment {
  id: string;
  inputIndex: number;
  captureOrder: number;
  source: string;
  destination: string;
  seq: number;
  ack?: number;
  flags: string[];
  payloadLength: number;
  capturedAt?: string;
  span: number; // 占用的序号空间：payload + SYN/FIN 幻影字节
  start: number; // 回绕归一化后的绝对起点
  end: number; // 回绕归一化后的绝对终点
}

interface DirectionInternal {
  base: number;
  wrap: boolean;
  segments: WorkingSegment[];
}

const directionKeyOf = (source: string, destination: string) => `${source}→${destination}`;
const connectionKeyOf = (source: string, destination: string) =>
  [source, destination].sort().join(' ↔ ');

function sequenceSpan(flags: string[], payloadLength: number): number {
  let span = payloadLength;
  if (flags.includes('SYN')) span += 1;
  if (flags.includes('FIN')) span += 1;
  return span;
}

/** 校验并规范化客户端提交的段列表，不合法时抛出带中文说明的错误。 */
export function parseSegmentInputs(body: unknown): TcpSegmentInput[] {
  const rawSegments = (body as { segments?: unknown } | null)?.segments;
  if (!Array.isArray(rawSegments) || rawSegments.length === 0) {
    throw new Error('空选择：请至少选择一个 TCP 段再进行流重建');
  }
  if (rawSegments.length > MAX_SEGMENTS) {
    throw new Error(`一次最多重建 ${MAX_SEGMENTS} 个段（收到 ${rawSegments.length} 个）`);
  }
  return rawSegments.map((raw, index) => {
    const segment = raw as Partial<TcpSegmentInput>;
    const label = `第 ${index + 1} 个段`;
    if (!segment || typeof segment.source !== 'string' || !segment.source.trim()) {
      throw new Error(`${label}缺少有效的 source 端点`);
    }
    if (!segment || typeof segment.destination !== 'string' || !segment.destination.trim()) {
      throw new Error(`${label}缺少有效的 destination 端点`);
    }
    const seq = Number(segment.seq);
    if (!Number.isInteger(seq) || seq < 0 || seq >= UINT32) {
      throw new Error(`${label}的 Seq=${String(segment.seq)} 非法：序号必须是 0 ~ 2^32-1 的整数`);
    }
    const payloadLength = Number(segment.payloadLength ?? 0);
    if (!Number.isInteger(payloadLength) || payloadLength < 0 || payloadLength > MAX_PAYLOAD_LENGTH) {
      throw new Error(`${label}的 payloadLength 非法`);
    }
    let ack: number | undefined;
    if (segment.ack !== undefined && segment.ack !== null) {
      ack = Number(segment.ack);
      if (!Number.isInteger(ack) || ack < 0 || ack >= UINT32) {
        throw new Error(`${label}的 Ack=${String(segment.ack)} 非法`);
      }
    }
    const flags = Array.isArray(segment.flags)
      ? segment.flags.filter((flag): flag is string => typeof flag === 'string').map((flag) => flag.toUpperCase())
      : [];
    return {
      ...(typeof segment.id === 'string' && segment.id.trim() ? { id: segment.id } : {}),
      source: segment.source.trim(),
      destination: segment.destination.trim(),
      seq,
      ...(ack !== undefined ? { ack } : {}),
      flags,
      payloadLength,
      ...(typeof segment.capturedAt === 'string' && segment.capturedAt.trim()
        ? { capturedAt: segment.capturedAt }
        : {})
    };
  });
}

/** 核心重建逻辑：按连接分组 → 按方向拆分 → 按到达顺序分析流行为 → 按序号输出逻辑范围。 */
export function reassembleTcpStream(input: TcpSegmentInput[]): TcpReassembleResponse {
  const orderingBasis: TcpReassembleResponse['orderingBasis'] = input.every(
    (segment) => typeof segment.capturedAt === 'string' && segment.capturedAt.trim().length > 0
  )
    ? 'capturedAt'
    : 'input';

  const segments: WorkingSegment[] = input.map((segment, index) => {
    const span = sequenceSpan(segment.flags ?? [], segment.payloadLength);
    return {
      id: segment.id ?? `seg-${index + 1}`,
      inputIndex: index,
      captureOrder: index,
      source: segment.source,
      destination: segment.destination,
      seq: segment.seq,
      ...(segment.ack !== undefined ? { ack: segment.ack } : {}),
      flags: segment.flags ?? [],
      payloadLength: segment.payloadLength,
      ...(segment.capturedAt !== undefined ? { capturedAt: segment.capturedAt } : {}),
      span,
      start: segment.seq,
      end: segment.seq + span
    };
  });

  const warnings: StreamWarning[] = [];
  const byConnection = new Map<string, WorkingSegment[]>();
  for (const segment of segments) {
    const key = connectionKeyOf(segment.source, segment.destination);
    const group = byConnection.get(key) ?? [];
    group.push(segment);
    byConnection.set(key, group);
  }
  if (byConnection.size > 1) {
    warnings.push({
      code: 'MIXED_CONNECTIONS',
      message: `选择中混入了 ${byConnection.size} 条不同连接的段，已按连接拆分后分别重建；跨连接的序号没有可比性，请勿直接比较。`
    });
  }

  const connections = [...byConnection.entries()].map(([key, group]) =>
    analyzeConnection(key, group, orderingBasis, warnings)
  );

  const totals = {
    segments: segments.length,
    connections: connections.length,
    directions: connections.reduce((sum, connection) => sum + connection.directions.length, 0),
    gaps: connections.reduce(
      (sum, connection) => sum + connection.directions.reduce((inner, direction) => inner + direction.gaps.filter((gap) => !gap.filled).length, 0),
      0
    ),
    missingBytes: connections.reduce(
      (sum, connection) => sum + connection.directions.reduce((inner, direction) => inner + direction.missingBytes, 0),
      0
    ),
    overlaps: connections.reduce(
      (sum, connection) => sum + connection.directions.reduce((inner, direction) => inner + direction.overlaps.length, 0),
      0
    ),
    retransmittedSegments: connections.reduce(
      (sum, connection) => sum + connection.directions.reduce((inner, direction) => inner + direction.retransmittedSegments, 0),
      0
    ),
    retransmittedBytes: connections.reduce(
      (sum, connection) => sum + connection.directions.reduce((inner, direction) => inner + direction.retransmittedBytes, 0),
      0
    ),
    directionSwitches: connections.reduce((sum, connection) => sum + connection.directionSwitches.length, 0)
  };

  return { orderingBasis, connections, warnings, totals };
}

function analyzeConnection(
  key: string,
  segments: WorkingSegment[],
  orderingBasis: TcpReassembleResponse['orderingBasis'],
  warnings: StreamWarning[]
): ConnectionReassembly {
  // 捕获顺序：优先 capturedAt（字典序可比较的时间串），否则沿用输入顺序
  const captureSorted = [...segments].sort((a, b) => {
    if (orderingBasis === 'capturedAt') {
      const byTime = String(a.capturedAt).localeCompare(String(b.capturedAt));
      if (byTime !== 0) return byTime;
    }
    return a.inputIndex - b.inputIndex;
  });
  captureSorted.forEach((segment, order) => {
    segment.captureOrder = order;
  });

  const directionSwitches: DirectionSwitch[] = [];
  for (let index = 1; index < captureSorted.length; index += 1) {
    const previous = directionKeyOf(captureSorted[index - 1].source, captureSorted[index - 1].destination);
    const current = directionKeyOf(captureSorted[index].source, captureSorted[index].destination);
    if (previous !== current) directionSwitches.push({ captureOrder: index, from: previous, to: current });
  }
  if (directionSwitches.length > 0) {
    warnings.push({
      code: 'DIRECTION_SWITCH',
      message: `连接 ${key} 在捕获顺序中出现 ${directionSwitches.length} 次方向切换：TCP 字节流是单向的，已将双向段拆分后分别重建。`
    });
  }

  const byDirection = new Map<string, WorkingSegment[]>();
  for (const segment of captureSorted) {
    const key = directionKeyOf(segment.source, segment.destination);
    const group = byDirection.get(key) ?? [];
    group.push(segment);
    byDirection.set(key, group);
  }

  const directions: DirectionStream[] = [];
  const internals = new Map<string, DirectionInternal>();
  for (const [directionKey, group] of byDirection) {
    const { stream, internal } = analyzeDirection(directionKey, group, warnings);
    directions.push(stream);
    internals.set(directionKey, internal);
  }

  applyAckCoverage(captureSorted, directions, internals);

  const endpoints = key.split(' ↔ ') as [string, string];
  return {
    key,
    endpoints,
    segmentCount: segments.length,
    captureOrder: captureSorted.map((segment) => segment.id),
    directions,
    directionSwitches
  };
}

function analyzeDirection(
  key: string,
  segments: WorkingSegment[],
  warnings: StreamWarning[]
): { stream: DirectionStream; internal: DirectionInternal } {
  const source = segments[0].source;
  const destination = segments[0].destination;
  const seqValues = segments.map((segment) => segment.seq);
  const wrap = Math.max(...seqValues) - Math.min(...seqValues) > UINT31;
  const normalize = (seq: number) => (wrap && seq < UINT31 ? seq + UINT32 : seq);

  for (const segment of segments) {
    segment.start = normalize(segment.seq);
    segment.end = segment.start + segment.span;
  }
  const base = Math.min(...segments.map((segment) => segment.start));

  if (wrap) {
    warnings.push({
      code: 'WRAP_AROUND',
      message: `方向 ${key} 的序号跨越 2^32 边界（最大值 ${Math.max(...seqValues)}，最小值 ${Math.min(...seqValues)}），已按模 2^32 算术将回绕后的序号 +2^32 归一化再排序。`
    });
  }

  // —— 到达顺序分析：重传 / 缺口 / 重叠都是"到达时"相对已接收流的行为 ——
  const byArrival = [...segments].sort((a, b) => a.captureOrder - b.captureOrder);
  const statusById = new Map<string, { status: StreamSegmentStatus; anomalies: StreamAnomaly[]; notes: string[] }>();
  let received: Array<[number, number]> = [];
  const openHoles: Array<{ start: number; end: number; openedBy: string }> = [];
  const recoveredHoles: Array<{ start: number; end: number; openedBy: string; filledBy: string }> = [];

  const computeHoles = (): Array<[number, number]> => {
    const holes: Array<[number, number]> = [];
    for (let index = 1; index < received.length; index += 1) {
      holes.push([received[index - 1][1], received[index][0]]);
    }
    return holes;
  };
  const intersectLength = (start: number, end: number): number =>
    received.reduce((sum, [a, b]) => sum + Math.max(0, Math.min(end, b) - Math.max(start, a)), 0);
  const insertInterval = (start: number, end: number) => {
    received.push([start, end]);
    received.sort((a, b) => a[0] - b[0]);
    const merged: Array<[number, number]> = [];
    for (const interval of received) {
      const last = merged[merged.length - 1];
      if (last && interval[0] <= last[1]) last[1] = Math.max(last[1], interval[1]);
      else merged.push([...interval]);
    }
    received = merged;
  };

  for (const segment of byArrival) {
    const anomalies: StreamAnomaly[] = [];
    const notes: string[] = [];
    let status: StreamSegmentStatus;

    if (segment.span === 0) {
      status = 'control';
      anomalies.push('CONTROL_ONLY');
      notes.push('纯 ACK / 控制段：不占用序号空间，不参与数据流拼接');
    } else if (received.length === 0) {
      status = 'in-order';
      notes.push(`该方向第一个到达的段，以其序号 ${segment.seq} 作为流基准`);
      insertInterval(segment.start, segment.end);
    } else {
      const frontier = received[0][1];
      const spanLength = segment.end - segment.start;
      const redundant = intersectLength(segment.start, segment.end);

      if (redundant >= spanLength) {
        const identical = byArrival.find(
          (other) => other !== segment && other.captureOrder < segment.captureOrder && other.start === segment.start && other.end === segment.end
        );
        status = identical ? 'duplicate' : 'retransmission';
        anomalies.push(identical ? 'DUPLICATE' : 'RETRANSMISSION');
        notes.push(
          identical
            ? `范围与捕获 #${identical.captureOrder + 1} 完全相同 → 重复段，全部 ${spanLength} 字节均为重传`
            : `整段 ${spanLength} 字节已被先前到达的段覆盖 → 完整重传，接收方直接丢弃`
        );
      } else if (redundant > 0) {
        status = 'overlap';
        anomalies.push('OVERLAP');
        notes.push(
          `其中 ${redundant} 字节与已接收数据重叠，仅 ${spanLength - redundant} 字节是新数据（部分重传 / 重新分段）`
        );
        insertInterval(segment.start, segment.end);
      } else if (segment.start > frontier) {
        status = 'out-of-order';
        anomalies.push('GAP_BEFORE');
        notes.push(
          `到达时连续流停在偏移 ${frontier - base}，本段从偏移 ${segment.start - base} 开始 → 前方留下 ${segment.start - frontier} 字节缺口（乱序到达，接收方会缓存并重复 ACK）`
        );
        insertInterval(segment.start, segment.end);
      } else {
        status = 'in-order';
        if (segment.start < received[0][0]) {
          notes.push('序号低于当前已接收流起点，向前补齐了更早期的数据（迟到的段）');
        } else {
          notes.push(`衔接连续流末尾，流位置推进 ${spanLength} 字节`);
        }
        insertInterval(segment.start, segment.end);
      }

      // 缺口事件：本段是否打开 / 填补了缺口
      const holesAfter = computeHoles();
      for (const hole of [...openHoles]) {
        const stillOpen = holesAfter.some(([a, b]) => a < hole.end && b > hole.start);
        if (!stillOpen) {
          openHoles.splice(openHoles.indexOf(hole), 1);
          recoveredHoles.push({ ...hole, filledBy: segment.id });
          notes.push(
            `填补了缺口 [${hole.start - base}, ${hole.end - base})（${hole.end - hole.start} 字节），字节流恢复连续`
          );
        }
      }
      for (const [a, b] of holesAfter) {
        const tracked = openHoles.find((hole) => a < hole.end && b > hole.start);
        if (tracked) {
          tracked.start = a;
          tracked.end = b;
        } else {
          openHoles.push({ start: a, end: b, openedBy: segment.id });
        }
      }
    }

    if (wrap && segment.seq < UINT31 && segment.span > 0) {
      anomalies.push('WRAP_AROUND');
      notes.push(`序号 ${segment.seq} 是回绕后的值，按 +2^32 归一化为 ${segment.start} 参与排序`);
    }
    statusById.set(segment.id, { status, anomalies, notes });
  }

  // —— 序号空间视图：覆盖区间、缺口、重叠区 ——
  const dataSegments = segments.filter((segment) => segment.span > 0);
  const coverage = mergeIntervals(dataSegments.map((segment) => [segment.start - base, segment.end - base] as [number, number]))
    .map(([start, end]) => ({ start, end }));
  const gaps: StreamGap[] = [];
  for (let index = 1; index < coverage.length; index += 1) {
    const start = coverage[index - 1].end;
    const end = coverage[index].start;
    const openedBy = openHoles.find((hole) => hole.start - base === start && hole.end - base === end)?.openedBy;
    gaps.push({
      start,
      end,
      length: end - start,
      ...(openedBy ? { openedBySegmentId: openedBy } : {}),
      filled: false,
      note: `缺口 [${start}, ${end}) 共 ${end - start} 字节：数据未到达，接收方会重复 ACK 请求重传`
    });
  }
  // 曾被乱序到达打开、后被重传填补的缺口也要保留，才能讲清"缺口 → 重传 → 恢复"的完整过程
  for (const hole of recoveredHoles) {
    gaps.push({
      start: hole.start - base,
      end: hole.end - base,
      length: hole.end - hole.start,
      openedBySegmentId: hole.openedBy,
      filledBySegmentId: hole.filledBy,
      filled: true,
      note: `缺口 [${hole.start - base}, ${hole.end - base}) 共 ${hole.end - hole.start} 字节，曾由重传段填补`
    });
  }
  gaps.sort((a, b) => a.start - b.start);
  const overlaps = computeOverlapRegions(dataSegments, base);

  const totalSpan = dataSegments.reduce((sum, segment) => sum + segment.span, 0);
  const uniqueBytes = coverage.reduce((sum, interval) => sum + interval.end - interval.start, 0);
  const maxEnd = dataSegments.length ? Math.max(...dataSegments.map((segment) => segment.end)) : base;
  const retransmittedSegments = segments.filter((segment) => {
    const status = statusById.get(segment.id)?.status;
    return status === 'retransmission' || status === 'duplicate' || status === 'overlap';
  }).length;

  const sorted = [...segments].sort((a, b) => a.start - b.start || a.captureOrder - b.captureOrder);
  const analyses: StreamSegmentAnalysis[] = sorted.map((segment) => {
    const record = statusById.get(segment.id)!;
    return {
      id: segment.id,
      inputIndex: segment.inputIndex,
      captureOrder: segment.captureOrder,
      source: segment.source,
      destination: segment.destination,
      seq: segment.seq,
      seqEnd: segment.seq + segment.span >= UINT32 ? segment.seq + segment.span - UINT32 : segment.seq + segment.span,
      payloadLength: segment.payloadLength,
      flags: segment.flags,
      streamOffset: segment.start - base,
      rangeStart: segment.start - base,
      rangeEnd: segment.end - base,
      status: record.status,
      anomalies: record.anomalies,
      note: record.notes.join('；')
    };
  });

  return {
    stream: {
      key,
      source,
      destination,
      baseSeq: segments.find((segment) => segment.start === base)?.seq ?? segments[0].seq,
      wrapAround: wrap,
      segments: analyses,
      coverage,
      gaps,
      overlaps,
      streamLength: maxEnd - base,
      uniqueBytes,
      missingBytes: gaps.filter((gap) => !gap.filled).reduce((sum, gap) => sum + gap.length, 0),
      retransmittedBytes: totalSpan - uniqueBytes,
      retransmittedSegments
    },
    internal: { base, wrap, segments }
  };
}

function mergeIntervals(intervals: Array<[number, number]>): Array<[number, number]> {
  const sorted = [...intervals].sort((a, b) => a[0] - b[0]);
  const merged: Array<[number, number]> = [];
  for (const interval of sorted) {
    const last = merged[merged.length - 1];
    if (last && interval[0] <= last[1]) last[1] = Math.max(last[1], interval[1]);
    else merged.push([...interval]);
  }
  return merged;
}

/** 扫描线求被两个及以上段覆盖的序号区间（重叠区）。 */
function computeOverlapRegions(segments: WorkingSegment[], base: number): StreamOverlapRegion[] {
  const events: Array<{ position: number; delta: number; id: string }> = [];
  for (const segment of segments) {
    events.push({ position: segment.start, delta: 1, id: segment.id });
    events.push({ position: segment.end, delta: -1, id: segment.id });
  }
  events.sort((a, b) => a.position - b.position || a.delta - b.delta);

  const regions: StreamOverlapRegion[] = [];
  const active = new Set<string>();
  let cursor: number | null = null;
  for (const event of events) {
    if (cursor !== null && event.position > cursor && active.size >= 2) {
      const last = regions[regions.length - 1];
      if (last && last.end === cursor - base && last.segmentIds.join() === [...active].sort().join()) {
        last.end = event.position - base;
        last.length = last.end - last.start;
      } else {
        regions.push({
          start: cursor - base,
          end: event.position - base,
          length: event.position - cursor,
          segmentIds: [...active].sort()
        });
      }
    }
    if (event.delta > 0) active.add(event.id);
    else active.delete(event.id);
    cursor = event.position;
  }
  return regions;
}

/** 按捕获顺序计算每个段的 ACK 对对端流的覆盖进度（"ACK 是否覆盖前一段数据"）。 */
function applyAckCoverage(
  captureSorted: WorkingSegment[],
  directions: DirectionStream[],
  internals: Map<string, DirectionInternal>
): void {
  const analysisById = new Map<string, StreamSegmentAnalysis>();
  for (const direction of directions) {
    for (const segment of direction.segments) analysisById.set(segment.id, segment);
  }
  const frontierByDirection = new Map<string, number>();

  for (const segment of captureSorted) {
    const ownKey = directionKeyOf(segment.source, segment.destination);
    const peerKey = directionKeyOf(segment.destination, segment.source);
    const peer = internals.get(peerKey);
    const analysis = analysisById.get(segment.id);

    if (analysis && segment.ack !== undefined && peer) {
      const normalizeAck = (ack: number) => (peer.wrap && ack < UINT31 ? ack + UINT32 : ack);
      const ackNorm = normalizeAck(segment.ack);
      const ackedBytes = Math.max(0, ackNorm - peer.base);
      const peerFrontier = frontierByDirection.get(peerKey);
      const peerSentBytes = peerFrontier !== undefined ? Math.max(0, peerFrontier - peer.base) : 0;
      const coversPeerStream = peerFrontier !== undefined ? ackNorm >= peerFrontier : true;
      let note: string;
      if (peerFrontier === undefined) {
        note = `对端数据尚未在捕获中出现，Ack=${segment.ack} 属于连接初始确认`;
      } else if (coversPeerStream) {
        note = `Ack=${segment.ack} 覆盖对端已发送的全部 ${peerSentBytes} 字节（累计确认到位）`;
      } else {
        note = `Ack=${segment.ack} 仅确认到对端流偏移 ${ackedBytes}，但对端已发送 ${peerSentBytes} 字节（落后 ${peerSentBytes - ackedBytes} 字节）→ 可能存在丢包或乱序`;
      }
      const coverage: AckCoverage = {
        ack: segment.ack,
        ackedBytes,
        peerSentBytes,
        coversPeerStream,
        note
      };
      analysis.ackCoverage = coverage;
    }

    if (segment.span > 0) {
      frontierByDirection.set(ownKey, Math.max(frontierByDirection.get(ownKey) ?? 0, segment.end));
    }
  }
}

// ---- 模拟捕获会话 ----

const CLIENT_A = '10.0.0.24:51842';
const SERVER_A = '10.0.0.8:443';
const CLIENT_B = '10.0.0.30:49152';
const SERVER_B = '10.0.0.8:80';

function timestamp(milliseconds: number): string {
  const totalSeconds = Math.floor(milliseconds / 1000);
  const minutes = String(Math.floor(totalSeconds / 60)).padStart(2, '0');
  const seconds = String(totalSeconds % 60).padStart(2, '0');
  const millis = String(milliseconds % 1000).padStart(3, '0');
  return `00:${minutes}:${seconds}.${millis}`;
}

interface SegmentSpec {
  source: string;
  destination: string;
  seq: number;
  ack?: number;
  flags: string[];
  payloadLength: number;
  at: number;
}

function sessionFrom(
  scenario: TcpStreamScenario,
  label: string,
  description: string,
  teachingPoints: string[],
  specs: SegmentSpec[]
): TcpCaptureSession {
  const segments: CapturedTcpSegment[] = specs.map((spec, index) => ({
    id: `seg-${scenario}-${index + 1}`,
    source: spec.source,
    destination: spec.destination,
    seq: spec.seq,
    ...(spec.ack !== undefined ? { ack: spec.ack } : {}),
    flags: spec.flags,
    payloadLength: spec.payloadLength,
    capturedAt: timestamp(spec.at)
  }));
  return { id: `session-${scenario}`, scenario, label, description, teachingPoints, segments };
}

export const TCP_STREAM_SCENARIOS: TcpStreamScenario[] = ['textbook', 'lossy', 'wrap', 'mixed'];

export function buildCaptureSession(scenario: TcpStreamScenario): TcpCaptureSession {
  switch (scenario) {
    case 'lossy':
      return sessionFrom(
        'lossy',
        '丢包与重传会话',
        '中间段丢失引发缺口，随后重传填补；另包含完整重传、重复段与部分重叠，ACK 在缺口前停滞。',
        [
          '捕获 #5 跳过序号到达 → 产生缺口，接收方 ACK 停在缺口前',
          '捕获 #8 的重传段填补缺口，字节流恢复连续',
          '捕获 #9 / #10 演示完整重传与部分重叠（重新分段）',
          '观察每个段在逻辑字节流中的范围，而非仅看列表顺序'
        ],
        [
          { source: CLIENT_A, destination: SERVER_A, seq: 1000, flags: ['SYN'], payloadLength: 0, at: 0 },
          { source: SERVER_A, destination: CLIENT_A, seq: 5000, ack: 1001, flags: ['SYN', 'ACK'], payloadLength: 0, at: 35 },
          { source: CLIENT_A, destination: SERVER_A, seq: 1001, ack: 5001, flags: ['ACK'], payloadLength: 0, at: 70 },
          { source: CLIENT_A, destination: SERVER_A, seq: 1001, ack: 5001, flags: ['ACK', 'PSH'], payloadLength: 300, at: 120 },
          { source: CLIENT_A, destination: SERVER_A, seq: 1601, ack: 5001, flags: ['ACK', 'PSH'], payloadLength: 300, at: 125 },
          { source: SERVER_A, destination: CLIENT_A, seq: 5001, ack: 1301, flags: ['ACK'], payloadLength: 0, at: 170 },
          { source: SERVER_A, destination: CLIENT_A, seq: 5001, ack: 1301, flags: ['ACK', 'PSH'], payloadLength: 200, at: 180 },
          { source: CLIENT_A, destination: SERVER_A, seq: 1301, ack: 5201, flags: ['ACK', 'PSH'], payloadLength: 300, at: 430 },
          { source: CLIENT_A, destination: SERVER_A, seq: 1001, ack: 5201, flags: ['ACK', 'PSH'], payloadLength: 300, at: 435 },
          { source: CLIENT_A, destination: SERVER_A, seq: 1801, ack: 5201, flags: ['ACK', 'PSH'], payloadLength: 200, at: 440 },
          { source: SERVER_A, destination: CLIENT_A, seq: 5201, ack: 2001, flags: ['ACK'], payloadLength: 0, at: 500 },
          { source: SERVER_A, destination: CLIENT_A, seq: 5201, ack: 2001, flags: ['ACK', 'PSH'], payloadLength: 256, at: 540 }
        ]
      );
    case 'wrap':
      return sessionFrom(
        'wrap',
        '序号回绕会话',
        '初始序号接近 2^32，传输过程中序号回绕到小数值，演示模 2^32 的序号算术。',
        [
          'ISN = 4294967200，接近 2^32 = 4294967296 上限',
          '捕获 #4 的数据跨越回绕点：尾部序号从 4294967295 回到 4',
          '后续段使用回绕后的小序号，直接按数值排序会得到错误顺序',
          '服务端按模 2^32 算术归一化后再确定逻辑流范围'
        ],
        [
          { source: CLIENT_A, destination: SERVER_A, seq: 4294967200, flags: ['SYN'], payloadLength: 0, at: 0 },
          { source: SERVER_A, destination: CLIENT_A, seq: 8000, ack: 4294967201, flags: ['SYN', 'ACK'], payloadLength: 0, at: 30 },
          { source: CLIENT_A, destination: SERVER_A, seq: 4294967201, ack: 8001, flags: ['ACK'], payloadLength: 0, at: 60 },
          { source: CLIENT_A, destination: SERVER_A, seq: 4294967201, ack: 8001, flags: ['ACK', 'PSH'], payloadLength: 100, at: 100 },
          { source: CLIENT_A, destination: SERVER_A, seq: 5, ack: 8001, flags: ['ACK', 'PSH'], payloadLength: 100, at: 140 },
          { source: CLIENT_A, destination: SERVER_A, seq: 105, ack: 8001, flags: ['ACK', 'PSH'], payloadLength: 50, at: 180 },
          { source: SERVER_A, destination: CLIENT_A, seq: 8001, ack: 155, flags: ['ACK', 'PSH'], payloadLength: 128, at: 220 },
          { source: SERVER_A, destination: CLIENT_A, seq: 8129, ack: 155, flags: ['ACK', 'PSH'], payloadLength: 64, at: 260 }
        ]
      );
    case 'mixed':
      return sessionFrom(
        'mixed',
        '混合捕获（两条连接）',
        '同一捕获文件中交错出现两条 TCP 连接的段，演示按连接五元组拆分后再重建。',
        [
          '选择中包含两条连接：10.0.0.24:51842↔10.0.0.8:443 与 10.0.0.30:49152↔10.0.0.8:80',
          '不同连接的序号空间相互独立，不能放在同一条流里排序',
          '服务端按连接拆分后分别重建，并给出混用警告'
        ],
        [
          { source: CLIENT_A, destination: SERVER_A, seq: 1000, flags: ['SYN'], payloadLength: 0, at: 0 },
          { source: CLIENT_B, destination: SERVER_B, seq: 60000, flags: ['SYN'], payloadLength: 0, at: 10 },
          { source: SERVER_A, destination: CLIENT_A, seq: 5000, ack: 1001, flags: ['SYN', 'ACK'], payloadLength: 0, at: 40 },
          { source: SERVER_B, destination: CLIENT_B, seq: 90000, ack: 60001, flags: ['SYN', 'ACK'], payloadLength: 0, at: 50 },
          { source: CLIENT_A, destination: SERVER_A, seq: 1001, ack: 5001, flags: ['ACK', 'PSH'], payloadLength: 120, at: 80 },
          { source: CLIENT_B, destination: SERVER_B, seq: 60001, ack: 90001, flags: ['ACK', 'PSH'], payloadLength: 80, at: 90 },
          { source: SERVER_A, destination: CLIENT_A, seq: 5001, ack: 1121, flags: ['ACK', 'PSH'], payloadLength: 200, at: 120 },
          { source: SERVER_B, destination: CLIENT_B, seq: 90001, ack: 60081, flags: ['ACK', 'PSH'], payloadLength: 96, at: 130 },
          { source: CLIENT_B, destination: SERVER_B, seq: 60081, ack: 90097, flags: ['ACK', 'PSH'], payloadLength: 80, at: 160 },
          { source: CLIENT_A, destination: SERVER_A, seq: 1121, ack: 5201, flags: ['ACK', 'PSH'], payloadLength: 120, at: 200 },
          { source: SERVER_A, destination: CLIENT_A, seq: 5201, ack: 1241, flags: ['ACK'], payloadLength: 0, at: 240 }
        ]
      );
    case 'textbook':
    default:
      return sessionFrom(
        'textbook',
        '标准有序会话',
        '三次握手后双向各发送两段数据，全部按序到达，ACK 始终覆盖对端已发送数据。',
        [
          'SYN / FIN 各占用 1 个序号（幻影字节），数据从 ISN+1 开始',
          '每个数据段的 Seq 恰好衔接上一段末尾 → 流位置连续推进',
          '每个 ACK 都覆盖对端已发送的全部字节',
          '可尝试取消勾选中间的段，观察缺口如何出现'
        ],
        [
          { source: CLIENT_A, destination: SERVER_A, seq: 1000, flags: ['SYN'], payloadLength: 0, at: 0 },
          { source: SERVER_A, destination: CLIENT_A, seq: 5000, ack: 1001, flags: ['SYN', 'ACK'], payloadLength: 0, at: 40 },
          { source: CLIENT_A, destination: SERVER_A, seq: 1001, ack: 5001, flags: ['ACK'], payloadLength: 0, at: 80 },
          { source: CLIENT_A, destination: SERVER_A, seq: 1001, ack: 5001, flags: ['ACK', 'PSH'], payloadLength: 200, at: 120 },
          { source: CLIENT_A, destination: SERVER_A, seq: 1201, ack: 5001, flags: ['ACK', 'PSH'], payloadLength: 200, at: 160 },
          { source: SERVER_A, destination: CLIENT_A, seq: 5001, ack: 1401, flags: ['ACK', 'PSH'], payloadLength: 512, at: 240 },
          { source: SERVER_A, destination: CLIENT_A, seq: 5513, ack: 1401, flags: ['ACK', 'PSH'], payloadLength: 512, at: 280 },
          { source: CLIENT_A, destination: SERVER_A, seq: 1401, ack: 6025, flags: ['ACK'], payloadLength: 0, at: 340 }
        ]
      );
  }
}
