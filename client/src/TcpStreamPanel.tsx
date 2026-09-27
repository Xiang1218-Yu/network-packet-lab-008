import { useEffect, useMemo, useState } from 'react';
import type {
  ConnectionReassembly,
  DirectionStream,
  StreamSegmentStatus,
  TcpCaptureSession,
  TcpReassembleResponse,
  TcpSegmentInput,
  TcpStreamScenario
} from '../../shared/types';
import { API_BASE } from './api';

const scenarioOptions: { value: TcpStreamScenario; label: string }[] = [
  { value: 'textbook', label: '标准会话 / 有序传输' },
  { value: 'lossy', label: '丢包重传 / 缺口与重叠' },
  { value: 'wrap', label: '序号回绕 / 2³² 边界' },
  { value: 'mixed', label: '混合连接 / 多条会话' }
];

const statusLabels: Record<StreamSegmentStatus, string> = {
  'in-order': '按序',
  'out-of-order': '乱序到达',
  overlap: '部分重叠',
  retransmission: '完整重传',
  duplicate: '重复段',
  control: '控制段'
};

const anomalyLabels: Record<string, string> = {
  RETRANSMISSION: '重传',
  DUPLICATE: '重复',
  OVERLAP: '重叠',
  GAP_BEFORE: '前方缺口',
  WRAP_AROUND: '序号回绕',
  CONTROL_ONLY: '不占序号'
};

export default function TcpStreamPanel() {
  const [scenario, setScenario] = useState<TcpStreamScenario>('lossy');
  const [session, setSession] = useState<TcpCaptureSession | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [displayOrder, setDisplayOrder] = useState<string[]>([]);
  const [result, setResult] = useState<TcpReassembleResponse | null>(null);
  const [sentUnsorted, setSentUnsorted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [reassembling, setReassembling] = useState(false);
  const [error, setError] = useState('');

  const loadSession = async (nextScenario = scenario) => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch(`${API_BASE}/api/tcp/session?scenario=${nextScenario}`);
      if (!response.ok) throw new Error(`API 请求失败：${response.status}`);
      const body = (await response.json()) as { data: TcpCaptureSession };
      setSession(body.data);
      setSelected(new Set(body.data.segments.map((segment) => segment.id)));
      setDisplayOrder(body.data.segments.map((segment) => segment.id));
      setResult(null);
      setSentUnsorted(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '加载捕获会话失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadSession('lossy');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const segmentById = useMemo(() => {
    const map = new Map(session?.segments.map((segment) => [segment.id, segment]) ?? []);
    return map;
  }, [session]);

  const directionsInSession = useMemo(() => {
    if (!session) return [];
    const keys = new Set<string>();
    for (const segment of session.segments) keys.add(`${segment.source}→${segment.destination}`);
    return [...keys];
  }, [session]);

  const toggleSegment = (id: string) => {
    setSelected((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectOnly = (predicate: (segment: TcpSegmentInput & { id: string }) => boolean) => {
    if (!session) return;
    setSelected(new Set(session.segments.filter(predicate).map((segment) => segment.id)));
  };

  const shuffleOrder = () => {
    setDisplayOrder((previous) => {
      const next = [...previous];
      for (let index = next.length - 1; index > 0; index -= 1) {
        const target = Math.floor(Math.random() * (index + 1));
        [next[index], next[target]] = [next[target], next[index]];
      }
      return next;
    });
  };

  const reassemble = async () => {
    if (!session) return;
    const chosen = displayOrder.filter((id) => selected.has(id)).map((id) => segmentById.get(id)!);
    if (chosen.length === 0) return; // 空选择：按钮已禁用，这里兜底
    // 乱序输入检测：提交的段按当前展示顺序发送，检查其序号是否非递减
    const seqs = chosen.map((segment) => segment.seq);
    const unsorted = seqs.some((seq, index) => index > 0 && seq < seqs[index - 1]);
    setReassembling(true);
    setError('');
    try {
      const response = await fetch(`${API_BASE}/api/tcp/reassemble`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ segments: chosen })
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body?.error ?? `API 请求失败：${response.status}`);
      setResult((body as { data: TcpReassembleResponse }).data);
      setSentUnsorted(unsorted);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '流重建失败');
      setResult(null);
    } finally {
      setReassembling(false);
    }
  };

  return (
    <section className="panel stream-panel">
      <div className="panel-heading">
        <div>
          <p className="section-kicker">03 / STREAM REASSEMBLY</p>
          <h3>TCP 流重建</h3>
        </div>
        <span className="badge">CROSS-PACKET</span>
      </div>
      <p className="stream-intro">
        从捕获会话中勾选多个 TCP 段，服务端按序号重建逻辑字节流，识别重传、缺口、重叠与方向切换，并解释每个 ACK 的覆盖进度。
      </p>

      <div className="stream-toolbar">
        <label className="stream-scenario-label">
          捕获会话
          <select value={scenario} onChange={(event) => { const next = event.target.value as TcpStreamScenario; setScenario(next); void loadSession(next); }}>
            {scenarioOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select>
        </label>
        <button className="button ghost" onClick={() => void loadSession()} disabled={loading}>↻ 重新载入</button>
        {session && <span className="stream-session-meta">{session.label} · {session.segments.length} 段</span>}
      </div>

      {session && (
        <>
          <p className="stream-session-desc">{session.description}</p>
          <div className="stream-teaching">
            {session.teachingPoints.map((point, index) => <span className="stream-teaching-chip" key={index}>{point}</span>)}
          </div>

          <div className="stream-select-bar">
            <button onClick={() => selectOnly(() => true)}>全选</button>
            <button onClick={() => setSelected(new Set())}>清空</button>
            {directionsInSession.map((direction) => (
              <button key={direction} onClick={() => selectOnly((segment) => `${segment.source}→${segment.destination}` === direction)}>
                仅选 {direction}
              </button>
            ))}
            <button onClick={shuffleOrder} title="打乱勾选段的提交顺序，验证服务端按序号重排">打乱顺序</button>
            <button onClick={() => setDisplayOrder(session.segments.map((segment) => segment.id))}>恢复捕获顺序</button>
            <span className="stream-selected-count">已选 {selected.size} / {session.segments.length} 段</span>
          </div>

          <div className="stream-table-wrap">
            <table className="stream-table">
              <thead>
                <tr><th /><th>捕获#</th><th>时间</th><th>方向</th><th>Flags</th><th>Seq</th><th>Ack</th><th>Len</th></tr>
              </thead>
              <tbody>
                {displayOrder.map((id, index) => {
                  const segment = segmentById.get(id);
                  if (!segment) return null;
                  const isSelected = selected.has(id);
                  return (
                    <tr key={id} className={isSelected ? 'selected' : 'dimmed'} onClick={() => toggleSegment(id)}>
                      <td><input type="checkbox" checked={isSelected} onChange={() => toggleSegment(id)} onClick={(event) => event.stopPropagation()} /></td>
                      <td>{index + 1}</td>
                      <td>{segment.capturedAt}</td>
                      <td className="stream-direction-cell">{segment.source} → {segment.destination}</td>
                      <td>{segment.flags?.join(',') || '—'}</td>
                      <td>{segment.seq}</td>
                      <td>{segment.ack ?? '—'}</td>
                      <td>{segment.payloadLength}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="stream-actions">
            <button className="button primary" onClick={() => void reassemble()} disabled={reassembling || selected.size === 0}>
              {reassembling ? '重建中…' : '重建字节流 →'}
            </button>
            {selected.size === 0 && <span className="stream-hint">空选择无法重建：请先在上方勾选至少一个 TCP 段</span>}
            {selected.size > 0 && <span className="stream-hint subtle">将按当前表格顺序提交 {selected.size} 个段，服务端按序号重建</span>}
          </div>
        </>
      )}

      {error && <div className="error-banner stream-error">⚠ {error} <button onClick={() => setError('')}>关闭</button></div>}

      {result && <StreamResult result={result} sentUnsorted={sentUnsorted} />}
    </section>
  );
}

function StreamResult({ result, sentUnsorted }: { result: TcpReassembleResponse; sentUnsorted: boolean }) {
  return (
    <div className="stream-result">
      <div className="stream-result-head">
        <p className="section-kicker">REASSEMBLY RESULT</p>
        <div className="stream-chips">
          <span className="stream-chip">{result.totals.segments} 段</span>
          <span className="stream-chip">{result.totals.connections} 条连接</span>
          <span className="stream-chip">{result.totals.directions} 个方向</span>
          <span className="stream-chip warn">{result.totals.retransmittedSegments} 段重传</span>
          <span className="stream-chip warn">{result.totals.gaps} 个开放缺口</span>
          <span className="stream-chip">{result.orderingBasis === 'capturedAt' ? '按捕获时间排序' : '按提交顺序排序'}</span>
        </div>
      </div>

      {sentUnsorted && (
        <div className="stream-banner info">↔ 检测到乱序输入：提交的段并非按序号排列，服务端已按序号重建逻辑流（下表捕获# 列保留原始到达顺序）。</div>
      )}
      {result.warnings.map((warning, index) => (
        <div className={`stream-banner ${warning.code === 'WRAP_AROUND' ? 'wrap' : 'warn'}`} key={index}>⚠ {warning.message}</div>
      ))}

      {result.connections.map((connection) => <ConnectionView key={connection.key} connection={connection} />)}
    </div>
  );
}

function ConnectionView({ connection }: { connection: ConnectionReassembly }) {
  return (
    <div className="stream-connection">
      <div className="stream-connection-head">
        <h4>连接 · {connection.endpoints[0]} ↔ {connection.endpoints[1]}</h4>
        <div className="stream-chips">
          <span className="stream-chip">{connection.segmentCount} 段</span>
          <span className="stream-chip">{connection.directions.length} 个方向</span>
          {connection.directionSwitches.length > 0 && (
            <span className="stream-chip warn">方向切换 {connection.directionSwitches.length} 次</span>
          )}
        </div>
      </div>
      {connection.directionSwitches.length > 0 && (
        <div className="stream-switches">
          {connection.directionSwitches.map((item, index) => (
            <span key={index}>捕获 #{item.captureOrder + 1}：{item.from} ⇄ {item.to}</span>
          ))}
        </div>
      )}
      {connection.directions.map((direction) => <DirectionView key={direction.key} direction={direction} />)}
    </div>
  );
}

function DirectionView({ direction }: { direction: DirectionStream }) {
  const coveragePercent = direction.streamLength > 0
    ? Math.round((direction.uniqueBytes / direction.streamLength) * 100)
    : 100;
  return (
    <div className="stream-direction">
      <div className="stream-direction-head">
        <strong>{direction.source} → {direction.destination}</strong>
        <span className="stream-chip">基准 Seq = {direction.baseSeq}</span>
        {direction.wrapAround && <span className="stream-chip wrap">↺ 序号回绕：已按 +2³² 归一化排序</span>}
      </div>
      <div className="stream-chips stats">
        <span className="stream-chip">流长度 {direction.streamLength} B</span>
        <span className="stream-chip">唯一字节 {direction.uniqueBytes} B</span>
        <span className="stream-chip">覆盖率 {coveragePercent}%</span>
        <span className="stream-chip warn">重传 {direction.retransmittedSegments} 段 / {direction.retransmittedBytes} B</span>
        <span className="stream-chip warn">缺失 {direction.missingBytes} B</span>
      </div>

      <StreamMap direction={direction} />

      {direction.gaps.length > 0 && (
        <div className="stream-gaps">
          {direction.gaps.map((gap, index) => (
            <div className={`stream-gap ${gap.filled ? 'filled' : 'open'}`} key={index}>
              {gap.filled ? '✓' : '⚠'} {gap.note}
              {gap.filledBySegmentId && <em>（由段 {gap.filledBySegmentId} 填补）</em>}
            </div>
          ))}
        </div>
      )}

      <table className="stream-table analysis">
        <thead>
          <tr><th>捕获#</th><th>状态</th><th>Seq → 结束</th><th>流范围</th><th>Len</th><th>Flags</th><th>ACK 覆盖</th><th>说明</th></tr>
        </thead>
        <tbody>
          {direction.segments.map((segment) => (
            <tr key={segment.id}>
              <td>#{segment.captureOrder + 1}</td>
              <td>
                <span className={`status-badge status-${segment.status}`}>{statusLabels[segment.status]}</span>
                {segment.anomalies.filter((anomaly) => anomaly === 'WRAP_AROUND').map((anomaly) => (
                  <span className="anomaly-chip" key={anomaly}>{anomalyLabels[anomaly]}</span>
                ))}
              </td>
              <td className="mono">{segment.seq} → {segment.seqEnd}</td>
              <td className="mono">[{segment.rangeStart}, {segment.rangeEnd})</td>
              <td className="mono">{segment.payloadLength}</td>
              <td className="mono">{segment.flags.join(',') || '—'}</td>
              <td className={segment.ackCoverage ? (segment.ackCoverage.coversPeerStream ? 'ack-ok' : 'ack-lag') : 'mono'}>
                {segment.ackCoverage
                  ? segment.ackCoverage.coversPeerStream
                    ? `✓ 覆盖对端 ${segment.ackCoverage.ackedBytes} B`
                    : `⚠ 落后 ${segment.ackCoverage.peerSentBytes - segment.ackCoverage.ackedBytes} B`
                  : '—'}
              </td>
              <td className="stream-note">{segment.note}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function StreamMap({ direction }: { direction: DirectionStream }) {
  const length = Math.max(direction.streamLength, 1);
  const pct = (value: number) => `${(value / length) * 100}%`;
  const widthOf = (span: number) => `max(${(span / length) * 100}%, 3px)`;
  return (
    <div className="stream-map">
      <div className="stream-map-axis">
        <span>偏移 0 · Seq {direction.baseSeq}</span>
        <span>逻辑字节流 · {direction.streamLength} 字节</span>
        <span>偏移 {direction.streamLength}</span>
      </div>
      <div className="stream-map-row">
        <span className="stream-map-label">重组流</span>
        <div className="stream-map-track">
          {direction.coverage.map((interval, index) => (
            <div
              className="stream-block covered"
              key={`c-${index}`}
              style={{ left: pct(interval.start), width: widthOf(interval.end - interval.start) }}
              title={`已覆盖 [${interval.start}, ${interval.end})`}
            />
          ))}
          {direction.gaps.filter((gap) => !gap.filled).map((gap, index) => (
            <div
              className="stream-block gap"
              key={`g-${index}`}
              style={{ left: pct(gap.start), width: widthOf(gap.length) }}
              title={`缺口 [${gap.start}, ${gap.end}) · ${gap.length} 字节未到达`}
            />
          ))}
        </div>
      </div>
      {direction.segments.map((segment) => (
        <div className="stream-map-row" key={segment.id}>
          <span className="stream-map-label">#{segment.captureOrder + 1}</span>
          <div className="stream-map-track">
            <div
              className={`stream-block seg status-${segment.status}`}
              style={{ left: pct(segment.rangeStart), width: widthOf(segment.rangeEnd - segment.rangeStart) }}
              title={`捕获 #${segment.captureOrder + 1} · Seq=${segment.seq} · 流范围 [${segment.rangeStart}, ${segment.rangeEnd}) · ${statusLabels[segment.status]}`}
            />
          </div>
        </div>
      ))}
      <div className="stream-map-legend">
        <span><i className="dot status-in-order" />按序</span>
        <span><i className="dot status-out-of-order" />乱序到达</span>
        <span><i className="dot status-retransmission" />完整重传</span>
        <span><i className="dot status-duplicate" />重复段</span>
        <span><i className="dot status-overlap" />部分重叠</span>
        <span><i className="dot status-control" />控制段</span>
        <span><i className="dot gap" />缺口</span>
      </div>
    </div>
  );
}
