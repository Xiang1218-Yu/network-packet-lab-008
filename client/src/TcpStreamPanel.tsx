import { useEffect, useMemo, useState } from 'react';
import type {
  CaptureScenario,
  CaptureSession,
  TcpAnomaly,
  TcpDirectionSummary,
  TcpSegmentAnalysis,
  TcpStreamEvent,
  TcpStreamReassembly
} from '../../shared/types';

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:3001';

const scenarioOptions: Array<{ value: CaptureScenario; label: string }> = [
  { value: 'standard', label: '标准会话' },
  { value: 'loss', label: '丢包与重传' },
  { value: 'wraparound', label: '序号回绕' },
  { value: 'mixed', label: '混用连接' }
];

const anomalyLabels: Record<TcpAnomaly, string> = {
  retransmission: '重传',
  overlap: '重叠',
  'gap-before': '前置缺口',
  'duplicate-ack': '重复 ACK',
  'wrap-suspect': '回绕可疑'
};

const eventIcons: Record<TcpStreamEvent['type'], string> = {
  retransmission: '↺',
  gap: '⚡',
  overlap: '⇄',
  'direction-switch': '⇋',
  wraparound: '∞',
  'duplicate-ack': '⚠'
};

export function TcpStreamPanel() {
  const [scenario, setScenario] = useState<CaptureScenario>('standard');
  const [session, setSession] = useState<CaptureSession | null>(null);
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [result, setResult] = useState<TcpStreamReassembly | null>(null);
  const [loadingSession, setLoadingSession] = useState(false);
  const [rebuilding, setRebuilding] = useState(false);
  const [error, setError] = useState('');

  const loadSession = async (next: CaptureScenario) => {
    setLoadingSession(true);
    setError('');
    setResult(null);
    try {
      const response = await fetch(`${API_BASE}/api/capture-session?scenario=${next}`);
      if (!response.ok) throw new Error(`API 请求失败：${response.status}`);
      const payload = (await response.json()) as { data: CaptureSession };
      setSession(payload.data);
      setSelected(new Set(payload.data.segments.map((segment) => segment.id)));
    } catch (cause) {
      setSession(null);
      setSelected(new Set());
      setError(cause instanceof Error ? cause.message : '载入捕获会话失败');
    } finally {
      setLoadingSession(false);
    }
  };

  useEffect(() => {
    void loadSession(scenario);
  }, [scenario]);

  const toggleSegment = (id: string) => {
    setSelected((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const rebuild = async () => {
    if (!session) return;
    // 始终按捕获顺序提交，乱序整理交给服务端重建逻辑
    const chosen = session.segments.filter((segment) => selected.has(segment.id));
    if (chosen.length === 0) {
      setError('未选择任何 TCP 段：请先在捕获会话中勾选至少一个段');
      return;
    }
    setRebuilding(true);
    setError('');
    try {
      const response = await fetch(`${API_BASE}/api/tcp-stream/reassemble`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          segments: chosen.map((segment) => ({
            id: segment.id,
            source: segment.source,
            destination: segment.destination,
            seq: segment.seq,
            ack: segment.ack,
            flags: segment.flags,
            payloadLength: segment.payloadLength
          }))
        })
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(typeof payload.error === 'string' ? payload.error : `API 请求失败：${response.status}`);
      setResult(payload.data as TcpStreamReassembly);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '流重建失败');
    } finally {
      setRebuilding(false);
    }
  };

  const segmentById = useMemo(
    () => new Map((result?.segments ?? []).map((segment) => [segment.id, segment])),
    [result]
  );

  return (
    <section className="panel stream-panel">
      <div className="panel-heading">
        <div>
          <p className="section-kicker">03 / TCP STREAM · CROSS-PACKET VIEW</p>
          <h3>TCP 流重建</h3>
        </div>
        <span className="badge">SEQ / ACK</span>
      </div>

      <div className="stream-controls">
        <div className="control-group">
          <label>捕获会话 <span>SESSION</span></label>
          <select value={scenario} onChange={(event) => setScenario(event.target.value as CaptureScenario)}>
            {scenarioOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select>
        </div>
        <div className="stream-selection-actions">
          <button className="button ghost" onClick={() => session && setSelected(new Set(session.segments.map((segment) => segment.id)))} disabled={!session || loadingSession}>全选</button>
          <button className="button ghost" onClick={() => setSelected(new Set())} disabled={!session || selected.size === 0}>清空</button>
          <button className="button primary" onClick={() => void rebuild()} disabled={rebuilding || loadingSession || !session || selected.size === 0}>
            {rebuilding ? '重建中…' : `重建 TCP 流 →${selected.size > 0 ? `（${selected.size} 段）` : ''}`}
          </button>
        </div>
      </div>

      {session && <p className="session-description">{session.title} — {session.description}</p>}
      {selected.size === 0 && session && <p className="selection-hint">⚠ 当前为空选择：未勾选任何段，无法重建。请至少勾选一个 TCP 段。</p>}

      <div className="session-table-wrap">
        {loadingSession ? (
          <div className="empty-state">正在载入捕获会话…</div>
        ) : !session ? (
          <div className="empty-state">捕获会话不可用。</div>
        ) : (
          <table className="session-table">
            <thead>
              <tr><th /><th>#</th><th>捕获时间</th><th>方向</th><th>Seq</th><th>Ack</th><th>Flags</th><th>Len</th></tr>
            </thead>
            <tbody>
              {session.segments.map((segment) => (
                <tr key={segment.id} className={selected.has(segment.id) ? 'row-selected' : ''} onClick={() => toggleSegment(segment.id)}>
                  <td><input type="checkbox" checked={selected.has(segment.id)} onChange={() => toggleSegment(segment.id)} onClick={(event) => event.stopPropagation()} /></td>
                  <td>{segment.order}</td>
                  <td>{segment.capturedAt}</td>
                  <td className="endpoint-cell">{segment.source} → {segment.destination}</td>
                  <td>{segment.seq}</td>
                  <td>{segment.ack}</td>
                  <td>{segment.flags.join(',')}</td>
                  <td>{segment.payloadLength}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {error && <div className="error-banner">⚠ {error} <button onClick={() => setError('')}>关闭</button></div>}

      {!result && !error && <div className="empty-state">勾选段后点击「重建 TCP 流」，这里将展示按序号展开的跨包关系视图。</div>}

      {result && (
        <div className="stream-result">
          {result.warnings.map((warning) => <div key={warning} className="warning-banner">⚠ {warning}</div>)}

          {result.ignored.length > 0 && (
            <div className="ignored-box">
              <strong>已排除 {result.ignored.length} 个其他连接的段：</strong>
              {result.ignored.map((item) => <div key={item.id} className="ignored-item"><code>{item.id}</code> {item.reason}</div>)}
            </div>
          )}

          <div className="connection-summary">
            <div className="connection-endpoints">
              <span className="endpoint-chip">{result.connection.a}</span>
              <span className="endpoint-arrow">⇄</span>
              <span className="endpoint-chip">{result.connection.b}</span>
            </div>
            <div className="stat-chips">
              <span className="stat-chip">分析 <strong>{result.stats.analyzed}</strong>/{result.stats.selected} 段</span>
              <span className="stat-chip">重传 <strong>{result.stats.retransmissions}</strong></span>
              <span className="stat-chip">缺口 <strong>{result.stats.gaps}</strong></span>
              <span className="stat-chip">重叠 <strong>{result.stats.overlaps}</strong></span>
              <span className="stat-chip">方向切换 <strong>{result.stats.directionSwitches}</strong></span>
              <span className="stat-chip">重复 ACK <strong>{result.stats.duplicateAcks}</strong></span>
            </div>
          </div>

          {result.directions.map((direction, index) => (
            <DirectionBlock key={direction.key} direction={direction} index={index} segmentById={segmentById} />
          ))}

          <div className="events-panel">
            <p className="section-kicker">STREAM EVENTS · 按捕获顺序</p>
            {result.events.length === 0 ? (
              <div className="empty-state">没有检测到重传、缺口、重叠或方向切换。</div>
            ) : (
              <div className="event-list">
                {result.events.map((event, index) => (
                  <div key={`${event.type}-${index}`} className={`event-item event-${event.type}`}>
                    <span className="event-icon">{eventIcons[event.type]}</span>
                    <span>{event.message}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

function DirectionBlock({ direction, index, segmentById }: {
  direction: TcpDirectionSummary;
  index: number;
  segmentById: Map<string, TcpSegmentAnalysis>;
}) {
  // 服务端返回的 segmentIds 已按流内偏移排序；不假设输入顺序
  const segments = direction.segmentIds
    .map((id) => segmentById.get(id))
    .filter((segment): segment is TcpSegmentAnalysis => Boolean(segment));

  return (
    <div className="direction-block">
      <div className="direction-header">
        <div>
          <p className="section-kicker">方向 {index === 0 ? '①' : '②'} · {direction.key === 'A_TO_B' ? 'A→B' : 'B→A'}</p>
          <h4>{direction.from} → {direction.to}</h4>
        </div>
        {direction.wraparound && <span className="wrap-badge">∞ 序号回绕</span>}
      </div>
      <div className="direction-meta">
        <span>基准序号 <strong>{direction.baseSeq}</strong>（{direction.baseSource === 'syn' ? '来自 SYN：ISN+1' : '按最小观测序号推断'}）</span>
        <span>连续覆盖 <strong>{direction.contiguousEnd}</strong> 字节</span>
        <span>唯一覆盖 <strong>{direction.coveredBytes}</strong> 字节</span>
        <span>未填补缺口 <strong>{direction.gaps.length}</strong> 处</span>
      </div>

      {segments.length === 0 ? (
        <div className="empty-state">该方向没有已分析的段。</div>
      ) : (
        <>
          <StreamDiagram direction={direction} segments={segments} />
          <div className="session-table-wrap">
            <table className="session-table segment-table">
              <thead>
                <tr><th>捕获#</th><th>流内范围</th><th>Seq</th><th>Ack</th><th>Flags</th><th>Len</th><th>状态与说明</th><th>ACK 解读</th></tr>
              </thead>
              <tbody>
                {segments.map((segment) => (
                  <tr key={segment.id}>
                    <td>#{segment.captureIndex + 1}</td>
                    <td className="range-cell">[{segment.streamStart}, {segment.streamEnd})</td>
                    <td>{segment.seq}</td>
                    <td>{segment.ack}</td>
                    <td>{segment.flags.join(',')}</td>
                    <td>{segment.payloadLength}</td>
                    <td className="status-cell">
                      {segment.anomalies.length > 0 && (
                        <span className="anomaly-chips">
                          {segment.anomalies.map((anomaly) => <span key={anomaly} className={`anomaly-chip chip-${anomaly}`}>{anomalyLabels[anomaly]}</span>)}
                        </span>
                      )}
                      {segment.notes.map((note) => <span key={note} className="segment-note">{note}</span>)}
                      {segment.anomalies.length === 0 && segment.notes.length === 0 && <span className="segment-note muted">按序到达，无异常</span>}
                    </td>
                    <td className="ack-cell">{segment.ackAnalysis ? segment.ackAnalysis.note : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

function StreamDiagram({ direction, segments }: { direction: TcpDirectionSummary; segments: TcpSegmentAnalysis[] }) {
  const span = Math.max(direction.spanEnd, 1);
  const pct = (value: number) => `${(value / span) * 100}%`;
  const barClass = (segment: TcpSegmentAnalysis): string => {
    if (segment.anomalies.includes('retransmission')) return 'is-retrans';
    if (segment.anomalies.includes('overlap')) return 'is-overlap';
    if (segment.flags.includes('SYN') || segment.flags.includes('FIN')) return 'is-control';
    if (segment.seqSpaceLength === 0) return 'is-empty';
    return '';
  };
  return (
    <div className="stream-diagram">
      <div className="stream-axis"><span>偏移 0</span><span>偏移 {direction.spanEnd}</span></div>
      <div className="stream-track">
        {direction.gaps.map((gap) => (
          <div
            key={`gap-${gap.start}-${gap.end}`}
            className="stream-gap"
            style={{ left: pct(gap.start), width: pct(gap.size) }}
            title={`未填补缺口：偏移 ${gap.start}–${gap.end - 1}（${gap.size} 字节）`}
          />
        ))}
        {segments.map((segment) => {
          const start = Math.max(0, segment.streamStart);
          const length = Math.max(segment.streamEnd - start, 0);
          return (
            <div
              key={segment.id}
              className={`stream-bar ${barClass(segment)}`}
              style={{ left: pct(start), width: `max(${pct(length)}, 4px)` }}
              title={`捕获 #${segment.captureIndex + 1} · 流内范围 [${segment.streamStart}, ${segment.streamEnd}) · Seq=${segment.seq}`}
            >
              <span>#{segment.captureIndex + 1}</span>
            </div>
          );
        })}
      </div>
      <div className="stream-legend">
        <span><i className="legend-swatch swatch-normal" /> 正常段</span>
        <span><i className="legend-swatch swatch-retrans" /> 重传</span>
        <span><i className="legend-swatch swatch-overlap" /> 重叠</span>
        <span><i className="legend-swatch swatch-control" /> SYN/FIN 控制段</span>
        <span><i className="legend-swatch swatch-empty" /> 纯 ACK（零长度）</span>
        <span><i className="legend-swatch swatch-gap" /> 未填补缺口</span>
      </div>
    </div>
  );
}
