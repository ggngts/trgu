<script setup lang="ts">
import { computed } from 'vue'
import { formatBytes } from '../api'
import { useAnalysisStore } from '../stores/analysis'
import { useSettingsStore, type MessageKey } from '../stores/settings'
import type { Severity } from '../types'

const store = useAnalysisStore()
const settings = useSettingsStore()

const scoreClass = computed(() => {
  const s = store.analysis?.threat_score ?? 0
  if (s >= 70) return 'bad'
  if (s >= 40) return 'mid'
  return 'good'
})

function sevClass(s: Severity) {
  return `sev-${s}`
}

function catLabel(c: string) {
  const map: Record<string, MessageKey> = {
    ddos: 'ddos', scan: 'scan', malware: 'malware', anomaly: 'anomaly',
  }
  const key = map[c]
  return key ? settings.t(key) : c
}

function severityLabel(severity: Severity) {
  const labels: Record<Severity, string> = settings.language === 'en'
    ? { info: 'info', low: 'low', medium: 'medium', high: 'high', critical: 'critical' }
    : { info: 'инфо', low: 'низкий', medium: 'средний', high: 'высокий', critical: 'критичный' }
  return labels[severity]
}

function indicator(threat: { indicators: string[] }, name: string) {
  return threat.indicators.find((value) => value.startsWith(`${name}=`))?.slice(name.length + 1) || '0'
}

function threatTitle(threat: { id: string; title: string }) {
  if (settings.language === 'ru') return threat.title
  if (threat.id.startsWith('scan-port-')) return 'Vertical port scan'
  if (threat.id.startsWith('scan-host-')) return 'Horizontal host scan'
  if (threat.id.startsWith('malware-port-')) return `Suspicious port ${threat.id.slice('malware-port-'.length)}`
  if (threat.id.startsWith('malware-exfil-')) return 'Possible data exfiltration'
  if (threat.id.startsWith('malware-beacon-')) return 'Possible C2 beaconing'
  const titles: Record<string, string> = {
    'ddos-syn-flood': 'Possible SYN flood',
    'ddos-udp-flood': 'Possible UDP flood',
    'ddos-icmp-flood': 'Possible ICMP flood',
    'ddos-high-pps': 'Unusually high packet rate',
    'scan-fin': 'Possible FIN / stealth scan',
    'scan-null': 'Possible NULL scan',
    'malware-dns-dga': 'Suspicious DNS names (DGA-like)',
    'malware-dns-flood': 'Unusual DNS volume',
    'malware-http-probe': 'Suspicious HTTP requests',
  }
  return titles[threat.id] || threat.title
}

function threatDescription(threat: { id: string; description: string; indicators: string[]; sources?: string[]; targets?: string[]; count?: number }) {
  if (settings.language === 'ru') return threat.description
  const metric = (key: string) => indicator(threat, key)
  switch (true) {
    case threat.id === 'ddos-syn-flood':
      return `${metric('syn_without_ack')} SYN packets without ACK and ${metric('syn_ack')} SYN-ACK packets (ratio ${metric('ratio')}). This pattern may indicate a TCP SYN flood.`
    case threat.id === 'ddos-udp-flood':
      return `${metric('udp_packets')} UDP packets (${metric('share')}% of capture). A high UDP share toward a small set of targets may indicate a flood or amplification.`
    case threat.id === 'ddos-icmp-flood':
      return `${metric('icmp_packets')} ICMP packets, including ${metric('echo_related')} echo-related packets. High echo traffic may indicate a ping flood.`
    case threat.id === 'ddos-high-pps':
      return `Average rate: ${metric('pps')} packets per second. A sustained high rate may indicate a flood or amplification attack.`
    case threat.id.startsWith('scan-port-'):
      return `${threat.sources?.[0] || 'A host'} → ${threat.targets?.[0] || 'a target'}: ${metric('unique_dst_ports')} unique destination ports, ${metric('sparse_hits')} with no more than two packets. This resembles a port scan.`
    case threat.id.startsWith('scan-host-'):
      return `${threat.sources?.[0] || 'A host'} probed ${metric('unique_dst_hosts')} hosts on destination port ${metric('dst_port')}. This resembles a network sweep.`
    case threat.id === 'scan-fin':
      return `${metric('fin_no_ack')} FIN packets without SYN/ACK. This pattern may indicate a stealth scan.`
    case threat.id === 'scan-null':
      return `${metric('null_like')} TCP-like packets without flags. This pattern may indicate a NULL scan.`
    case threat.id.startsWith('malware-port-'):
      return `Observed ${metric('packets')} packets on port ${threat.id.slice('malware-port-'.length)}. This port is commonly associated with backdoors, C2, or remote access tools.`
    case threat.id === 'malware-dns-dga':
      return `${metric('long_names')} long DNS names and ${metric('high_entropy')} high-entropy labels. This may indicate algorithmically generated domains or DNS tunneling.`
    case threat.id === 'malware-dns-flood':
      return `${metric('dns_packets')} DNS packets (${metric('share')}% of capture). The volume may indicate DNS tunneling or a DNS flood.`
    case threat.id.startsWith('malware-exfil-'):
      return `Host ${threat.id.slice('malware-exfil-'.length)} sent about ${(Number(metric('sent_bytes')) / 1e6).toFixed(1)} MB and received about ${(Number(metric('recv_bytes')) / 1e6).toFixed(1)} MB. This may indicate unusual outbound data transfer.`
    case threat.id.startsWith('malware-beacon-'):
      return `${metric('beacons')} repeated connection attempts at approximately ${metric('interval_sec')} second intervals (CV ${metric('cv')}). Regular callbacks may indicate C2 beaconing.`
    case threat.id === 'malware-http-probe':
      return `${threat.count || 0} requests matched exploitation or reconnaissance patterns, such as path traversal, web shell, or admin probes.`
    default:
      return threat.description
  }
}

function displayLog(line: string) {
  const splitAt = line.indexOf('  ')
  if (splitAt < 0) return settings.status(line)
  return `${line.slice(0, splitAt)}  ${settings.status(line.slice(splitAt + 2))}`
}

function displayFilename() {
  const filename = store.analysis?.filename || ''
  if (settings.language === 'ru' && filename.startsWith('Live capture')) {
    return filename.replace('Live capture', 'Захват в реальном времени')
  }
  return filename
}
</script>

<template>
  <div class="page">
    <header class="top">
      <div class="brand fade-rise">
        <span class="mark" aria-hidden="true" />
        <div>
          <h1>Traffic Guardian</h1>
          <p class="tag">{{ settings.t('tagline') }}</p>
        </div>
      </div>
      <div class="status mono fade-rise" style="animation-delay: 0.08s">
        <span :class="store.health?.tshark ? 'dot ok' : 'dot bad'" />
        {{ settings.t('tshark') }}
      </div>
    </header>

    <section class="hero fade-rise" style="animation-delay: 0.12s">
      <div class="live-banner"><span :class="store.liveStatus === 'Захват активен' ? 'dot ok pulse' : 'dot mid'" /><strong>{{ settings.status(store.liveStatus) }}</strong><span class="mono muted">{{ settings.t('interface') }}: {{ store.analysis?.filename.split('·')[1]?.trim() || 'any' }}</span></div>
    </section>

    <template v-if="store.analysis">
      <section class="score-row fade-rise">
        <div class="score" :class="scoreClass">
          <div class="score-num mono">{{ store.analysis.threat_score }}</div>
          <div class="score-label">{{ settings.t('threatScore') }}</div>
        </div>
        <div class="meta">
          <h2 class="mono">{{ displayFilename() }}</h2>
          <div class="chips">
            <span>{{ store.analysis.summary.packet_count.toLocaleString() }} pkt</span>
            <span>{{ formatBytes(store.analysis.summary.bytes_total) }}</span>
            <span>{{ store.analysis.summary.duration_sec.toFixed(2) }}s</span>
            <span>{{ store.analysis.summary.pps.toFixed(0) }} pps</span>
            <span>{{ store.analysis.summary.unique_ips }} IP</span>
          </div>
          <span class="live-tag">LIVE</span>
        </div>
      </section>

      <section class="grid">
        <article class="panel wide">
          <h3>{{ settings.t('latestPackets') }} <span class="badge">{{ settings.t('live') }}</span></h3>
          <div class="live-table-wrap"><table class="table mono"><thead><tr><th>#</th><th>{{ settings.t('time') }}</th><th>{{ settings.t('source') }}</th><th>{{ settings.t('destination') }}</th><th>{{ settings.t('protocol') }}</th><th>{{ settings.t('bytes') }}</th></tr></thead>
            <tbody><tr v-for="(p, i) in [...store.livePackets].reverse()" :key="i"><td>{{ p.Number }}</td><td>{{ p.TimeRel.toFixed(3) }}s</td><td>{{ p.SrcIP }}:{{ p.SrcPort || '—' }}</td><td>{{ p.DstIP }}:{{ p.DstPort || '—' }}</td><td>{{ p.Protocol }}</td><td>{{ p.Length }}</td></tr></tbody>
          </table></div>
        </article>
        <article class="panel wide">
          <h3>{{ settings.t('logs') }}</h3><div class="live-logs mono"><div v-for="(line, i) in [...store.liveLogs].reverse()" :key="i">{{ displayLog(line) }}</div></div>
        </article>
        <article class="panel fade-rise" style="animation-delay: 0.05s">
          <h3>{{ settings.t('protocols') }}</h3>
          <ul class="bars">
            <li v-for="p in store.analysis.protocols.slice(0, 10)" :key="p.name">
              <div class="bar-head">
                <span class="mono">{{ p.name }}</span>
                <span class="mono muted">{{ p.percentage.toFixed(1) }}%</span>
              </div>
              <div class="bar-track">
                <div class="bar-fill" :style="{ width: Math.min(p.percentage, 100) + '%' }" />
              </div>
            </li>
          </ul>
        </article>

        <article class="panel fade-rise" style="animation-delay: 0.1s">
          <h3>{{ settings.t('summary') }}</h3>
          <dl class="kv mono">
            <div><dt>TCP</dt><dd>{{ store.analysis.summary.tcp_count }}</dd></div>
            <div><dt>UDP</dt><dd>{{ store.analysis.summary.udp_count }}</dd></div>
            <div><dt>ICMP</dt><dd>{{ store.analysis.summary.icmp_count }}</dd></div>
            <div><dt>DNS</dt><dd>{{ store.analysis.summary.dns_count }}</dd></div>
            <div><dt>HTTP</dt><dd>{{ store.analysis.summary.http_count }}</dd></div>
            <div><dt>TLS</dt><dd>{{ store.analysis.summary.tls_count }}</dd></div>
            <div><dt>{{ settings.t('ports') }}</dt><dd>{{ store.analysis.summary.unique_ports }}</dd></div>
            <div><dt>{{ settings.t('avgSize') }}</dt><dd>{{ store.analysis.summary.avg_packet_size.toFixed(0) }} B</dd></div>
          </dl>
        </article>

        <article class="panel wide fade-rise" style="animation-delay: 0.15s">
          <h3>{{ settings.t('localThreats') }}</h3>
          <div v-if="!store.analysis.threats.length" class="empty">{{ settings.t('noThreats') }}</div>
          <ul v-else class="threats">
            <li v-for="t in store.analysis.threats" :key="t.id">
              <div class="threat-top">
                <span class="sev" :class="sevClass(t.severity)">{{ severityLabel(t.severity) }}</span>
                <span class="cat">{{ catLabel(t.category) }}</span>
                <strong>{{ threatTitle(t) }}</strong>
                <span class="mono muted">{{ Math.round(t.confidence * 100) }}%</span>
              </div>
              <p>{{ threatDescription(t) }}</p>
              <div v-if="t.indicators?.length" class="inds mono">
                <span v-for="(ind, i) in t.indicators.slice(0, 6)" :key="i">{{ ind }}</span>
              </div>
            </li>
          </ul>
        </article>

        <article class="panel fade-rise" style="animation-delay: 0.2s">
          <h3>{{ settings.t('topTalkers') }}</h3>
          <table class="table mono">
            <thead>
              <tr><th>IP</th><th>pkt</th><th>bytes</th></tr>
            </thead>
            <tbody>
              <tr v-for="t in store.analysis.top_talkers.slice(0, 12)" :key="t.ip">
                <td>{{ t.ip }}</td>
                <td>{{ t.packets }}</td>
                <td>{{ formatBytes(t.bytes) }}</td>
              </tr>
            </tbody>
          </table>
        </article>

        <article class="panel fade-rise" style="animation-delay: 0.25s">
          <h3>{{ settings.t('conversations') }}</h3>
          <table class="table mono">
            <thead>
              <tr><th>pair</th><th>proto</th><th>bytes</th></tr>
            </thead>
            <tbody>
              <tr v-for="(c, i) in store.analysis.conversations.slice(0, 12)" :key="i">
                <td>{{ c.src }} ↔ {{ c.dst }}</td>
                <td>{{ c.protocol }}</td>
                <td>{{ formatBytes(c.bytes) }}</td>
              </tr>
            </tbody>
          </table>
        </article>

      </section>
    </template>
  </div>
</template>

<style scoped>
.page {
  max-width: 1120px;
  margin: 0 auto;
  padding: 28px 20px 80px;
}

.top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 28px;
  padding-right: 100px;
}

.brand {
  display: flex;
  gap: 14px;
  align-items: center;
}

.mark {
  width: 42px;
  height: 42px;
  border-radius: 8px;
  background:
    linear-gradient(145deg, transparent 42%, var(--accent) 42% 58%, transparent 58%),
    var(--ink);
  box-shadow: var(--shadow);
  animation: pulse-ring 2.8s ease infinite;
}

h1 {
  margin: 0;
  font-size: clamp(1.55rem, 4.2vw, 2.55rem);
  font-weight: 800;
  letter-spacing: -0.035em;
  line-height: 1;
}

.tag {
  margin: 4px 0 0;
  color: var(--muted);
  font-size: 0.92rem;
}

.status {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.78rem;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--muted);
}
.dot.ok {
  background: var(--ok);
}
.dot.bad {
  background: var(--danger);
}
.dot.mid {
  background: var(--warn);
}

.hero {
  margin-bottom: 28px;
}

.live-banner { display:flex; align-items:center; gap:10px; padding:16px 18px; border:1px solid var(--line); background:rgba(0,168,150,.08); }
.live-banner .muted { margin-left:auto; font-size:.8rem; }
.live-tag { display:inline-block; padding:4px 9px; background:var(--danger); color:white; font:600 .7rem var(--mono); letter-spacing:.08em; }
.pulse { animation: live-pulse 1.6s ease infinite; }
.live-table-wrap { max-height:300px; overflow:auto; }
.live-logs { max-height:220px; overflow:auto; padding:12px; background:rgba(0,0,0,.06); font-size:.78rem; line-height:1.8; }
@keyframes live-pulse { 50% { box-shadow:0 0 0 6px rgba(47,143,91,0); } 0%,100% { box-shadow:0 0 0 0 rgba(47,143,91,.35); } }

.drop {
  border: 1.5px dashed rgba(11, 18, 32, 0.35);
  background: rgba(255, 255, 255, 0.45);
  backdrop-filter: blur(6px);
  min-height: 180px;
  display: grid;
  place-items: center;
  text-align: center;
  padding: 28px;
  transition: border-color 0.2s, background 0.2s, transform 0.2s;
  cursor: pointer;
}

.drop:hover,
.drop.over {
  border-color: var(--accent);
  background: rgba(0, 168, 150, 0.08);
  transform: translateY(-1px);
}

.drop.busy {
  pointer-events: none;
  opacity: 0.85;
}

.drop-title {
  margin: 0;
  font-size: 1.6rem;
  font-weight: 700;
  letter-spacing: -0.03em;
}

.drop-sub {
  margin: 8px 0 0;
  color: var(--muted);
  max-width: 36rem;
}

.spinner {
  width: 36px;
  height: 36px;
  border: 3px solid var(--paper-2);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}

.err {
  color: var(--danger);
  margin: 10px 0 0;
}

.score-row {
  display: flex;
  gap: 20px;
  align-items: stretch;
  margin-bottom: 22px;
}

.score {
  width: 120px;
  min-height: 120px;
  display: grid;
  place-content: center;
  text-align: center;
  background: var(--ink);
  color: #fff;
  border-radius: var(--radius);
}

.score.good {
  background: linear-gradient(160deg, var(--ink), #0f3d34);
}
.score.mid {
  background: linear-gradient(160deg, var(--ink), #4a3208);
}
.score.bad {
  background: linear-gradient(160deg, var(--ink), #4a1018);
}

.score-num {
  font-size: 2.6rem;
  font-weight: 600;
  line-height: 1;
}

.score-label {
  font-size: 0.72rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  opacity: 0.7;
  margin-top: 6px;
}

.meta h2 {
  margin: 0 0 10px;
  font-size: 1.1rem;
  word-break: break-all;
}

.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 12px;
}

.chips span {
  font-family: var(--mono);
  font-size: 0.78rem;
  padding: 4px 8px;
  background: rgba(11, 18, 32, 0.06);
  border-radius: 2px;
}

.ghost {
  border: 1px solid var(--line);
  background: transparent;
  padding: 6px 12px;
  border-radius: var(--radius);
  color: var(--muted);
}

.grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.panel {
  background: rgba(255, 255, 255, 0.62);
  border: 1px solid var(--line);
  padding: 18px;
  border-radius: var(--radius);
}

.panel.wide {
  grid-column: 1 / -1;
}

.panel h3 {
  margin: 0 0 14px;
  font-size: 0.95rem;
  letter-spacing: 0.02em;
  text-transform: uppercase;
  display: flex;
  align-items: center;
  gap: 10px;
}

.badge {
  font-size: 0.68rem;
  font-weight: 600;
  padding: 2px 7px;
  background: var(--accent);
  color: #fff;
  border-radius: 2px;
  letter-spacing: 0.04em;
}

.badge.soft {
  background: var(--ink-soft);
}

.bars {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 10px;
}

.bar-head {
  display: flex;
  justify-content: space-between;
  font-size: 0.82rem;
  margin-bottom: 4px;
}

.bar-track {
  height: 6px;
  background: rgba(11, 18, 32, 0.08);
  border-radius: 99px;
  overflow: hidden;
}

.bar-fill {
  height: 100%;
  background: var(--accent);
  border-radius: 99px;
  transition: width 0.6s ease;
}

.kv {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px 16px;
  margin: 0;
}

.kv div {
  display: flex;
  justify-content: space-between;
  border-bottom: 1px solid var(--line);
  padding-bottom: 6px;
}

.kv dt {
  color: var(--muted);
  margin: 0;
}

.kv dd {
  margin: 0;
  font-weight: 500;
}

.threats {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 14px;
}

.threats li {
  padding-bottom: 14px;
  border-bottom: 1px solid var(--line);
}

.threats li:last-child {
  border-bottom: 0;
  padding-bottom: 0;
}

.threat-top {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 12px;
  align-items: baseline;
  margin-bottom: 6px;
}

.sev {
  font-family: var(--mono);
  font-size: 0.72rem;
  text-transform: uppercase;
  font-weight: 600;
}

.cat {
  font-size: 0.75rem;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.threats p {
  margin: 0;
  color: var(--ink-soft);
  line-height: 1.45;
}

.inds {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 8px;
}

.inds span {
  font-size: 0.72rem;
  background: rgba(11, 18, 32, 0.06);
  padding: 2px 6px;
}

.table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.78rem;
}

.table th {
  text-align: left;
  color: var(--muted);
  font-weight: 500;
  padding: 0 8px 8px 0;
}

.table td {
  padding: 6px 8px 6px 0;
  border-top: 1px solid var(--line);
  vertical-align: top;
  word-break: break-all;
}

.primary {
  border: 0;
  background: var(--ink);
  color: #fff;
  padding: 10px 16px;
  border-radius: var(--radius);
  font-weight: 600;
}

.primary:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

.hint,
.muted {
  color: var(--muted);
}

.hint {
  margin: -6px 0 12px;
  font-size: 0.9rem;
}

.empty {
  color: var(--muted);
}

@media (max-width: 760px) {
  .grid,
  .kv {
    grid-template-columns: 1fr;
  }
  .score-row {
    flex-direction: column;
  }
  .score {
    width: 100%;
    min-height: 96px;
  }
  .top {
    flex-direction: column;
  }
}
</style>
