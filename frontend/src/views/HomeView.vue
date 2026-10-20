<script setup lang="ts">
import { computed, ref } from 'vue'
import { formatBytes } from '../api'
import { useAnalysisStore } from '../stores/analysis'
import type { Severity } from '../types'

const store = useAnalysisStore()
const dragOver = ref(false)
const question = ref('Дай вердикт по угрозам и что проверить дальше.')
const fileInput = ref<HTMLInputElement | null>(null)

const scoreClass = computed(() => {
  const s = store.analysis?.threat_score ?? 0
  if (s >= 70) return 'bad'
  if (s >= 40) return 'mid'
  return 'good'
})

function onDrop(e: DragEvent) {
  dragOver.value = false
  const f = e.dataTransfer?.files?.[0]
  if (f) store.analyze(f)
}

function onFile(e: Event) {
  const input = e.target as HTMLInputElement
  const f = input.files?.[0]
  if (f) store.analyze(f)
  input.value = ''
}

function sevClass(s: Severity) {
  return `sev-${s}`
}

function catLabel(c: string) {
  const map: Record<string, string> = {
    ddos: 'DDoS / flood',
    scan: 'Сканирование',
    malware: 'Malware / C2',
    anomaly: 'Аномалия',
  }
  return map[c] || c
}
</script>

<template>
  <div class="page">
    <header class="top">
      <div class="brand fade-rise">
        <span class="mark" aria-hidden="true" />
        <div>
          <h1>Traffic Guardian</h1>
          <p class="tag">PCAP → tshark → эвристики → Gemini</p>
        </div>
      </div>
      <div class="status mono fade-rise" style="animation-delay: 0.08s">
        <span :class="store.health?.tshark ? 'dot ok' : 'dot bad'" />
        tshark
        <span :class="store.health?.gemini ? 'dot ok' : 'dot mid'" />
        gemini
      </div>
    </header>

    <section class="hero fade-rise" style="animation-delay: 0.12s">
      <div
        class="drop"
        :class="{ over: dragOver, busy: store.loading }"
        @dragover.prevent="dragOver = true"
        @dragleave.prevent="dragOver = false"
        @drop.prevent="onDrop"
        @click="fileInput?.click()"
      >
        <input
          ref="fileInput"
          type="file"
          accept=".pcap,.pcapng,.cap"
          hidden
          @change="onFile"
        />
        <div v-if="store.loading" class="spinner" />
        <template v-else>
          <p class="drop-title">Загрузи PCAP</p>
          <p class="drop-sub">.pcap / .pcapng — разбор на бэке, угрозы без ожидания Gemini</p>
        </template>
      </div>
      <p v-if="store.error" class="err">{{ store.error }}</p>
    </section>

    <template v-if="store.analysis">
      <section class="score-row fade-rise">
        <div class="score" :class="scoreClass">
          <div class="score-num mono">{{ store.analysis.threat_score }}</div>
          <div class="score-label">threat score</div>
        </div>
        <div class="meta">
          <h2 class="mono">{{ store.analysis.filename }}</h2>
          <div class="chips">
            <span>{{ store.analysis.summary.packet_count.toLocaleString() }} pkt</span>
            <span>{{ formatBytes(store.analysis.summary.bytes_total) }}</span>
            <span>{{ store.analysis.summary.duration_sec.toFixed(2) }}s</span>
            <span>{{ store.analysis.summary.pps.toFixed(0) }} pps</span>
            <span>{{ store.analysis.summary.unique_ips }} IP</span>
          </div>
          <button class="ghost" type="button" @click="store.reset()">новый файл</button>
        </div>
      </section>

      <section class="grid">
        <article class="panel fade-rise" style="animation-delay: 0.05s">
          <h3>Протоколы</h3>
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
          <h3>Сводка</h3>
          <dl class="kv mono">
            <div><dt>TCP</dt><dd>{{ store.analysis.summary.tcp_count }}</dd></div>
            <div><dt>UDP</dt><dd>{{ store.analysis.summary.udp_count }}</dd></div>
            <div><dt>ICMP</dt><dd>{{ store.analysis.summary.icmp_count }}</dd></div>
            <div><dt>DNS</dt><dd>{{ store.analysis.summary.dns_count }}</dd></div>
            <div><dt>HTTP</dt><dd>{{ store.analysis.summary.http_count }}</dd></div>
            <div><dt>TLS</dt><dd>{{ store.analysis.summary.tls_count }}</dd></div>
            <div><dt>порты</dt><dd>{{ store.analysis.summary.unique_ports }}</dd></div>
            <div><dt>avg size</dt><dd>{{ store.analysis.summary.avg_packet_size.toFixed(0) }} B</dd></div>
          </dl>
        </article>

        <article class="panel wide fade-rise" style="animation-delay: 0.15s">
          <h3>Локальные угрозы <span class="badge">без Gemini</span></h3>
          <div v-if="!store.analysis.threats.length" class="empty">Эвристики ничего критичного не нашли.</div>
          <ul v-else class="threats">
            <li v-for="t in store.analysis.threats" :key="t.id">
              <div class="threat-top">
                <span class="sev" :class="sevClass(t.severity)">{{ t.severity }}</span>
                <span class="cat">{{ catLabel(t.category) }}</span>
                <strong>{{ t.title }}</strong>
                <span class="mono muted">{{ Math.round(t.confidence * 100) }}%</span>
              </div>
              <p>{{ t.description }}</p>
              <div v-if="t.indicators?.length" class="inds mono">
                <span v-for="(ind, i) in t.indicators.slice(0, 6)" :key="i">{{ ind }}</span>
              </div>
            </li>
          </ul>
        </article>

        <article class="panel fade-rise" style="animation-delay: 0.2s">
          <h3>Top talkers</h3>
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
          <h3>Conversations</h3>
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

        <article class="panel wide ai fade-rise" style="animation-delay: 0.3s">
          <h3>Gemini <span class="badge soft">по запросу</span></h3>
          <p class="hint">AI получает сводку и локальные детекции — не сырой PCAP целиком.</p>
          <textarea v-model="question" rows="3" placeholder="Вопрос аналитику…" />
          <div class="ai-actions">
            <button
              class="primary"
              type="button"
              :disabled="store.aiLoading || !store.health?.gemini"
              @click="store.runAI(question)"
            >
              {{ store.aiLoading ? 'думает…' : 'спросить Gemini' }}
            </button>
            <span v-if="!store.health?.gemini" class="muted">GEMINI_API_KEY не задан</span>
          </div>
          <p v-if="store.aiError" class="err">{{ store.aiError }}</p>
          <div v-if="store.ai" class="ai-answer">
            <div class="ai-meta mono">{{ store.ai.model }}</div>
            <pre>{{ store.ai.answer }}</pre>
          </div>
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

.ai textarea {
  width: 100%;
  resize: vertical;
  border: 1px solid var(--line);
  background: rgba(255, 255, 255, 0.8);
  padding: 12px;
  border-radius: var(--radius);
  margin-bottom: 12px;
}

.ai-actions {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
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

.ai-answer {
  margin-top: 8px;
  padding: 14px;
  background: rgba(11, 18, 32, 0.04);
  border-left: 3px solid var(--accent);
}

.ai-meta {
  font-size: 0.72rem;
  color: var(--muted);
  margin-bottom: 8px;
  text-transform: uppercase;
}

.ai-answer pre {
  margin: 0;
  white-space: pre-wrap;
  font-family: var(--font);
  line-height: 1.5;
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
