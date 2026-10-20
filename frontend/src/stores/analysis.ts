import { defineStore } from 'pinia'
import { ref } from 'vue'
import { API_BASE, fetchHealth, uploadPcap } from '../api'
import type { Analysis, Health, LivePacket } from '../types'

const emptySummary: Analysis['summary'] = {
  packet_count: 0,
  bytes_total: 0,
  duration_sec: 0,
  avg_packet_size: 0,
  pps: 0,
  unique_ips: 0,
  unique_ports: 0,
  tcp_count: 0,
  udp_count: 0,
  icmp_count: 0,
  dns_count: 0,
  http_count: 0,
  tls_count: 0,
}

export const useAnalysisStore = defineStore('analysis', () => {
  const health = ref<Health | null>(null)
  const analysis = ref<Analysis | null>(null)
  const loading = ref(false)
  const error = ref('')
  const liveStatus = ref('Подключение к live-захвату…')
  const livePackets = ref<LivePacket[]>([])
  const liveLogs = ref<string[]>([])
  let stream: EventSource | null = null

  function connectLive() {
    stream?.close()
    stream = new EventSource(`${API_BASE}/api/live`)
    stream.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as Partial<{
          status: string
          analysis: Analysis
          packets: LivePacket[]
          logs: string[]
        }>
        if (!data.analysis || typeof data.analysis !== 'object') {
          throw new Error('В live-ответе нет сводки анализа')
        }

        analysis.value = {
          ...data.analysis,
          id: data.analysis.id || 'live',
          filename: data.analysis.filename || 'Live capture',
          summary: data.analysis.summary || emptySummary,
          protocols: Array.isArray(data.analysis.protocols) ? data.analysis.protocols : [],
          top_talkers: Array.isArray(data.analysis.top_talkers) ? data.analysis.top_talkers : [],
          conversations: Array.isArray(data.analysis.conversations) ? data.analysis.conversations : [],
          threats: Array.isArray(data.analysis.threats) ? data.analysis.threats : [],
        }
        liveStatus.value = data.status || 'Live-захват подключён'
        livePackets.value = Array.isArray(data.packets) ? data.packets : []
        liveLogs.value = Array.isArray(data.logs) ? data.logs : []
      } catch (e) {
        console.error('Invalid live response', e, event.data)
        liveStatus.value = e instanceof Error ? e.message : 'Ошибка ответа live API'
      }
    }
    stream.onerror = () => { liveStatus.value = 'Нет соединения с live-захватом' }
  }

  async function loadHealth() {
    try {
      health.value = await fetchHealth()
    } catch {
      health.value = { ok: false, tshark: false }
    }
  }

  async function analyze(file: File) {
    loading.value = true
    error.value = ''
    try {
      analysis.value = await uploadPcap(file)
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Ошибка анализа'
      analysis.value = null
    } finally {
      loading.value = false
    }
  }

  function reset() {
    analysis.value = null
    error.value = ''
  }

  return {
    health,
    analysis,
    loading,
    error,
    loadHealth,
    connectLive,
    liveStatus,
    livePackets,
    liveLogs,
    analyze,
    reset,
  }
})
