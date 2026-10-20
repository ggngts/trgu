import { defineStore } from 'pinia'
import { ref } from 'vue'
import { API_BASE, askAI, fetchHealth, uploadPcap } from '../api'
import type { AIResponse, Analysis, Health } from '../types'

export const useAnalysisStore = defineStore('analysis', () => {
  const health = ref<Health | null>(null)
  const analysis = ref<Analysis | null>(null)
  const ai = ref<AIResponse | null>(null)
  const loading = ref(false)
  const aiLoading = ref(false)
  const error = ref('')
  const aiError = ref('')
  const liveStatus = ref('Подключение к live-захвату…')
  const livePackets = ref<any[]>([])
  const liveLogs = ref<string[]>([])
  let stream: EventSource | null = null

  function connectLive() {
    stream?.close()
    stream = new EventSource(`${API_BASE}/api/live`)
    stream.onmessage = (event) => {
      const data = JSON.parse(event.data)
      liveStatus.value = data.status
      analysis.value = data.analysis
      livePackets.value = data.packets
      liveLogs.value = data.logs
    }
    stream.onerror = () => { liveStatus.value = 'Нет соединения с live-захватом' }
  }

  async function loadHealth() {
    try {
      health.value = await fetchHealth()
    } catch {
      health.value = { ok: false, tshark: false, gemini: false }
    }
  }

  async function analyze(file: File) {
    loading.value = true
    error.value = ''
    ai.value = null
    aiError.value = ''
    try {
      analysis.value = await uploadPcap(file)
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Ошибка анализа'
      analysis.value = null
    } finally {
      loading.value = false
    }
  }

  async function runAI(question: string) {
    if (!analysis.value) return
    aiLoading.value = true
    aiError.value = ''
    try {
      ai.value = await askAI(analysis.value.id, question)
    } catch (e) {
      aiError.value = e instanceof Error ? e.message : 'Ошибка Gemini'
    } finally {
      aiLoading.value = false
    }
  }

  function reset() {
    analysis.value = null
    ai.value = null
    error.value = ''
    aiError.value = ''
  }

  return {
    health,
    analysis,
    ai,
    loading,
    aiLoading,
    error,
    aiError,
    loadHealth,
    connectLive,
    liveStatus,
    livePackets,
    liveLogs,
    analyze,
    runAI,
    reset,
  }
})
