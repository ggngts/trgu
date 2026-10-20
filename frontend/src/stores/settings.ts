import { defineStore } from 'pinia'
import { ref } from 'vue'

export type Language = 'en' | 'ru'

const messages = {
  en: {
    switchTheme: 'Switch to light theme', switchThemeDark: 'Switch to dark theme', language: 'Language',
    tagline: 'Live traffic → tshark → local heuristics', tshark: 'tshark',
    connecting: 'Connecting to live capture…', liveConnected: 'Live capture connected', noConnection: 'No connection to live capture',
    captureActive: 'Capture active', waiting: 'Waiting for tshark', hostStream: 'Processing live traffic from the host network namespace',
    captureOn: 'Capture running on interface', restarting: 'Restarting tshark',
    threatScore: 'threat score', latestPackets: 'Latest packets', live: 'live', logs: 'tshark logs',
    time: 'time', source: 'source', destination: 'destination', protocol: 'protocol', bytes: 'bytes',
    protocols: 'Protocols', summary: 'Summary', ports: 'ports', avgSize: 'avg size',
    localThreats: 'Local threats', noThreats: 'Heuristics found no critical issues.',
    topTalkers: 'Top talkers', packets: 'packets', conversations: 'Conversations', pair: 'pair',
    interface: 'interface', scan: 'Scanning', malware: 'Malware / C2', anomaly: 'Anomaly', ddos: 'DDoS / flood',
    loading: 'Analyzing…', uploadError: 'Analysis failed',
  },
  ru: {
    switchTheme: 'Включить светлую тему', switchThemeDark: 'Включить тёмную тему', language: 'Язык',
    tagline: 'Live-трафик → tshark → локальные эвристики', tshark: 'tshark',
    connecting: 'Подключение к live-захвату…', liveConnected: 'Live-захват подключён', noConnection: 'Нет соединения с live-захватом',
    captureActive: 'Захват активен', waiting: 'Ожидание tshark', hostStream: 'Обрабатываю live-поток из сетевого пространства хоста',
    captureOn: 'Захват запущен на интерфейсе', restarting: 'Перезапуск tshark',
    threatScore: 'уровень угрозы', latestPackets: 'Последние пакеты', live: 'live', logs: 'Логи tshark',
    time: 'время', source: 'источник', destination: 'назначение', protocol: 'протокол', bytes: 'байты',
    protocols: 'Протоколы', summary: 'Сводка', ports: 'порты', avgSize: 'средний размер',
    localThreats: 'Локальные угрозы', noThreats: 'Эвристики не обнаружили критичных событий.',
    topTalkers: 'Активные узлы', packets: 'пакеты', conversations: 'Соединения', pair: 'пара',
    interface: 'интерфейс', scan: 'Сканирование', malware: 'Malware / C2', anomaly: 'Аномалия', ddos: 'DDoS / флуд',
    loading: 'Анализ…', uploadError: 'Ошибка анализа',
  },
} as const

export type MessageKey = keyof typeof messages.en

export const useSettingsStore = defineStore('settings', () => {
  const savedTheme = localStorage.getItem('theme')
  const dark = ref(savedTheme !== 'light')
  const savedLanguage = localStorage.getItem('language')
  const language = ref<Language>(savedLanguage === 'ru' ? 'ru' : 'en')

  function applyTheme() {
    document.documentElement.dataset.theme = dark.value ? 'dark' : 'light'
    localStorage.setItem('theme', dark.value ? 'dark' : 'light')
  }

  function toggleTheme() {
    dark.value = !dark.value
    applyTheme()
  }

  function setLanguage(value: Language) {
    language.value = value
    document.documentElement.lang = value
    localStorage.setItem('language', value)
  }

  function toggleLanguage() {
    setLanguage(language.value === 'en' ? 'ru' : 'en')
  }

  function t(key: MessageKey): string {
    return messages[language.value][key]
  }

  function status(value: string): string {
    if (value === 'Захват активен') return t('captureActive')
    if (value === 'Ожидание tshark') return t('waiting')
    if (value === 'Обрабатываю live-поток с сетевого пространства хоста') return t('hostStream')
    if (value === 'Live-захват подключён') return t('liveConnected')
    if (value === 'Нет соединения с live-захватом') return t('noConnection')
    if (value === 'Подключение к live-захвату…') return t('connecting')
    if (value === 'Ошибка ответа live API') return language.value === 'en' ? 'Live API response error' : value
    if (value === 'В live-ответе нет сводки анализа') return language.value === 'en' ? 'Live response has no analysis summary' : value
    if (value.startsWith('Захват запущен на интерфейсе ')) return `${t('captureOn')} ${value.slice('Захват запущен на интерфейсе '.length)}`
    if (value.startsWith('Перезапуск tshark')) return `${t('restarting')} ${value.slice('Перезапуск tshark'.length)}`
    return value
  }

  return { dark, language, toggleTheme, toggleLanguage, applyTheme, setLanguage, t, status }
})
