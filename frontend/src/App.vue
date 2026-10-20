<script setup lang="ts">
import { onMounted } from 'vue'
import { RouterView } from 'vue-router'
import { useAnalysisStore } from './stores/analysis'
import { useSettingsStore } from './stores/settings'

const store = useAnalysisStore()
const settings = useSettingsStore()
onMounted(() => {
  settings.applyTheme()
  settings.setLanguage(settings.language)
  store.loadHealth()
  store.connectLive()
})
</script>

<template>
  <div class="settings-controls">
    <button class="setting-toggle language-toggle" type="button" @click="settings.toggleLanguage" :aria-label="settings.t('language')">
      {{ settings.language === 'en' ? 'RU' : 'EN' }}
    </button>
    <button class="setting-toggle theme-toggle" type="button" @click="settings.toggleTheme" :aria-label="settings.t(settings.dark ? 'switchTheme' : 'switchThemeDark')">
      {{ settings.dark ? '☀' : '☾' }}
    </button>
  </div>
  <RouterView />
</template>
