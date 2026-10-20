<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { RouterView } from 'vue-router'
import { useAnalysisStore } from './stores/analysis'

const store = useAnalysisStore()
const dark = ref(localStorage.getItem('theme') === 'dark')
function toggleTheme() {
  dark.value = !dark.value
  document.documentElement.dataset.theme = dark.value ? 'dark' : 'light'
  localStorage.setItem('theme', dark.value ? 'dark' : 'light')
}
onMounted(() => {
  document.documentElement.dataset.theme = dark.value ? 'dark' : 'light'
  store.loadHealth()
  store.connectLive()
})
</script>

<template>
  <button class="theme-toggle" type="button" @click="toggleTheme" :aria-label="dark ? 'Включить светлую тему' : 'Включить тёмную тему'">{{ dark ? '☀' : '☾' }}</button>
  <RouterView />
</template>
