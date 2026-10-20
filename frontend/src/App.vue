<script setup lang="ts">
import { onMounted } from 'vue'
import { RouterView } from 'vue-router'
import { useAnalysisStore } from './stores/analysis'

const store = useAnalysisStore()
onMounted(() => store.loadHealth())
</script>

<template>
  <RouterView />
</template>
