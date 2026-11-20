import { createApp } from 'vue'
import App from './App.vue'
import { installLocale } from './locale/state.ts'

installLocale()
createApp(App).mount('#app')
