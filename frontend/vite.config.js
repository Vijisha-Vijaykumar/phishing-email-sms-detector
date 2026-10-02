import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/predict': 'http://127.0.0.1:8000',
      '/health': 'http://127.0.0.1:8000',
      '/model-info': 'http://127.0.0.1:8000',
      '/fingerprint': 'http://127.0.0.1:8000',
      '/extract': 'http://127.0.0.1:8000',
      '/url-check': 'http://127.0.0.1:8000',
      '/sender-check': 'http://127.0.0.1:8000',
      '/repeat-check': 'http://127.0.0.1:8000',
      '/research': 'http://127.0.0.1:8000',
      '/samples': 'http://127.0.0.1:8000',
      '/api': 'http://127.0.0.1:8000',
      '/analyze-attachment': 'http://127.0.0.1:8000',
      '/analyze-url': 'http://127.0.0.1:8000',
      '/web-intel': 'http://127.0.0.1:8000'
    }
  }
})
