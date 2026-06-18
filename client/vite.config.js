import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Клиент-доказывающий запускается на порту 5173.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
})
