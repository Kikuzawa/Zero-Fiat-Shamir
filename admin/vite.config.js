import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Веб-интерфейс администратора запускается на порту 5174.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
  },
})
