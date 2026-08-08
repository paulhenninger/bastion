import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Backend on 8080; cookies ride through untouched.
      '/api': 'http://localhost:8080',
    },
  },
});
