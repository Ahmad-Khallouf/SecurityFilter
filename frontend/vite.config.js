import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The dev server proxies every /api request to the ASP.NET Core backend running
// under its "http" launch profile (http://localhost:5170). Because the browser
// only ever talks to the Vite origin (http://localhost:5173), there are no CORS
// issues during development. If you run the backend on a different port, change
// the target below.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:5170',
        changeOrigin: true,
      },
    },
  },
});
