import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'

// The administration page and the administration API share one origin in every
// deployment. The production build is served by the control-plane listener from
// a configured directory, so assets are referenced from that same root. In
// development no process serves the page, so the dev server proxies the API,
// health and metrics paths to the running control plane and the page keeps using
// relative, same-origin requests.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'TOKENSTREAM_')
  const controlPlane =
    process.env.TOKENSTREAM_ADMIN_PROXY_TARGET ||
    env.TOKENSTREAM_ADMIN_PROXY_TARGET ||
    'http://127.0.0.1:3001'
  const proxied = ['/admin/api', '/healthz', '/metrics']

  return {
    plugins: [vue()],
    base: '/',
    server: {
      proxy: Object.fromEntries(
        proxied.map((path) => [path, { target: controlPlane, changeOrigin: false }]),
      ),
    },
  }
})
