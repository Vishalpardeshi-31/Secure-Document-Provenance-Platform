/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#090d16',
        surface: '#0f172a',
        'surface-elevated': '#1e293b',
        border: '#334155',
        'border-subtle': '#1e293b',
        primary: {
          DEFAULT: '#3b82f6',
          hover: '#2563eb',
        },
        security: {
          ok: '#10b981',
          warning: '#f59e0b',
          danger: '#ef4444',
          neutral: '#64748b',
        }
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
