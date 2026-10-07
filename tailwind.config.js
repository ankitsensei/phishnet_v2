/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          900: '#06090e',
          850: '#090d14',
          800: '#0c1017',
          750: '#101620',
          700: '#141b29',
          600: '#1e293b',
          border: 'rgba(255, 255, 255, 0.08)',
          glow: '#06b6d4'
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        display: ['Plus Jakarta Sans', 'sans-serif'],
        mono: ['Fira Code', 'monospace']
      }
    },
  },
  plugins: [],
}
