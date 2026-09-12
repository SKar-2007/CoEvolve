/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        brand: {
          red: "#E63946",
          yellow: "#FFD166",
          green: "#06D6A0",
          blue: "#118AB2",
        },
      },
    },
  },
  plugins: [],
};
