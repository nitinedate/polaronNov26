import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Component tests run the real Malware Detection pages in jsdom with the API module mocked.
export default defineConfig({
  plugins: [react()],
  test: { environment: "jsdom", include: ["src/**/*.test.tsx"], restoreMocks: true },
});
