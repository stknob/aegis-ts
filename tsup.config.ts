import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/aegis128l.mts", "src/aegis256.mts"],
  format: ["cjs", "esm"],
  dts: true,
  outDir: "dist",
  clean: true,
});
