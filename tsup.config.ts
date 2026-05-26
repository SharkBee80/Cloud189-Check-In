import { defineConfig } from "tsup";

export default defineConfig((options) => ({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: false,
  clean: true,
  sourcemap: false,
  minify: true,
  minifyIdentifiers: true,
  minifyWhitespace: true,
  minifySyntax: true,
  splitting: false,
  shims: true,
  esbuildOptions: (options) => {
    options.charset = "utf8";
  },
  watch:
    options.watch ?
      (() => {
        console.log(`Watching...`);
        return "/src/**";
      })()
    : false,
  onSuccess: async () => console.log("\n✅ " + new Date().toLocaleString() + " tsup Done."),
}));
