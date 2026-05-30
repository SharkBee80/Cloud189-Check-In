import { defineConfig, type Options } from "tsup";

export default defineConfig((options) => {
  const base_options: Options = {
    entry: ["src/index.ts"],
    dts: false,
    clean: true,
    sourcemap: false,
    minify: false,
    minifyIdentifiers: true,
    minifyWhitespace: false,
    minifySyntax: true,
    splitting: false,
    shims: true,
    // pure: ["console.debug"],
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
  };
  return [
    // 1. 全量版本 (Bundle Everything)
    {
      ...base_options,
      format: "cjs",
      noExternal: [/.*/],
    },
    // 2. 依赖分离版本 (Exclude Dependencies)
    {
      ...base_options,
      format: "esm",
    },
  ];
});
