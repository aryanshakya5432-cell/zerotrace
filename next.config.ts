import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Route handlers in this project explicitly opt into `runtime = 'nodejs'`,
  // which is incompatible with Cache Components. Keep the default runtime model.
  cacheComponents: false,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
