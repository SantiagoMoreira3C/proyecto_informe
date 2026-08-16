const apiInternalUrl = process.env.API_INTERNAL_URL || "http://api:8000";

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  async rewrites() {
    return [{
      source: "/api/:path*",
      destination: `${apiInternalUrl}/api/:path*`,
    }];
  },
};

export default nextConfig;
