/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',

  // The dashboard serves no user-supplied images, so the built-in Image
  // Optimization API is not needed. Disabling it drops the sharp dependency,
  // whose bundled libvips carried two high and one critical advisory
  // (npm audit). Images are delivered as-is.
  images: {
    unoptimized: true,
  },
}

module.exports = nextConfig
