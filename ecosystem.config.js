/**
 * PM2 Ecosystem Config — DigitalOcean Droplet
 *
 * Usage:
 *   pm2 start ecosystem.config.js
 *   pm2 save          # persist across reboots
 *   pm2 startup       # generate systemd unit (follow the printed command)
 *   pm2 logs          # tail live logs
 *   pm2 monit         # real-time dashboard
 */

module.exports = {
  apps: [
    {
      name: "unipile-ghl",
      script: "index.js",

      // ── Clustering ──────────────────────────────────────────────────────
      // "max" spawns one worker per vCPU. For a 1-vCPU Droplet use 1.
      // For 2+ vCPU Droplets use "max" for full utilisation.
      instances: 1,
      exec_mode: "fork",   // use "cluster" if instances > 1

      // ── Restart policy ──────────────────────────────────────────────────
      autorestart: true,
      watch: false,          // never watch in production
      max_memory_restart: "256M",

      // ── Environment ─────────────────────────────────────────────────────
      // Do NOT put secrets here — use a .env file or DO environment variables.
      // PM2 will load a .env file automatically if dotenv is installed,
      // or you can set env vars in the Droplet shell before running pm2 start.
      env: {
        NODE_ENV: "production",
        PORT: 3000,
      },

      // ── Logging ─────────────────────────────────────────────────────────
      // JSON-lines logs — tail with: pm2 logs unipile-ghl --raw
      log_type: "json",
      out_file: "/var/log/unipile-ghl/out.log",
      error_file: "/var/log/unipile-ghl/error.log",
      merge_logs: true,
      log_date_format: "YYYY-MM-DDTHH:mm:ss.SSSZ",

      // ── Graceful shutdown ───────────────────────────────────────────────
      kill_timeout: 10000,    // ms to wait for SIGTERM before SIGKILL
      listen_timeout: 8000,   // ms to wait for app to be ready on restart
    },
  ],
};
