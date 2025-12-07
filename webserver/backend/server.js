#!/usr/bin/env node

const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const { execFile } = require("child_process");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3001;

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
app.use(cors());
app.use(bodyParser.json());

// ---------------------------------------------------------------------------
// CURRENT CONFIG (in-memory)
// ---------------------------------------------------------------------------
let currentConfig = {
  interface: "wlan1",
  mode: "ap",             // "ap" | "sta" | "mesh"
  ssid: "halow_ap",
  bssid: "",
  channel: 1,
  bandwidth: 1,           // MHz: 1, 2, 4, 8, 16
  country: "US",
  txPowerDbm: 10,
  ipv4Mode: "static",     // "static" | "dhcp"
  ipv4Address: "192.168.50.1",
  ipv4Netmask: "255.255.255.0",
  ipv4Gateway: "",
};

// ---------------------------------------------------------------------------
// FUNCTION TO APPLY CONFIG
// Replace this with calls into your actual Pi scripts
// ---------------------------------------------------------------------------
function applyHalowConfig(config, callback) {
  // Example wiring — replace with your real scripts
  const args = [
    config.interface,
    config.mode,
    config.ssid,
    String(config.channel),
    String(config.bandwidth),
    config.country,
    String(config.txPowerDbm),
    config.ipv4Mode,
    config.ipv4Address,
    config.ipv4Netmask,
    config.ipv4Gateway,
  ];

  execFile(
    "/usr/local/bin/configure_halow.sh", // change to your actual script
    args,
    { timeout: 30000 },
    (error, stdout, stderr) => {
      console.log("configure_halow stdout:", stdout);
      console.error("configure_halow stderr:", stderr);

      if (error) return callback(error);
      callback(null);
    }
  );
}

// ---------------------------------------------------------------------------
// REST API
// ---------------------------------------------------------------------------

// Get current config
app.get("/api/halow/config", (req, res) => {
  res.json(currentConfig);
});

// Update + apply config
app.post("/api/halow/config", (req, res) => {
  const incoming = req.body || {};

  if (!incoming.interface) {
    return res.status(400).json({ error: "interface is required" });
  }

  if (!["ap", "sta", "mesh"].includes(incoming.mode)) {
    return res.status(400).json({ error: "mode must be ap|sta|mesh" });
  }

  // merge config
  currentConfig = {
    ...currentConfig,
    ...incoming,
    channel: Number(incoming.channel ?? currentConfig.channel),
    bandwidth: Number(incoming.bandwidth ?? currentConfig.bandwidth),
    txPowerDbm: Number(incoming.txPowerDbm ?? currentConfig.txPowerDbm),
  };

  // apply it
  applyHalowConfig(currentConfig, (err) => {
    if (err) {
      return res.status(500).json({
        error: "Failed to apply configuration",
        details: err.message,
      });
    }
    res.json({ ok: true, config: currentConfig });
  });
});

// Reapply last config (e.g., after reboot)
app.post("/api/halow/reapply", (req, res) => {
  applyHalowConfig(currentConfig, (err) => {
    if (err) {
      return res.status(500).json({ error: "Failed to re-apply config" });
    }
    res.json({ ok: true, config: currentConfig });
  });
});

// ---------------------------------------------------------------------------
// STATIC FRONTEND SERVING (React build)
// ---------------------------------------------------------------------------

const distPath = path.join(__dirname, "..", "frontend", "dist");
app.use(express.static(distPath));

// FINAL FALLBACK: any request not matched above -> index.html
// NOTE: no path string here, so path-to-regexp is never invoked.
app.use((req, res) => {
  res.sendFile(path.join(distPath, "index.html"));
});

// ---------------------------------------------------------------------------
// START SERVER
// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`HaLow config server listening on port ${PORT}`);
});
