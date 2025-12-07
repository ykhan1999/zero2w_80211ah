import { useEffect, useState } from "react";

const INITIAL_CONFIG = {
  interface: "wlan1",
  mode: "ap",
  ssid: "",
  bssid: "",
  channel: 1,
  bandwidth: 1,
  country: "US",
  txPowerDbm: 10,
  ipv4Mode: "static",
  ipv4Address: "192.168.50.1",
  ipv4Netmask: "255.255.255.0",
  ipv4Gateway: "",
};

export default function App() {
  const [config, setConfig] = useState(INITIAL_CONFIG);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState(null); // { type: "ok" | "error", message: string }

  // Fetch initial config from backend
  useEffect(() => {
    let cancelled = false;

    async function loadConfig() {
      try {
        const res = await fetch("/api/halow/config");
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (!cancelled) {
          setConfig((prev) => ({ ...prev, ...data }));
          setLoading(false);
        }
      } catch (err) {
        console.error("Failed to load config:", err);
        if (!cancelled) {
          setStatus({
            type: "error",
            message: "Failed to load config from server",
          });
          setLoading(false);
        }
      }
    }

    loadConfig();
    return () => {
      cancelled = true;
    };
  }, []);

  function handleChange(e) {
    const { name, value } = e.target;

    // Normalize numeric fields
    if (["channel", "bandwidth", "txPowerDbm"].includes(name)) {
      setConfig((prev) => ({ ...prev, [name]: value === "" ? "" : Number(value) }));
    } else {
      setConfig((prev) => ({ ...prev, [name]: value }));
    }
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setSaving(true);
    setStatus(null);

    try {
      const res = await fetch("/api/halow/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }

      setConfig((prev) => ({ ...prev, ...(data.config || {}) }));
      setStatus({ type: "ok", message: "Configuration applied successfully." });
    } catch (err) {
      console.error("Failed to save config:", err);
      setStatus({
        type: "error",
        message: `Failed to apply configuration: ${err.message}`,
      });
    } finally {
      setSaving(false);
    }
  }

  async function handleReapply() {
    setSaving(true);
    setStatus(null);
    try {
      const res = await fetch("/api/halow/reapply", { method: "POST" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      setStatus({ type: "ok", message: "Re-applied last configuration." });
    } catch (err) {
      console.error("Failed to re-apply config:", err);
      setStatus({
        type: "error",
        message: `Failed to re-apply configuration: ${err.message}`,
      });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="app-root">
      <header className="header">
        <h1>Zero2W HaLow Config</h1>
        <p className="subtitle">Configure IEEE 802.11ah radio over REST</p>
      </header>

      <main className="main">
        {loading ? (
          <div className="card">Loading current configuration…</div>
        ) : (
          <form className="card form" onSubmit={handleSubmit}>
            <section className="section">
              <h2>Radio</h2>
              <div className="grid">
                <label>
                  Interface
                  <input
                    name="interface"
                    value={config.interface}
                    onChange={handleChange}
                    required
                  />
                </label>

                <label>
                  Mode
                  <select name="mode" value={config.mode} onChange={handleChange}>
                    <option value="ap">Access Point</option>
                    <option value="sta">Station</option>
                    <option value="mesh">Mesh</option>
                  </select>
                </label>

                <label>
                  Country
                  <input
                    name="country"
                    value={config.country}
                    onChange={handleChange}
                    maxLength={2}
                  />
                </label>

                <label>
                  Channel
                  <input
                    type="number"
                    name="channel"
                    min="1"
                    max="52"
                    value={config.channel}
                    onChange={handleChange}
                  />
                </label>

                <label>
                  Bandwidth (MHz)
                  <select
                    name="bandwidth"
                    value={config.bandwidth}
                    onChange={handleChange}
                  >
                    <option value={1}>1</option>
                    <option value={2}>2</option>
                    <option value={4}>4</option>
                    <option value={8}>8</option>
                    <option value={16}>16</option>
                  </select>
                </label>

                <label>
                  Tx Power (dBm)
                  <input
                    type="number"
                    name="txPowerDbm"
                    min="0"
                    max="30"
                    value={config.txPowerDbm}
                    onChange={handleChange}
                  />
                </label>
              </div>
            </section>

            <section className="section">
              <h2>Network</h2>
              <div className="grid">
                <label>
                  SSID
                  <input
                    name="ssid"
                    value={config.ssid}
                    onChange={handleChange}
                    placeholder="halow_ap"
                    required
                  />
                </label>

                <label>
                  BSSID (optional)
                  <input
                    name="bssid"
                    value={config.bssid}
                    onChange={handleChange}
                    placeholder="auto"
                  />
                </label>

                <label>
                  IPv4 Mode
                  <select
                    name="ipv4Mode"
                    value={config.ipv4Mode}
                    onChange={handleChange}
                  >
                    <option value="static">Static</option>
                    <option value="dhcp">DHCP</option>
                  </select>
                </label>

                {config.ipv4Mode === "static" && (
                  <>
                    <label>
                      IPv4 Address
                      <input
                        name="ipv4Address"
                        value={config.ipv4Address}
                        onChange={handleChange}
                      />
                    </label>

                    <label>
                      Netmask
                      <input
                        name="ipv4Netmask"
                        value={config.ipv4Netmask}
                        onChange={handleChange}
                      />
                    </label>

                    <label>
                      Gateway (optional)
                      <input
                        name="ipv4Gateway"
                        value={config.ipv4Gateway}
                        onChange={handleChange}
                      />
                    </label>
                  </>
                )}
              </div>
            </section>

            {status && (
              <div
                className={`status ${
                  status.type === "error" ? "status-error" : "status-ok"
                }`}
              >
                {status.message}
              </div>
            )}

            <div className="actions">
              <button type="submit" disabled={saving}>
                {saving ? "Applying…" : "Apply Configuration"}
              </button>
              <button
                type="button"
                className="secondary"
                onClick={handleReapply}
                disabled={saving}
              >
                Re-apply Last
              </button>
            </div>
          </form>
        )}
      </main>
    </div>
  );
}
