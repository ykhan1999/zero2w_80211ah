import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useWizard } from "../wizard/WizardContext.jsx";

const BACKEND_URL = `${window.location.protocol}//${window.location.hostname}:5174`;

async function scanHalowNetworks() {
  const res = await fetch(`${BACKEND_URL}/api/wifi/scanhalow`);
  if (!res.ok) throw new Error("Scan failed");
  const data = await res.json();
  if (!data.ok) throw new Error(data.error || "Scan failed");
  return data.networks; // [{ssid,bssid,frequency,signal,secure,flags}]
}

function dbmToBars(dbm) {
  if (typeof dbm !== "number") return 0;
  if (dbm >= -50) return 4;
  if (dbm >= -60) return 3;
  if (dbm >= -70) return 2;
  if (dbm >= -80) return 1;
  return 0;
}

function SignalBars({ dbm }) {
  const bars = dbmToBars(dbm);
  return (
    <div className="sig" aria-label={`Signal ${bars}/4`}>
      <span className={`bar ${bars >= 1 ? "on" : ""}`} />
      <span className={`bar ${bars >= 2 ? "on" : ""}`} />
      <span className={`bar ${bars >= 3 ? "on" : ""}`} />
      <span className={`bar ${bars >= 4 ? "on" : ""}`} />
    </div>
  );
}

export default function Step3() {
  const didAutoScan = useRef(false);
  const nav = useNavigate();
  const { answers, setAnswers } = useWizard();

  const mode = answers.mode; // "gateway" | "client"

  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState("");
  const [networks, setNetworks] = useState([]);
  const [useHidden, setUseHidden] = useState(false);

  // collapse/expand list like Step2
  const [listOpen, setListOpen] = useState(false);

  // reset when mode changes
  useEffect(() => {
    setScanError("");
    setNetworks([]);
    setScanning(false);
    setUseHidden(false);
    setListOpen(false);
    didAutoScan.current = false;
  }, [mode]);

  // auto scan once when entering Step3 IF in client mode
  useEffect(() => {
    if (mode !== "client") return;
    if (didAutoScan.current) return;
    didAutoScan.current = true;
    handleScan();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode]);

  const canContinue = useMemo(() => {
    const ssidOk = (answers.halowssid || "").trim().length > 0;

    // you can relax this if you support open networks
    const pwOk = (answers.halowpw || "").trim().length >= 8;

    return ssidOk && pwOk;
  }, [answers.halowssid, answers.halowpw]);

  async function handleScan() {
    if (mode !== "client") return; // only scan in client mode
    setScanning(true);
    setScanError("");
    try {
      const result = await scanHalowNetworks();

      const cleaned = (result || [])
        .filter((n) => (n.ssid || "").trim().length > 0)
        .map((n) => ({
          ...n,
          ssid: (n.ssid || "").trim(),
          signal: typeof n.signal === "string" ? Number(n.signal) : n.signal,
        }));

      // Dedupe by SSID, keep strongest
      const bestBySsid = new Map();
      for (const n of cleaned) {
        const key = n.ssid;
        const existing = bestBySsid.get(key);

        const sNew = typeof n.signal === "number" ? n.signal : -999;
        const sOld = existing && typeof existing.signal === "number" ? existing.signal : -999;

        if (!existing || sNew > sOld || (sNew === sOld && !!n.secure && !existing.secure)) {
          bestBySsid.set(key, n);
        }
      }

      const deduped = Array.from(bestBySsid.values());

      // Sort strongest first
      deduped.sort((a, b) => {
        const sa = typeof a.signal === "number" ? a.signal : -999;
        const sb = typeof b.signal === "number" ? b.signal : -999;
        return sb - sa;
      });

      setNetworks(deduped);
      setListOpen(true); // open list after scan
    } catch (e) {
      setScanError(e?.message || "Unable to scan for HaLow networks.");
    } finally {
      setScanning(false);
    }
  }

  function chooseNetwork(ssid) {
    setUseHidden(false);
    setAnswers((a) => ({ ...a, halowssid: ssid }));
    setListOpen(false); // collapse after selection
  }

  function toggleHidden() {
    setUseHidden((v) => !v);
    setAnswers((a) => ({ ...a, halowssid: "" }));
    setListOpen(false);
  }

  return (
    <div className="card">
      <div className="cardHeader">
        <div>
          <h2>HaLow Network</h2>

          {mode === "client" ? (
            <div className="sub">
              Client mode: Scan for nearby HaLow networks and select the one to join. You can also add a hidden HaLow network.
            </div>
          ) : (
            <div className="sub">
              Gateway mode: Choose the HaLow hotspot name and password that your HaLow devices will use.
            </div>
          )}
        </div>
        <div className="badge">Step 3</div>
      </div>

      <div className="cardBody">
        <div className="grid">
          {/* CLIENT MODE: scan + select */}
          {mode === "client" && (
            <>
              <div className="field">
                <div className="labelRow">
                  <label>Available HaLow networks</label>
                  <span className="hint">Pick one or add hidden</span>
                </div>

                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <button type="button" onClick={handleScan} disabled={scanning}>
                    {scanning ? "Scanning…" : "Scan"}
                  </button>

                  <button
                    type="button"
                    onClick={toggleHidden}
                    className={useHidden ? "primary" : ""}
                    aria-pressed={useHidden}
                  >
                    {useHidden ? "Hidden network: ON" : "Add hidden network"}
                  </button>

                  {!useHidden && networks.length > 0 && !listOpen && (
                    <button type="button" onClick={() => setListOpen(true)}>
                      Change network
                    </button>
                  )}

                  {!useHidden && networks.length > 0 && listOpen && (
                    <button type="button" onClick={() => setListOpen(false)}>
                      Hide list
                    </button>
                  )}
                </div>

                {scanError && (
                  <div style={{ marginTop: 8 }} className="error">
                    {scanError}
                  </div>
                )}

                {!useHidden && listOpen && networks.length > 0 && (
                  <div className="list" style={{ marginTop: 12 }}>
                    {networks.map((n) => {
                      const selected = (answers.halowssid || "") === n.ssid;
                      return (
                        <button
                          key={n.ssid}
                          type="button"
                          className={`listItem ${selected ? "selected" : ""}`}
                          onClick={() => chooseNetwork(n.ssid)}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", width: "100%" }}>
                            <span>{n.ssid}</span>
                            <span className="hint" style={{ display: "flex", alignItems: "center", gap: 10 }}>
                              <span>{n.secure ? "Secured" : "Open"}</span>
                              <SignalBars dbm={n.signal} />
                            </span>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                )}

                {!useHidden && networks.length === 0 && (
                  <div style={{ marginTop: 10 }} className="hint">
                    Tap <b>Scan</b> to find nearby HaLow networks.
                  </div>
                )}

                {!useHidden && networks.length > 0 && !listOpen && (
                  <div style={{ marginTop: 10 }} className="hint">
                    Selected: <b>{answers.halowssid || "—"}</b> (tap <b>Change network</b> to pick another)
                  </div>
                )}
              </div>

              <div className="field">
                <div className="labelRow">
                  <label>HaLow Name (SSID)</label>
                  <span className="hint">Required</span>
                </div>

                {useHidden ? (
                  <input
                    value={answers.halowssid || ""}
                    onChange={(e) => setAnswers((a) => ({ ...a, halowssid: e.target.value }))}
                    placeholder="Enter hidden HaLow SSID"
                  />
                ) : (
                  <input value={answers.halowssid || ""} readOnly placeholder="Select a HaLow network above" />
                )}
              </div>

              <div className="field">
                <div className="labelRow">
                  <label>HaLow Password</label>
                  <span className="hint">Min 8 characters</span>
                </div>
                <input
                  type="password"
                  value={answers.halowpw || ""}
                  onChange={(e) => setAnswers((a) => ({ ...a, halowpw: e.target.value }))}
                  placeholder="Min 8 characters"
                />
              </div>
            </>
          )}

          {/* GATEWAY MODE: create hotspot (no scan) */}
          {mode === "gateway" && (
            <>
              <div className="field">
                <div className="labelRow">
                  <label>HaLow Hotspot Name (SSID)</label>
                  <span className="hint">Required</span>
                </div>
                <input
                  value={answers.halowssid || ""}
                  onChange={(e) => setAnswers((a) => ({ ...a, halowssid: e.target.value }))}
                  placeholder="Choose HaLow network name"
                />
              </div>

              <div className="field">
                <div className="labelRow">
                  <label>HaLow Hotspot Password</label>
                  <span className="hint">Min 8 characters</span>
                </div>
                <input
                  type="password"
                  value={answers.halowpw || ""}
                  onChange={(e) => setAnswers((a) => ({ ...a, halowpw: e.target.value }))}
                  placeholder="Min 8 characters"
                />
              </div>
            </>
          )}

          <div className="actions">
            <button onClick={() => nav("/step/2")}>Back</button>
            <button className="primary" disabled={!canContinue} onClick={() => nav("/step/4")}>
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
