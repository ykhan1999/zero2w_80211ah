import express from "express";
import cors from "cors";
import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

function runCommand(cmd, args = [], timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`Command timed out: ${cmd}`));
    }, timeoutMs);

    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));

    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(stderr || `Command failed: ${cmd}`));
      } else {
        resolve({ stdout, stderr });
      }
    });
  });
}

const app = express();
app.use(cors());
app.use(express.json());

// --- locate scripts dir ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SCRIPTS_DIR = path.join(__dirname, "scripts");

// --- simple allowlists for options ---
const MODES = new Set(["gateway", "client"]);
const OPTIM = new Set(["speed", "distance"]);

// Map wizard answers -> script args (NO SHELL, NO STRING CONCAT COMMANDS)
function buildArgsFromAnswers(answers) {
  const args = [];

  // mode
  if (!MODES.has(answers.mode)) throw new Error("Invalid mode");
  args.push("--mode", answers.mode);

  // optim
  if (!OPTIM.has(answers.optim)) throw new Error("Invalid optimization");
  args.push("--optim", answers.optim);

  // regular SSID
  if (typeof answers.regssid !== "string" || answers.regssid.length < 1 || answers.regssid.length > 64) {
    throw new Error("Invalid SSID");
  }

  // HaLow SSID
  if (typeof answers.halowssid !== "string" || answers.halowssid.length < 1 || answers.halowssid.length > 64) {
    throw new Error("Invalid SSID");
  }

  // HaLow PW
  if (typeof answers.halowpw !== "string" || answers.halowpw.length < 8 || answers.halowpw.length > 64) {
    throw new Error("Invalid Password");
  }

// Characters that sed escapes: &, /, "
  const INVALID_CHARS = /[&/"]/;

  function assertValid(value, label) {
   if (INVALID_CHARS.test(value)) {
     throw new Error(`${label} contains invalid characters (&, /, ")`);
   }
  }

  assertValid(answers.regssid, "SSID");
  args.push("--ssid", answers.regssid);

  assertValid(answers.regpw, "Password");
  args.push("--pw", answers.regpw);

  assertValid(answers.halowssid, "HaLow SSID");
  args.push("--halow-ssid", answers.halowssid);

  assertValid(answers.halowpw, "HaLow password");
  args.push("--halow-pw", answers.halowpw);

  return args;
}

app.get("/api/wifi/scan", async (req, res) => {
  try {
    const scriptPath = path.join(SCRIPTS_DIR, "scan_2.4.sh");

    // Trigger scan then read results
    const { stdout } = await runCommand(scriptPath,[], 8000);
    const networks = JSON.parse(stdout);

    res.json({ ok: true, networks });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/api/wifi/scanhalow", async (req, res) => {
  try {
    const scriptPath = path.join(SCRIPTS_DIR, "scan_0.9.sh");

    // Trigger scan then read results
    const { stdout } = await runCommand(scriptPath,[], 8000);
    const networks = JSON.parse(stdout);

    res.json({ ok: true, networks });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post("/api/run", (req, res) => {
  try {
    const answers = req.body?.answers ?? {};
    const args = buildArgsFromAnswers(answers);

    const scriptPath = path.join(SCRIPTS_DIR, "activate_config.sh");

    const child = spawn(scriptPath, args, {
      shell: false,
      stdio: ["ignore", "ignore", "ignore"], // don’t block waiting on output
      detached: true,                        // allow it to keep running
    });

    res.json({ ok: true, pid: child.pid, args });

    child.unref();

    child.on("error", (err) => {
      console.error("Spawn error:", err);
    });

  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.post("/api/stoptimer", (req, res) => {
  try {
    const scriptPath = path.join(SCRIPTS_DIR, "stop_timer.sh");

    const child = spawn(scriptPath, args, {
      shell: false,
      stdio: ["ignore", "ignore", "ignore"], // don’t block waiting on output
      detached: true,                        // allow it to keep running
    });

    res.json({ ok: true, pid: child.pid, args });

    child.unref();

    child.on("error", (err) => {
      console.error("Spawn error:", err);
    });

  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.listen(5174, "0.0.0.0", () => {
  console.log("Backend listening on http://0.0.0.0:5174");
});
