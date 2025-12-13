import express from "express";
import cors from "cors";
import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
app.use(cors());
app.use(express.json());

// --- locate scripts dir ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SCRIPTS_DIR = path.join(__dirname, "scripts");

// --- simple allowlists for options (edit these for your real prompts) ---
const MODES = new Set(["scan", "connect"]);
const VERBOSITY = new Set(["quiet", "normal", "debug"]);

// Map wizard answers -> script args (NO SHELL, NO STRING CONCAT COMMANDS)
function buildArgsFromAnswers(answers) {
  const args = [];

  // mode
  if (!MODES.has(answers.mode)) throw new Error("Invalid mode");
  args.push("--mode", answers.mode);

  // target (example: hostname-ish / ssid-ish)
  if (typeof answers.target !== "string" || answers.target.length < 1 || answers.target.length > 64) {
    throw new Error("Invalid target");
  }
  // very conservative: allow letters/numbers/underscore/dash/dot/space
  if (!/^[\w.\- ]+$/.test(answers.target)) throw new Error("Target has invalid characters");
  args.push("--target", answers.target);

  // verbosity
  if (!VERBOSITY.has(answers.verbosity)) throw new Error("Invalid verbosity");
  args.push("--verbosity", answers.verbosity);

  // example toggle
  if (typeof answers.dryRun !== "boolean") throw new Error("Invalid dryRun");
  if (answers.dryRun) args.push("--dry-run");

  return args;
}

app.post("/api/run", (req, res) => {
  try {
    const answers = req.body?.answers ?? {};
    const args = buildArgsFromAnswers(answers);

    // Pick which script to run (also allowlist this if you have multiple)
    const scriptPath = path.join(SCRIPTS_DIR, "my_script.sh");

    // spawn without shell to avoid injection
    const child = spawn(scriptPath, args, {
      shell: false,
      stdio: ["ignore", "pipe", "pipe"]
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));

    child.on("close", (code) => {
      res.json({ ok: code === 0, code, stdout, stderr, args });
    });

    child.on("error", (err) => {
      res.status(500).json({ ok: false, error: err.message });
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.listen(5174, "0.0.0.0", () => {
  console.log("Backend listening on http://0.0.0.0:5174");
});
