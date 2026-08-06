// =============================================================================
// motion.js — capture harness behind motion.html?scene=<sceneId>.
//
// Renders one animated scene into a fixed 1080×1350 stage and exposes a
// frame-addressed seek() for tools/make_motion.py to screenshot. The driver
// loads a scene ONCE and then walks frames, so setup cost is paid per scene,
// not per frame.
//
// Contract with the generator (mirrors carousel.js's window.__carousel* flags):
//   window.__motionScenes   — every renderable scene id
//   window.__motionDone     — true once setup (or failure) has settled
//   window.__motionFailures — human-readable problems; non-empty = broken
//   window.__motionFrames   — frame count of the loaded scene
//   window.__motionSeek(i)  — paint frame i; returns when the DOM is updated
//
// Determinism is the whole point: seek(i) must be a pure function of i. Nothing
// here may depend on wall-clock time, and css/motion.css carries no transitions
// or keyframes, so re-running a capture reproduces the same frames byte for
// byte.
// =============================================================================
import { fetchJSON } from "./common.js";
import { scene as hypeRace } from "./motion/hype_race.js";
import { scene as severityFlood } from "./motion/severity_flood.js";
import { scene as cnaConcentration } from "./motion/cna_concentration.js";

const SCENES = new Map([hypeRace, severityFlood, cnaConcentration].map((s) => [s.id, s]));

window.__motionScenes = [...SCENES.keys()];

const failures = [];

async function boot() {
  const sceneId = new URLSearchParams(location.search).get("scene");

  // Bare load: the generator reads window.__motionScenes and moves on.
  if (!sceneId) return;

  const s = SCENES.get(sceneId);
  if (!s) {
    failures.push(`unknown scene "${sceneId}" — known: ${[...SCENES.keys()].join(", ")}`);
    return;
  }

  const stage = document.getElementById("stage");
  let data;
  try {
    data = await fetchJSON(s.data);
  } catch (err) {
    failures.push(`${sceneId}: ${s.data} failed to load — ${err.message}`);
    return;
  }

  let frames;
  try {
    ({ frames } = s.setup(stage, data));
  } catch (err) {
    failures.push(`${sceneId}: setup failed — ${err.message}`);
    return;
  }

  if (!Number.isInteger(frames) || frames < 2) {
    failures.push(`${sceneId}: setup reported a bad frame count (${frames})`);
    return;
  }

  // Webfonts must be resolved before the first screenshot or the opening
  // frames capture in the fallback face and the clip visibly reflows.
  await document.fonts.ready;

  s.seek(0);
  window.__motionFrames = frames;
  window.__motionSeek = (i) => {
    if (!Number.isInteger(i) || i < 0 || i >= frames) throw new Error(`seek out of range: ${i}`);
    s.seek(i);
    // Force style/layout to flush so the driver's screenshot can't race the
    // paint. Reading offsetHeight is the cheapest synchronous way to do it.
    void document.body.offsetHeight;
  };
}

window.__motionReady = boot()
  .catch((err) => {
    failures.push(`boot crashed — ${err && err.message ? err.message : String(err)}`);
  })
  .finally(() => {
    window.__motionFailures = failures;
    window.__motionDone = true;
  });
