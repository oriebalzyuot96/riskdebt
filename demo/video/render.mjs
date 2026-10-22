// Renders explainer.html to riskdebt-demo.{mp4,webm} + poster.jpg in this folder.
// Every CSS animation is paused and scrubbed to the exact frame time, so output is deterministic.
// Usage: npm i playwright-core && npx playwright-core install chromium && node render.mjs   (needs ffmpeg on PATH)
//        node render.mjs sheet   (contact sheet of 8 frames → sheet.jpg, for a quick check)
import { chromium } from 'playwright-core';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const FPS = 30, DURATION = 48, W = 1280, H = 720;
const mode = process.argv[2] || 'full';
const frames = process.env.FRAMES_DIR || path.join(os.tmpdir(), 'riskdebt-frames');

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH });
const page = await browser.newPage({ viewport: { width: W, height: H }, deviceScaleFactor: 1 });
await page.goto(pathToFileURL(path.join(here, 'explainer.html')).href, { waitUntil: 'networkidle' });
await page.evaluate(() => document.fonts.ready);
await page.evaluate(() => document.getAnimations().forEach(a => a.pause()));
const seek = t => page.evaluate(ms => document.getAnimations().forEach(a => { a.currentTime = ms; }), t * 1000);
const run = (cmd, args) => { const r = spawnSync(cmd, args, { stdio: 'inherit' }); if (r.status !== 0) throw new Error(`${cmd} failed`); };

if (mode === 'sheet') {
  const dir = path.join(frames, 'sheet'); fs.rmSync(dir, { recursive: true, force: true }); fs.mkdirSync(dir, { recursive: true });
  const times = [3, 10, 18, 23.5, 29.5, 36, 41.5, 47];
  for (const [i, t] of times.entries()) { await seek(t); await page.screenshot({ path: path.join(dir, `s${i}.jpg`), type: 'jpeg', quality: 85 }); }
  await browser.close();
  run('ffmpeg', ['-y', '-loglevel', 'error', '-i', path.join(dir, 's%d.jpg'), '-vf', 'scale=640:-1,tile=2x4:padding=6', '-frames:v', '1', path.join(here, 'sheet.jpg')]);
  console.log('sheet →', path.join(here, 'sheet.jpg'));
  process.exit(0);
}

fs.rmSync(frames, { recursive: true, force: true }); fs.mkdirSync(frames, { recursive: true });
for (let f = 0; f < FPS * DURATION; f++) {
  await seek(f / FPS);
  await page.screenshot({ path: path.join(frames, `f${String(f).padStart(4, '0')}.jpg`), type: 'jpeg', quality: 93 });
  if (f % 300 === 0) console.log(`frame ${f}/${FPS * DURATION}`);
}
await seek(3);
await page.screenshot({ path: path.join(here, 'poster.jpg'), type: 'jpeg', quality: 86 });
await browser.close();

// Frames are full-range JPEG; convert to TV-range yuv420p so the MP4 plays in Safari/iOS.
const input = ['-y', '-loglevel', 'error', '-framerate', String(FPS), '-i', path.join(frames, 'f%04d.jpg')];
const vf = ['-vf', 'scale=in_range=full:out_range=tv,format=yuv420p'];
run('ffmpeg', [...input, ...vf, '-c:v', 'libx264', '-profile:v', 'high', '-preset', 'slow', '-crf', '22',
  '-color_range', 'tv', '-colorspace', 'bt709', '-color_primaries', 'bt709', '-color_trc', 'bt709',
  '-movflags', '+faststart', path.join(here, 'riskdebt-demo.mp4')]);
run('ffmpeg', [...input, ...vf, '-c:v', 'libvpx-vp9', '-b:v', '0', '-crf', '36', '-row-mt', '1', '-deadline', 'good', '-cpu-used', '3',
  path.join(here, 'riskdebt-demo.webm')]);
console.log('done');
