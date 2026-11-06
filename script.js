/* ==========================================================
   Password Security Analyzer v3.0 — script.js
   Vanilla ES6+. All analysis runs locally; nothing is sent anywhere.
   ========================================================== */
'use strict';

/* ---------------------------------------------------------
   1. CONFIGURATION
   --------------------------------------------------------- */
const GUESSES_PER_SECOND = 1e10;           // illustrative default (10 billion / s)
const SECONDS_PER_YEAR = 31557600;         // 365.25 days
const POOL_SIZES = { upper: 26, lower: 26, number: 10, symbol: 32, other: 32 };

const CHARSETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  number: '0123456789',
  symbol: '!@#$%^&*()-_=+[]{};:,.?/~'
};

const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password12', 'password123', 'password1234', 'passw0rd', 'p@ssw0rd', 'p@ssword',
  '123456', '1234567', '12345678', '123456789', '1234567890', '111111', '000000', '121212', '123123', '654321',
  'qwerty', 'qwerty1', 'qwerty12', 'qwerty123', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbnm', '1q2w3e4r', '1q2w3e',
  'abc123', 'abcd1234', 'abcdef', 'iloveyou', 'letmein', 'welcome', 'welcome1', 'admin', 'admin123', 'administrator',
  'login', 'monkey', 'dragon', 'football', 'baseball', 'master', 'sunshine', 'princess', 'shadow', 'superman',
  'trustno1', 'whatever', 'secret', 'hello', 'hello123', 'freedom', 'batman', 'starwars', 'changeme', 'default',
  'guest', 'root', 'test', 'test123', 'user', 'india123', 'cricket', 'iloveu', 'google', 'flower', 'michael', 'jesus'
]);
const COMMON_WORDS = ['password', 'passw0rd', 'qwerty', 'letmein', 'welcome', 'iloveyou', 'admin', 'trustno1', 'dragon', 'monkey', 'football', 'sunshine', 'princess', '123456'];
const SEQUENCES = ['abcdefghijklmnopqrstuvwxyz', '0123456789', '9876543210', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'poiuytrewq', 'lkjhgfdsa', 'mnbvcxz', 'zyxwvutsrqponmlkjihgfedcba'];

/* ---------------------------------------------------------
   2. ANALYSIS ENGINE (pure functions, no DOM)
   --------------------------------------------------------- */
function charClasses(pw) {
  return {
    upper: /[A-Z]/.test(pw),
    lower: /[a-z]/.test(pw),
    number: /[0-9]/.test(pw),
    symbol: /[ -\/:-@\[-`{-~]/.test(pw),   // printable ASCII symbols and space
    other: /[^\x20-\x7E]/.test(pw)          // anything outside printable ASCII
  };
}

function poolSize(classes) {
  let n = 0;
  for (const k of Object.keys(POOL_SIZES)) if (classes[k]) n += POOL_SIZES[k];
  return n;
}

function entropyBits(length, pool) {
  return pool > 1 ? length * Math.log2(pool) : 0;
}

/** log10 of the estimated average crack time in seconds, computed in log space so it never overflows. */
function log10CrackSeconds(length, pool, gps = GUESSES_PER_SECOND) {
  if (!length || pool < 2) return -Infinity;
  return length * Math.log10(pool) - Math.log10(2) - Math.log10(gps);
}

const LARGE_NAMES = ['', 'thousand', 'million', 'billion', 'trillion', 'quadrillion', 'quintillion', 'sextillion', 'septillion', 'octillion', 'nonillion', 'decillion'];

/** Returns { text, html } describing a duration given as log10(seconds). */
function formatCrackTime(log10Sec) {
  const plain = (t) => ({ text: t, html: t });
  if (!isFinite(log10Sec) || log10Sec < -3) return plain('Instantly');
  if (log10Sec < 0) return plain('Less than a second');

  const fmt = (v) => (v >= 100 ? Math.round(v) : Math.round(v * 10) / 10).toLocaleString('en-US');
  const unit = (v, singular) => { const r = fmt(v); return `${r} ${singular}${r === '1' ? '' : 's'}`; };

  if (log10Sec < 300) {
    const s = Math.pow(10, log10Sec);
    if (s < 60) return plain(unit(s, 'second'));
    if (s < 3600) return plain(unit(s / 60, 'minute'));
    if (s < 86400) return plain(unit(s / 3600, 'hour'));
    if (s < 86400 * 365.25) return plain(unit(s / 86400, 'day'));
  }

  const log10Years = log10Sec - Math.log10(SECONDS_PER_YEAR);
  if (log10Years < 3) return plain(unit(Math.pow(10, log10Years), 'year'));

  const group = Math.floor(log10Years / 3);
  if (group < LARGE_NAMES.length) {
    const mantissa = Math.pow(10, log10Years - group * 3);
    const t = `${fmt(mantissa)} ${LARGE_NAMES[group]} years`;
    return plain(t);
  }
  const exp = Math.floor(log10Years);
  const mant = Math.pow(10, log10Years - exp);
  const m = (Math.round(mant * 10) / 10).toFixed(1);
  return { text: `${m} x 10^${exp} years`, html: `${m} &times; 10<sup>${exp}</sup> years` };
}

function normalizeLeet(s) {
  return s.toLowerCase().replace(/[@4]/g, 'a').replace(/0/g, 'o').replace(/3/g, 'e').replace(/[$5]/g, 's').replace(/7/g, 't').replace(/[1!]/g, 'i');
}

function isCommonPassword(pw) {
  const lower = pw.toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) return true;
  const stripped = lower.replace(/[^a-z]+$/, '');                  // drop trailing digits / symbols
  if (stripped.length >= 4 && COMMON_PASSWORDS.has(stripped)) return true;
  const leet = normalizeLeet(pw).replace(/[^a-z]+$/, '');
  if (leet.length >= 4 && (COMMON_PASSWORDS.has(leet) || COMMON_WORDS.includes(leet))) return true;
  // Short passwords that are just a common word with a few extra characters
  if (pw.length <= 14) {
    const leetFull = normalizeLeet(pw);
    if (COMMON_WORDS.some((w) => w.length >= 6 && leetFull.includes(normalizeLeet(w)))) return true;
  }
  return false;
}

function hasSequence(pw) {
  const lower = pw.toLowerCase();
  for (const seq of SEQUENCES) {
    for (let i = 0; i + 3 <= seq.length; i++) {
      if (lower.includes(seq.slice(i, i + 3))) return true;
    }
  }
  return false;
}

const hasRepeats = (pw) => /(.)\1{2,}/.test(pw);
const hasYear = (pw) => /(?:19|20)\d{2}/.test(pw);
/** e.g. "Krishna@2026", "Summer2024!", "Hello123" -> one word followed by symbols/digits */
const hasWordDigitsPattern = (pw) => /^[A-Za-z]{4,}[^A-Za-z]{1,6}$/.test(pw) && /[A-Za-z]/.test(pw) && /[^A-Za-z]/.test(pw);

function analyzePassword(pw) {
  const length = pw.length;
  const classes = charClasses(pw);
  const pool = poolSize(classes);
  const entropy = entropyBits(length, pool);
  const log10Sec = log10CrackSeconds(length, pool);
  const common = length > 0 && isCommonPassword(pw);
  const sequence = length > 0 && hasSequence(pw);
  const repeats = length > 0 && hasRepeats(pw);
  const year = length > 0 && hasYear(pw);
  const wordPattern = length > 0 && hasWordDigitsPattern(pw);

  const checks = {
    upper: classes.upper,
    lower: classes.lower,
    number: classes.number,
    symbol: classes.symbol || classes.other,
    len12: length >= 12,
    notCommon: length > 0 && !common
  };

  // ----- score -----
  let score = Math.min(100, (entropy / 90) * 100);
  if (sequence) score -= 15;
  if (repeats) score -= 10;
  if (year) score -= 12;
  if (wordPattern) score -= 15;
  if (length > 0 && length < 8) score = Math.min(score, 35);
  if (common) score = Math.min(score, 8);
  score = Math.max(0, Math.round(score));
  if (length === 0) score = 0;

  let level = 'weak', label = 'Weak';
  if (score >= 80) { level = 'strong'; label = 'Strong'; }
  else if (score >= 50) { level = 'moderate'; label = 'Moderate'; }

  // ----- crack time (a known-common password is guessed immediately in practice) -----
  let crack = formatCrackTime(log10Sec);
  let crackNote = 'Average time at 10 billion guesses / second';
  if (common) {
    crack = { text: 'Instantly', html: 'Instantly' };
    crackNote = 'Found in common-password lists; attackers try these first';
  }

  // ----- weaknesses & suggestions -----
  const weaknesses = [];
  const suggestions = [];
  if (common) weaknesses.push('Matches or closely resembles a commonly used password.');
  if (length < 12) weaknesses.push(`Short length (${length} characters; 12 or more recommended).`);
  if (!classes.upper) weaknesses.push('No uppercase letters.');
  if (!classes.lower) weaknesses.push('No lowercase letters.');
  if (!classes.number) weaknesses.push('No numbers.');
  if (!checks.symbol) weaknesses.push('No symbols.');
  if (sequence) weaknesses.push('Contains a predictable sequence (such as abc, 123 or qwerty).');
  if (repeats) weaknesses.push('Contains repeated characters (such as aaa or 111).');
  if (year) weaknesses.push('Contains a year-like number, which is easy to guess.');
  if (wordPattern) weaknesses.push('Follows a predictable "word + digits/symbols" structure.');

  if (common) suggestions.push({ type: 'bad', text: 'Avoid common passwords and well-known words; attackers try them first.' });
  if (length < 12) suggestions.push({ type: 'todo', text: 'Use at least 12 characters; a longer passphrase can be easier to remember.' });
  if (!classes.upper) suggestions.push({ type: 'todo', text: 'Add uppercase letters.' });
  if (!classes.lower) suggestions.push({ type: 'todo', text: 'Add lowercase letters.' });
  if (!classes.number) suggestions.push({ type: 'todo', text: 'Include numbers.' });
  if (!checks.symbol) suggestions.push({ type: 'todo', text: 'Include symbols, if the service allows them.' });
  if (sequence) suggestions.push({ type: 'todo', text: 'Avoid predictable sequences such as abc, 123 or qwerty.' });
  if (repeats) suggestions.push({ type: 'todo', text: 'Avoid repeating the same character several times in a row.' });
  if (year) suggestions.push({ type: 'todo', text: 'Avoid years, birthdays and other dates.' });
  if (wordPattern) suggestions.push({ type: 'todo', text: 'Avoid a single word followed by digits or a symbol; use random words or characters instead.' });

  if (suggestions.length === 0) {
    suggestions.push({ type: 'good', text: 'Great job! This password has strong length and variety.' });
    suggestions.push({ type: 'good', text: 'No common patterns or predictable sequences were detected.' });
  }
  suggestions.push({ type: 'tip', text: 'Use a unique password for every account.' });

  return { length, classes, pool, entropy, log10Sec, crack, crackNote, common, sequence, repeats, year, wordPattern, checks, score, level, label, weaknesses, suggestions };
}

/* ---------------------------------------------------------
   3. SECURE PASSWORD GENERATOR
   --------------------------------------------------------- */
function secureRandomInt(max) {
  // Unbiased integer in [0, max) using rejection sampling over crypto.getRandomValues()
  const buf = new Uint32Array(1);
  const limit = Math.floor(0x100000000 / max) * max;
  do { globalThis.crypto.getRandomValues(buf); } while (buf[0] >= limit);
  return buf[0] % max;
}

function secureShuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/** Returns a string, or null when no character category is selected. */
function generatePassword(length, opts) {
  const sets = Object.keys(CHARSETS).filter((k) => opts[k]).map((k) => CHARSETS[k]);
  if (sets.length === 0) return null;
  length = Math.max(1, Math.min(40, Math.floor(length)));

  const pick = (set) => set[secureRandomInt(set.length)];
  const chars = [];

  if (length >= sets.length) {
    sets.forEach((s) => chars.push(pick(s)));               // one from every selected category
    const all = sets.join('');
    while (chars.length < length) chars.push(pick(all));
  } else {
    // Not enough room for every category: use a random subset of categories
    secureShuffle(sets.slice()).slice(0, length).forEach((s) => chars.push(pick(s)));
  }
  return secureShuffle(chars).join('');
}

/* ---------------------------------------------------------
   4. PDF REPORT (hand-written PDF 1.4 writer, no libraries)
   The password is NOT an input to this code path: only the
   analysis summary is passed in.
   --------------------------------------------------------- */
const PDF = { W: 595.28, H: 841.89, M: 48 };

function pdfSanitize(s) {
  return String(s)
    .replace(/[  -​ ]/g, ' ')
    .replace(/[–—]/g, '-').replace(/[‘’]/g, "'").replace(/[“”]/g, '"')
    .replace(/×/g, 'x').replace(/≈/g, '~')
    .replace(/[^\x20-\x7E]/g, '?');
}
const pdfEscape = (s) => pdfSanitize(s).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');

function textWidth(s, size, bold) {
  let w = 0;
  for (const ch of pdfSanitize(s)) {
    if ('ijl.,:;!|\' '.includes(ch)) w += 0.28;
    else if ('ft()[]{}-/\\"'.includes(ch)) w += 0.34;
    else if ('mwMW@%'.includes(ch)) w += 0.88;
    else if (/[A-Z]/.test(ch)) w += 0.69;
    else if (/[0-9]/.test(ch)) w += 0.556;
    else w += 0.54;
  }
  return w * size * (bold ? 1.06 : 1);
}

function wrapText(text, size, maxW, bold) {
  const lines = [];
  let line = '';
  for (const word of pdfSanitize(text).split(/\s+/)) {
    const test = line ? line + ' ' + word : word;
    if (textWidth(test, size, bold) <= maxW) line = test;
    else { if (line) lines.push(line); line = word; }
  }
  if (line) lines.push(line);
  return lines;
}

const hexRGB = (hex) => {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255].map((v) => v.toFixed(3)).join(' ');
};

function buildReportPDF(a, when) {
  const pages = [];
  let ops = [];
  let y = 0;
  const { W, H, M } = PDF;
  const contentW = W - 2 * M;

  const newPage = () => { if (ops.length) pages.push(ops.join('\n')); ops = []; y = M; };
  const ensure = (h) => { if (y + h > H - 60) newPage(); };
  const Y = (top) => (H - top).toFixed(2);
  const rect = (x, top, w, h, hex) => ops.push(`${hexRGB(hex)} rg ${x.toFixed(2)} ${Y(top + h)} ${w.toFixed(2)} ${h.toFixed(2)} re f`);
  const strokeRect = (x, top, w, h, hex) => ops.push(`${hexRGB(hex)} RG 0.8 w ${x.toFixed(2)} ${Y(top + h)} ${w.toFixed(2)} ${h.toFixed(2)} re S`);
  const text = (s, x, top, size, bold, hex) => ops.push(`BT /${bold ? 'F2' : 'F1'} ${size} Tf ${hexRGB(hex || '#0F172A')} rg ${x.toFixed(2)} ${Y(top)} Td (${pdfEscape(s)}) Tj ET`);
  const hr = () => { ops.push(`${hexRGB('#E2E8F0')} RG 0.8 w ${M} ${Y(y)} m ${W - M} ${Y(y)} l S`); y += 12; };

  const paragraph = (s, size = 10.5, hex = '#334155', indent = 0, bold = false) => {
    const lines = wrapText(s, size, contentW - indent, bold);
    lines.forEach((ln) => { ensure(size * 1.5); text(ln, M + indent, y + size, size, bold, hex); y += size * 1.5; });
  };
  const heading = (s) => { ensure(40); y += 8; text(s, M, y + 13, 13, true, '#0F172A'); y += 20; hr(); };
  const bullet = (s, hex = '#334155') => {
    const lines = wrapText(s, 10.5, contentW - 16, false);
    ensure(lines.length * 15.75);
    rect(M + 2, y + 5.5, 3.5, 3.5, '#2563EB');
    lines.forEach((ln) => { text(ln, M + 16, y + 10.5, 10.5, false, hex); y += 15.75; });
  };

  newPage();

  // Header band
  rect(0, 0, W, 104, '#0F172A');
  rect(M, 30, 34, 34, '#38BDF8');
  text('PS', M + 8, 53, 15, true, '#0F172A');
  text('Password Security Report', M + 48, 49, 21, true, '#F8FAFC');
  text('Password Security Analyzer v3.0 - generated locally in your browser', M + 48, 66, 9.5, false, '#CBD5E1');
  text('Generated: ' + when, M + 48, 82, 9.5, false, '#CBD5E1');
  y = 124;

  // Privacy banner
  rect(M, y, contentW, 30, '#EAF2FE');
  text('Privacy: the password itself is never included in this report.', M + 12, y + 19, 10, true, '#1D4ED8');
  y += 50;

  // Summary
  const levelHex = a.level === 'strong' ? '#15803D' : a.level === 'moderate' ? '#A16207' : '#DC2626';
  const boxW = (contentW - 24) / 3;
  const boxes = [['STRENGTH RATING', a.label, levelHex], ['SECURITY SCORE', `${a.score} / 100`, '#0F172A'], ['PASSWORD LENGTH', `${a.length} characters`, '#0F172A']];
  boxes.forEach((b, i) => {
    const x = M + i * (boxW + 12);
    strokeRect(x, y, boxW, 58, '#CBD5E1');
    text(b[0], x + 12, y + 20, 8.5, true, '#64748B');
    text(b[1], x + 12, y + 44, 17, true, b[2]);
  });
  y += 76;

  heading('Key metrics');
  const row = (k, v) => { ensure(20); text(k, M, y + 11, 10.5, true, '#0F172A'); const lines = wrapText(v, 10.5, contentW - 170, false); lines.forEach((ln, i) => text(ln, M + 170, y + 11 + i * 15, 10.5, false, '#334155')); y += Math.max(1, lines.length) * 15 + 5; };
  row('Estimated entropy', a.length ? `${a.entropy.toFixed(1)} bits` : 'n/a');
  row('Character pool size', a.pool ? `${a.pool} possible characters` : 'n/a');
  row('Estimated crack time', a.crack.text);
  row('Assumed guessing rate', '10 billion guesses per second (illustrative)');
  if (a.common) row('Note', 'Matches a common-password pattern; real-world cracking would be near-instant.');

  heading('Character category checks');
  const checkRows = [
    ['Uppercase letters (A-Z)', a.checks.upper], ['Lowercase letters (a-z)', a.checks.lower],
    ['Numbers (0-9)', a.checks.number], ['Symbols (! @ # $ ...)', a.checks.symbol],
    ['At least 12 characters', a.checks.len12], ['Not a common password', a.checks.notCommon]
  ];
  checkRows.forEach(([k, ok]) => {
    ensure(20);
    text(k, M, y + 11, 10.5, false, '#0F172A');
    rect(M + 250, y, 62, 16, ok ? '#DCFCE7' : '#FEE2E2');
    text(ok ? 'PASSED' : 'NOT MET', M + 259, y + 11.5, 8.5, true, ok ? '#15803D' : '#B91C1C');
    y += 22;
  });

  heading('Detected weaknesses');
  if (a.weaknesses.length) a.weaknesses.forEach((w) => bullet(w));
  else paragraph('No weaknesses were detected by this tool\'s checks.');

  heading('Security recommendations');
  a.suggestions.forEach((s) => bullet(s.text));

  ensure(250);   // keep the methodology section together on one page
  heading('Methodology and limitations');
  paragraph('Entropy is estimated as length x log2(character pool size). The pool is the sum of the character classes used (26 uppercase, 26 lowercase, 10 digits, 32 symbols). This assumes every character is chosen uniformly at random, so it can overestimate the unpredictability of human-created passwords.');
  y += 4;
  paragraph('Crack time uses an illustrative average exhaustive-search model: average guesses = N^L / 2, divided by 10 billion guesses per second. It is theoretical; real cracking time depends on the attack scenario, hashing algorithm, hardware and guessing rate, and is not a guarantee.');
  y += 4;
  paragraph('The score starts from entropy and is reduced for common passwords, sequences, repeated characters, years and predictable word-plus-digits structures. This tool does not check real data breaches or leaked-password databases. Use a unique password for every account and enable multi-factor authentication.');

  newPage();   // flush the last page

  // ----- assemble the PDF file (all ASCII, so string length == byte length) -----
  const total = pages.length;
  const streams = pages.map((p, i) => {
    const footer = `${hexRGB('#E2E8F0')} RG 0.8 w ${M} 52 m ${W - M} 52 l S\nBT /F1 8.5 Tf ${hexRGB('#64748B')} rg ${M} 38 Td (${pdfEscape('Password Security Analyzer - local report, contains no password data')}) Tj ET\n` +
      `BT /F1 8.5 Tf ${hexRGB('#64748B')} rg ${(W - M - 40).toFixed(2)} 38 Td (${pdfEscape(`Page ${i + 1} of ${total}`)}) Tj ET`;
    return p + '\n' + footer;
  });

  let out = '%PDF-1.4\n';
  const offsets = [];
  const add = (n, body) => { offsets[n] = out.length; out += `${n} 0 obj\n${body}\nendobj\n`; };
  const pageObj = (i) => 5 + i * 2;
  add(1, '<< /Type /Catalog /Pages 2 0 R >>');
  add(2, `<< /Type /Pages /Kids [${streams.map((_, i) => pageObj(i) + ' 0 R').join(' ')}] /Count ${total} >>`);
  add(3, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
  add(4, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
  streams.forEach((s, i) => {
    add(pageObj(i), `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${W.toFixed(2)} ${H.toFixed(2)}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${pageObj(i) + 1} 0 R >>`);
    add(pageObj(i) + 1, `<< /Length ${s.length} >>\nstream\n${s}\nendstream`);
  });
  const count = 5 + total * 2;
  const xrefAt = out.length;
  out += `xref\n0 ${count}\n0000000000 65535 f \n`;
  for (let n = 1; n < count; n++) out += String(offsets[n]).padStart(10, '0') + ' 00000 n \n';
  out += `trailer\n<< /Size ${count} /Root 1 0 R >>\nstartxref\n${xrefAt}\n%%EOF\n`;

  const bytes = new Uint8Array(out.length);
  for (let i = 0; i < out.length; i++) bytes[i] = out.charCodeAt(i) & 255;
  return bytes;
}

function formatWhen(d) {
  const p = (n) => String(n).padStart(2, '0');
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? '+' : '-';
  const oh = p(Math.floor(Math.abs(off) / 60)), om = p(Math.abs(off) % 60);
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())} (UTC${sign}${oh}:${om})`;
}

/* ---------------------------------------------------------
   5. UI
   --------------------------------------------------------- */
function initUI() {
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));
  const root = document.documentElement;

  /* ---- Theme ---- */
  const themeBtn = $('#themeToggle');
  const applyTheme = (t) => {
    root.setAttribute('data-theme', t);
    themeBtn.setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
  };
  applyTheme(root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light');
  themeBtn.addEventListener('click', () => {
    const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    try { localStorage.setItem('psa-theme', next); } catch (e) { /* storage unavailable */ }
  });

  /* ---- Navigation: active state follows scroll ---- */
  const links = $$('.nav__link');
  const sections = ['analyzer', 'generator', 'about'].map((id) => document.getElementById(id));
  const setActive = (id) => links.forEach((l) => l.classList.toggle('is-active', l.dataset.section === id));
  let ticking = false;
  const onScroll = () => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      ticking = false;
      const atBottom = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4;
      let current = 'analyzer';
      sections.forEach((s) => { if (s.getBoundingClientRect().top <= 140) current = s.id; });
      if (atBottom) current = 'about';
      setActive(current);
    });
  };
  window.addEventListener('scroll', onScroll, { passive: true });
  links.forEach((l) => l.addEventListener('click', () => setActive(l.dataset.section)));

  /* ---- Analyzer ---- */
  const input = $('#passwordInput');
  const ring = $('#ring'), ringBar = $('#ringBar');
  const CIRC = 2 * Math.PI * 52;
  let latest = null;

  const renderSuggestions = (items) => {
    const list = $('#suggestList');
    list.innerHTML = '';
    items.forEach((s) => {
      const li = document.createElement('li');
      li.className = s.type;
      li.textContent = s.text;
      list.appendChild(li);
    });
  };

  const DEFAULT_TIPS = [
    { type: 'tip', text: 'Use at least 12 characters; a longer passphrase can be easier to remember.' },
    { type: 'tip', text: 'Add uppercase letters.' },
    { type: 'tip', text: 'Add lowercase letters.' },
    { type: 'tip', text: 'Include numbers.' },
    { type: 'tip', text: 'Include symbols, if the service allows them.' },
    { type: 'tip', text: 'Avoid predictable sequences such as abc, 123 or qwerty.' },
    { type: 'tip', text: 'Use a unique password for every account.' }
  ];

  const setCheck = (name, state) => {   // state: 'pass' | 'fail' | 'idle'
    $$(`[data-check="${name}"]`).forEach((el) => {
      el.classList.toggle('is-pass', state === 'pass');
      el.classList.toggle('is-fail', state === 'fail');
    });
  };

  function renderEmpty() {
    latest = null;
    ring.className = 'ring';
    ring.setAttribute('aria-label', 'Password strength meter: not analyzed');
    ringBar.style.strokeDashoffset = CIRC;
    $('#strengthLabel').textContent = 'Not analyzed';
    $('#strengthScore').innerHTML = '&mdash;';
    $('#mEntropy').innerHTML = '&mdash;';
    $('#mLength').textContent = '0 characters';
    $('#mPool').innerHTML = '&mdash;';
    $('#crackValue').innerHTML = '&mdash;';
    $('#crackNote').textContent = 'Enter a password to estimate.';
    ['upper', 'lower', 'number', 'symbol', 'len12', 'common'].forEach((c) => setCheck(c, 'idle'));
    $('#commonText').textContent = 'Not a common password';
    renderSuggestions(DEFAULT_TIPS);
  }

  function render(a) {
    latest = a;
    ring.className = `ring is-${a.level}`;
    ring.setAttribute('aria-label', `Password strength: ${a.label}, score ${a.score} out of 100`);
    ringBar.style.strokeDashoffset = CIRC * (1 - a.score / 100);
    $('#strengthLabel').textContent = a.label;
    $('#strengthScore').textContent = `${a.score} / 100`;
    $('#mEntropy').textContent = `${a.entropy.toFixed(1)} bits`;
    $('#mLength').textContent = `${a.length} character${a.length === 1 ? '' : 's'}`;
    $('#mPool').textContent = `${a.pool} symbols`;
    $('#crackValue').innerHTML = a.crack.html;
    $('#crackNote').textContent = a.crackNote;

    ['upper', 'lower', 'number', 'symbol'].forEach((c) => setCheck(c, a.checks[c] ? 'pass' : 'idle'));
    setCheck('len12', a.checks.len12 ? 'pass' : 'idle');
    if (a.common) { setCheck('common', 'fail'); $('#commonText').textContent = 'Common password detected'; }
    else { setCheck('common', 'pass'); $('#commonText').textContent = 'Not a common password'; }
    renderSuggestions(a.suggestions);
  }

  function runAnalysis() {
    const pw = input.value;
    if (!pw) renderEmpty(); else render(analyzePassword(pw));
  }

  input.addEventListener('input', runAnalysis);
  $('#analyzeForm').addEventListener('submit', (e) => {
    e.preventDefault();
    if (!input.value) { flashAction('Enter a password first.', true); input.focus(); return; }
    runAnalysis();
  });

  /* ---- Show / hide ---- */
  const eye = $('#eyeBtn');
  eye.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    eye.classList.toggle('is-on', show);
    eye.setAttribute('aria-pressed', String(show));
    eye.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    input.focus();
  });

  /* ---- Status helper ---- */
  let actionTimer;
  function flashAction(msg, isError) {
    const el = $('#actionStatus');
    el.textContent = msg;
    el.classList.toggle('is-error', !!isError);
    clearTimeout(actionTimer);
    actionTimer = setTimeout(() => { el.textContent = ''; }, 3500);
  }

  /* ---- Clear ---- */
  $('#clearBtn').addEventListener('click', () => {
    input.value = '';
    input.type = 'password';
    eye.classList.remove('is-on');
    eye.setAttribute('aria-pressed', 'false');
    eye.setAttribute('aria-label', 'Show password');
    renderEmpty();
    flashAction('Cleared.');
    input.focus();
  });

  /* ---- Download report ---- */
  $('#downloadBtn').addEventListener('click', () => {
    if (!latest) { flashAction('Analyze a password first to generate a report.', true); input.focus(); return; }
    const now = new Date();
    const bytes = buildReportPDF(latest, formatWhen(now));   // only the analysis summary is passed in
    const blob = new Blob([bytes], { type: 'application/pdf' });
    const url = URL.createObjectURL(blob);
    const p = (n) => String(n).padStart(2, '0');
    const a = document.createElement('a');
    a.href = url;
    a.download = `Password-Security-Report-${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}-${p(now.getHours())}${p(now.getMinutes())}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    flashAction('Security report downloaded. It does not contain your password.');
  });

  /* ---- Generator ---- */
  const slider = $('#lengthSlider');
  const lengthValue = $('#lengthValue');
  const out = $('#generatedOutput');
  const hint = $('#genHint');
  const genStatus = $('#genStatus');
  const HINT_DEFAULT = hint.textContent;

  slider.addEventListener('input', () => { lengthValue.textContent = slider.value; });

  const getOpts = () => ({ upper: $('#optUpper').checked, lower: $('#optLower').checked, number: $('#optNumber').checked, symbol: $('#optSymbol').checked });

  function flashGen(msg, isError) {
    genStatus.textContent = msg;
    genStatus.classList.toggle('is-error', !!isError);
  }

  $('#generateBtn').addEventListener('click', () => {
    const opts = getOpts();
    const len = parseInt(slider.value, 10);
    const pw = generatePassword(len, opts);
    if (pw === null) {
      out.value = '';
      hint.textContent = 'Select at least one character type to generate a password.';
      hint.classList.add('is-error');
      flashGen('');
      return;
    }
    hint.classList.remove('is-error');
    const selected = Object.values(opts).filter(Boolean).length;
    hint.textContent = len < selected
      ? `Length ${len} is shorter than the ${selected} selected character types, so some types are not represented.`
      : (len < 8 ? 'Lengths below 8 characters are not recommended.' : HINT_DEFAULT);
    out.value = pw;
    flashGen('');
    resetCopy();
  });

  ['#optUpper', '#optLower', '#optNumber', '#optSymbol'].forEach((s) => $(s).addEventListener('change', () => {
    if (Object.values(getOpts()).some(Boolean)) { hint.classList.remove('is-error'); hint.textContent = HINT_DEFAULT; }
  }));

  const copyBtn = $('#copyBtn'), copyText = $('#copyText');
  let copyTimer;
  function resetCopy() { clearTimeout(copyTimer); copyBtn.classList.remove('is-done'); copyText.textContent = 'Copy'; }
  copyBtn.addEventListener('click', async () => {
    if (!out.value) { flashGen('Generate a password first.', true); return; }
    let ok = false;
    try { await navigator.clipboard.writeText(out.value); ok = true; }
    catch (e) {
      try { out.focus(); out.select(); ok = document.execCommand('copy'); out.setSelectionRange(0, 0); } catch (e2) { ok = false; }
    }
    if (ok) {
      copyBtn.classList.add('is-done');
      copyText.textContent = 'Copied!';
      flashGen('Password copied to clipboard.');
      clearTimeout(copyTimer);
      copyTimer = setTimeout(() => { resetCopy(); flashGen(''); }, 2200);
    } else {
      flashGen('Copy failed. Select the text and copy it manually.', true);
    }
  });

  renderEmpty();
  onScroll();
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initUI);
  else initUI();
}

/* Allow the pure logic to be unit-tested in Node. */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyzePassword, generatePassword, formatCrackTime, buildReportPDF, log10CrackSeconds, poolSize, charClasses, secureRandomInt };
}
