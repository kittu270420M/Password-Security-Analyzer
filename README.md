# Password Security Analyzer v3.0

A minimalist, privacy-first password security dashboard built with plain **HTML5, CSS3 and vanilla JavaScript (ES6+)**.
It analyzes password strength, entropy and estimated crack time, gives dynamic security recommendations,
generates cryptographically secure passwords, and exports a PDF security report, all **locally in your browser**.

```
Password-Security-Analyzer/
├── index.html      # structure
├── style.css       # light + dark themes, responsive layout
├── script.js       # analysis engine, generator, PDF writer, UI
├── README.md
└── screenshots/    # real screenshots of the running app (light, dark, mobile)
```

## Installation

There is nothing to install. No build step, no dependencies, no backend.

1. Unzip the project.
2. Open `index.html` in any modern browser (Chrome, Edge, Firefox, Safari).

Optional: serve it locally (for example `python3 -m http.server 8000`, then open <http://localhost:8000>).

> The page uses *Poppins* if it is installed on your system and otherwise falls back to a clean system font.
> No fonts or scripts are loaded from the internet.

## Usage

**Analyzer**
- Type a password. Results update live, or press **Analyze**.
- The eye icon shows or hides the password.
- You get a strength meter (0–100), entropy, length, character pool size, an estimated crack time, per-category checks, a 12-character check, a common-password warning, and tailored suggestions.

**Generator**
- Choose a length from 1 to 40 (slider is red 1–8, yellow 9–14, green 15–40) and the character types, then press **Generate**.
- **Copy** puts the password on your clipboard and shows a confirmation.
- If every type is unchecked you are asked to choose at least one.

**Footer actions**
- **Download Security Report** creates a PDF in the browser. It never contains the password.
- **Clear** resets the input and all results.

**Theme**
- The moon/sun button toggles light and dark mode instantly. Your choice is remembered with `localStorage` (the only thing the app ever stores).

## How it works

| Topic | Method |
|---|---|
| Entropy | `L × log2(N)`, where N is the character pool (26 upper + 26 lower + 10 digits + 32 symbols) |
| Crack time | Average guesses `N^L / 2` ÷ **10 billion guesses/second** (illustrative). Computed in log space, so very large values never overflow |
| Score | Entropy-based (0–100), reduced for common passwords, sequences, repeats, years and "word + digits" structures. 80+ Strong, 50–79 Moderate, below 50 Weak |
| Generator | `crypto.getRandomValues()` with rejection sampling (no modulo bias), one character from each selected type when length allows, secure Fisher–Yates shuffle. `Math.random()` is never used |
| PDF | A small hand-written PDF 1.4 writer in `script.js`, so no library or network is needed. Only the analysis summary is passed to it, never the password |

## Limitations (please read)

- Entropy from a character pool assumes uniformly random characters. Human-created passwords are far more predictable, so the estimate can **overestimate** real strength (for example, a long but well-known phrase can score high).
- Crack time is **theoretical** and depends on the attack scenario, hashing algorithm, hardware and guessing rate. It is not a guarantee.
- The common-password list is small and built in. The app does **not** check real data breaches.
- Use a unique password for every account and enable multi-factor authentication.

## Privacy

No backend, no database, no analytics, no external API. The password stays in the input field in your browser, is never logged, stored or transmitted, and is never written to the PDF.

## Browser support

Any current browser with `crypto.getRandomValues`, CSS custom properties and CSS grid. Copy-to-clipboard uses the Clipboard API with a fallback.
