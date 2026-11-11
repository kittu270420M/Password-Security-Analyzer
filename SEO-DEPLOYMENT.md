# Password Security Analyzer — SEO-ready build

This folder contains the SEO-updated static website.

## Files
- `index.html` — updated title, description, canonical URL, social metadata, WebApplication JSON-LD, and visible password-security guide/FAQ.
- `style.css` — original styles plus styling for the new guide and FAQ.
- `script.js` — original application logic, unchanged.
- `robots.txt` — permits crawling and points crawlers to the sitemap.
- `sitemap.xml` — lists the canonical homepage URL.

## Deploy
1. Replace the corresponding files in the root of your existing GitHub/Vercel project with these files.
2. Add `robots.txt` and `sitemap.xml` to the same project root.
3. Commit and push the changes; wait for the Vercel deployment to finish.
4. Confirm these URLs load:
   - https://password-security-analyzer-kittu07.vercel.app/
   - https://password-security-analyzer-kittu07.vercel.app/robots.txt
   - https://password-security-analyzer-kittu07.vercel.app/sitemap.xml

## Google Search Console
1. Keep the existing Google verification meta tag in `index.html`.
2. In Search Console, open the URL-prefix property for `https://password-security-analyzer-kittu07.vercel.app/`.
3. Submit `sitemap.xml` under **Sitemaps**.
4. Use **URL Inspection** on the homepage, run **Test Live URL**, then select **Request Indexing** if available.
5. Check indexing and search performance over time. Crawling or indexing is not an instant ranking guarantee.

## Target search intent
Primary: free password strength checker; password security analyzer.
Secondary: online password analyzer; secure password generator; password entropy calculator; password cracking time calculator; password security checker.

## Important accuracy notes
- The tool does not query breached-password databases.
- Crack-time values are illustrative estimates based on an assumed 10 billion guesses per second.
- Entropy assumes uniformly random character selection and can overestimate human-created password strength.
- Do not add a `meta keywords` tag; Google says it does not use it for ranking.
