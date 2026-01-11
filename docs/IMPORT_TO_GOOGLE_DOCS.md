# Importing these docs into Google Docs

I created Markdown files (`docs/backend.md`, `docs/frontend.md`) in the repository. Google Docs doesn't import Markdown natively, but here are simple ways to get the content into Google Docs (pick one):

Option A — Quick copy/paste (fast, easiest):
1. Open `docs/backend.md` in VS Code or a Markdown viewer.
2. Select all and copy (Ctrl+C).
3. Open Google Docs and create a new document.
4. Paste (Ctrl+V). Google Docs will paste the text; you may need to adjust headings and code blocks slightly.

Option B — Convert via Markdown-to-DOCX (best formatting):
- If you have Pandoc installed, convert md -> docx, then upload to Google Drive and open with Google Docs.

Commands (Windows PowerShell):

```powershell
# Install Pandoc (if you don't have it): https://pandoc.org/installing.html
# Convert markdown to docx
pandoc docs/backend.md -o backend.docx
pandoc docs/frontend.md -o frontend.docx
# Now upload backend.docx/frontend.docx to Google Drive and open with Google Docs (Drive will convert and keep formatting)
```

Option C — Use a Markdown editor that exports to DOCX / HTML
- Many Markdown editors (Typora, VS Code extensions) can export to DOCX or HTML. Export and then upload/open in Google Docs.

Notes:
- Images referenced relatively (e.g., `src/assets/logo.png`) will not automatically embed; upload images to Google Drive or copy them into the Doc after import.
- If you want me to generate `.docx` files in the repo (so you can directly upload), tell me and I can create them using a local conversion step (Pandoc) — I can only generate the Markdown here unless you want me to run a conversion using tools available in this environment.


If you'd like, I can:
- Create one combined single Markdown file with full docs (I already did two files). Or,
- Produce a `.docx` converted file and add it to the repo (if you want me to attempt conversion here, say so and I will run it).
