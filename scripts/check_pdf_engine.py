#!/usr/bin/env python3
"""
check_pdf_engine.py — diagnose why the Gap report downloads as HTML instead of PDF.

RUN IT INSIDE THE SAME ENVIRONMENT THAT SERVES THE API (the API container), e.g.:
    docker compose exec api python /app/check_pdf_engine.py
    # or, from the backend dir on the host that runs it:
    python check_pdf_engine.py

It answers three questions:
  1) Is the FIXED code actually running here? (the version that never serves HTML)
  2) Can xhtml2pdf (the high-fidelity engine) render in THIS environment?
  3) Can the PyMuPDF fallback render here?
Then it prints a one-line verdict telling you exactly what to do.
"""
import importlib, io, os, sys, traceback

# Make the running 'app' package importable whether this is run from the backend
# dir, the repo root, or copied into the API container's workdir.
for _p in (os.getcwd(), os.path.join(os.getcwd(), "backend"), "/app", "/app/backend"):
    if os.path.isdir(os.path.join(_p, "app")) and _p not in sys.path:
        sys.path.insert(0, _p)

GREEN, RED, YEL, RST = "\033[32m", "\033[31m", "\033[33m", "\033[0m"
def ok(m):   print(f"{GREEN}[ OK ]{RST} {m}")
def bad(m):  print(f"{RED}[FAIL]{RST} {m}")
def warn(m): print(f"{YEL}[WARN]{RST} {m}")

print("=" * 68)
print(" Gap-report PDF engine diagnostic")
print("=" * 68)

# 1) Which code is running?
fixed = False
try:
    mod = importlib.import_module("app.services.gap_assessment_report")
    path = getattr(mod, "__file__", "?")
    fixed = hasattr(mod, "_fitz_html_to_pdf") and hasattr(mod, "_pisa_html_to_pdf")
    src = ""
    try:
        import inspect
        src = inspect.getsource(mod.export_merged_gap_report)
    except Exception:
        pass
    serves_html = 'text/html' in src
    print(f"\nRunning module: {path}")
    if fixed and not serves_html:
        ok("FIXED code is live (two-engine render, no HTML fallback).")
    else:
        bad("OLD code is live — it still falls back to serving HTML.")
        print("     -> Your deployment is NOT running the updated gap_assessment_report.py.")
except Exception as exc:
    warn(f"Could not import app.services.gap_assessment_report ({exc}).")
    # Fallback: read the source file directly and check for the fix markers.
    found = None
    for _p in sys.path + [os.getcwd(), "/app", "/app/backend"]:
        cand = os.path.join(_p, "app", "services", "gap_assessment_report.py")
        if os.path.isfile(cand):
            found = cand
            break
    if found:
        txt = open(found, encoding="utf-8").read()
        fixed = "_fitz_html_to_pdf" in txt and "_pisa_html_to_pdf" in txt
        serves_html = '"text/html"' in txt or "'text/html'" in txt
        print(f"Checked source file: {found}")
        if fixed and not serves_html:
            ok("FIXED code is on disk (two-engine render, no HTML fallback).")
        else:
            bad("OLD code is on disk — it still falls back to serving HTML.")
    else:
        warn("Could not locate gap_assessment_report.py to check. Run from the backend dir "
             "or inside the API container.")

# 2) xhtml2pdf (primary)
print("\n-- xhtml2pdf (high-fidelity engine) --")
pisa_ok = False
for name in ("reportlab", "PIL", "xhtml2pdf"):
    try:
        m = importlib.import_module(name)
        v = getattr(m, "__version__", getattr(m, "Version", "?"))
        ok(f"{name} {v}")
    except Exception as exc:
        bad(f"{name} import failed: {exc}")
try:
    from xhtml2pdf import pisa
    buf = io.BytesIO()
    html = "<html><body><h1>probe</h1><table border=1><tr><td>a</td><td>b</td></tr></table></body></html>"
    st = pisa.CreatePDF(html, dest=buf, encoding="utf-8")
    if st.err:
        bad(f"xhtml2pdf rendered with {st.err} error(s) — pisa is broken in this env.")
    elif buf.getvalue()[:5] != b"%PDF-":
        bad("xhtml2pdf did not produce a PDF.")
    else:
        pisa_ok = True
        ok(f"xhtml2pdf rendered a {buf.tell()} byte PDF.")
except Exception:
    bad("xhtml2pdf raised while rendering:")
    traceback.print_exc()

# 3) PyMuPDF fallback
print("\n-- PyMuPDF (fallback engine) --")
fitz_ok = False
try:
    try:
        import pymupdf as fitz
    except Exception:
        import fitz
    ok(f"PyMuPDF {getattr(fitz, '__version__', '?')}")
    buf = io.BytesIO()
    w = fitz.DocumentWriter(buf)
    mb = fitz.Rect(0, 0, 597, 843)
    story = fitz.Story(html="<h1>probe</h1><p>hello</p>")
    more = 1
    while more:
        dev = w.begin_page(mb); more, _ = story.place(mb + (36, 36, -36, -36)); story.draw(dev); w.end_page()
    w.close()
    if buf.getvalue()[:5] == b"%PDF-":
        fitz_ok = True
        ok(f"PyMuPDF fallback rendered a {buf.tell()} byte PDF.")
    else:
        bad("PyMuPDF did not produce a PDF.")
except Exception:
    bad("PyMuPDF fallback raised:")
    traceback.print_exc()

# Verdict
print("\n" + "=" * 68)
if pisa_ok and fixed:
    print(f"{GREEN}VERDICT:{RST} Everything is healthy. Full-fidelity PDF should download.")
elif pisa_ok and not fixed:
    print(f"{YEL}VERDICT:{RST} The engine works, but OLD code is running. Deploy the updated "
          "gap_assessment_report.py and REBUILD the API image, then restart.")
elif (not pisa_ok) and fitz_ok and fixed:
    print(f"{YEL}VERDICT:{RST} xhtml2pdf is broken here, but the fallback works, so downloads will "
          "be PDF (lower fidelity). Fix xhtml2pdf (see the FAIL line above) for the styled report.")
elif (not pisa_ok) and fitz_ok and not fixed:
    print(f"{RED}VERDICT:{RST} xhtml2pdf is broken AND old code is running -> you get HTML. "
          "Deploy the updated code + rebuild the image. That alone makes downloads PDF via the "
          "fallback; then repair xhtml2pdf for full fidelity.")
elif not fitz_ok:
    print(f"{RED}VERDICT:{RST} Neither engine works here. Install deps: "
          "pip install 'reportlab>=4.4,<6' 'xhtml2pdf>=0.2.16,<0.3' 'pymupdf>=1.24' and rebuild.")
print("=" * 68)
