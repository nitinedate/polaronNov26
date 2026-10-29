# Polaron V1.17.5: iPhone live scans report what they really checked

A live iPhone scan completed with "No known indicators", 0 findings and 4 coverage gaps. Reproducing it showed that
the scan ran with **no threat intelligence loaded** (0 indicators), and that three of the four gaps were wrong.

## Fixed
- "Backup Manifest.db not present" and "No iOS app inventory evidence found" no longer appear for live captures:
  the phone's own app list is merged first.
- The jailbreak-app check now sees a live iPhone's apps (it ran before they were merged); it also knows Dopamine,
  TrollStore and Filza.
- ML scoring and the sequence model say they analyse Android app code instead of reporting a "missing" classifier.
- Anything the collector could not read on the phone (profiles, crash reports, a refused command) is shown under
  Coverage instead of staying inside the capture bundle.
- A scan that ran with zero indicators says so in its verdict box; New scan and Scan a connected phone warn before
  starting when no feed is loaded.
- Threat intelligence lists recommended sources (Pegasus/MVT, stalkerware) with Download links, or Subscribe when
  online sync is on.
- iPhone apps show "Binary not collected" instead of "No APK in evidence"; the indicator sweep reports log files too.

## To get a meaningful result for the scanned iPhone
1. Threat intelligence -> Recommended sources: download both files (or Subscribe), import them.
2. Open the scan and select Scan again: it re-checks the same capture against the new indicators; the phone does not
   need to be reconnected.
