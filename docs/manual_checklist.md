# Manual Phishing Triage Checklist (Human Baseline)

This checklist is the procedure the analyst follows when triaging
each email **manually** during the experiment. It is the control
condition that is timed and compared against the automated pipeline.

It also doubles as the **evidence-completeness rubric**. The
automated runs are scored against the same items, so "completeness"
uses the same criteria for both conditions.

---

## Setup

Before starting a timed run:

1. Open a stopwatch (mobile phone or a script) reset to zero.
2. Open the `.eml` file in a plain-text viewer.
3. Open the web form at `tools/manual_triage_form/index.html`, which
   records the verdict and times each email.
4. Have the following reference tools available in browser tabs:
   - `https://urlhaus-api.abuse.ch/api/`
   - `https://www.virustotal.com/gui/home/url`
   - A WHOIS lookup tool of choice.

Do not start the stopwatch until step 4 is complete and the email is
already on screen.

## Steps (start the stopwatch on step 1)

1. **Read the headers.** Note Message-ID, From, Return-Path, Reply-To,
   Subject, Date, and X-Mailer. Write them in the form.

2. **Locate the Authentication-Results header** (or note its absence).
   Record SPF, DKIM, DMARC results.

3. **Cross-check sender domains.** Compare the From-domain with the
   Return-Path domain and the Reply-To domain. Note any mismatch.

4. **Check the display name.** Does it claim to be a known brand whose
   real domain differs from the From-domain? Note any such impersonation.

5. **Extract URLs from the body.** List every distinct URL present.

6. **Inspect each URL.**
   - Is it an IP address rather than a hostname?
   - Is it a punycode or look-alike domain?
   - Is it a known URL shortener?
   - Is the visible text different from the underlying href?

7. **Check at least the most suspicious URL** against URLhaus or your
   reputation source of choice. Record the result.

8. **Read the body text.** Is there urgency language (24 hours,
   immediate action), a credential or payment request, or an executable
   attachment?

9. **Form a verdict.** One of: BENIGN, SUSPICIOUS, or MALICIOUS. Write
   the three strongest reasons.

10. **Stop the stopwatch.** Record the elapsed time in the form.

## Verdict mapping

To allow direct comparison with the automated tool's risk band:

| Manual verdict | Maps to automated band |
|----------------|------------------------|
| BENIGN         | LOW                    |
| SUSPICIOUS     | MEDIUM or HIGH         |
| MALICIOUS      | HIGH or CRITICAL       |

## Evidence-completeness scoring

Each of the following items contributes one point if its result was
recorded in the form. The maximum score per email is 10. The same
rubric is applied to the automated report by checking which fields
are populated.

- [ ] Message-ID recorded
- [ ] From-domain recorded
- [ ] Return-Path domain recorded
- [ ] Reply-To domain recorded (or noted as absent)
- [ ] SPF result recorded
- [ ] DKIM result recorded
- [ ] DMARC result recorded
- [ ] At least one URL extracted (or noted as none present)
- [ ] At least one URL classified for risk
- [ ] Final verdict and reasons recorded

## Notes for the experimenter

- Triage every email exactly once. Do not re-read or revise after the
  stopwatch stops.
- If a step cannot be completed because the data is genuinely absent
  (e.g. no Authentication-Results header), record "absent" and move on
  rather than spending time hunting.
- The point of the manual run is to mimic what a junior SOC analyst
  realistically does, not to perform a perfect investigation.
