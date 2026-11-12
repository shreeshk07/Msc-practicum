# Manual test plan

Run these five checks before using the form in a real session. They take
a few minutes and they confirm the things that matter most: that the
session loads, that the email appears without delay, that the timer is
honest, that the ground truth stays hidden, and that the output is
complete. Use the twenty session emails in `session_emails/`, which is
what `manifest.json` points at.

Open the browser developer console before you start so you can watch the
timing line that prints after each Next click.

## Check 1: Session loads and Begin stays locked until ready

Purpose: confirm the form will not start without a pseudonym, a stratum,
and a loaded session.

Steps:

1. Open the form, either by double clicking `index.html` and selecting
   `manifest.json` together with the twenty `.eml` files in
   `session_emails/`, or by serving the folder and opening it over
   localhost.
2. Watch the loader line. It should end at "Session loaded. 20 emails
   ready."
3. Leave the pseudonym unset and confirm Begin is disabled.
4. Choose a pseudonym but no stratum. Begin stays disabled.
5. Choose a stratum as well.

Expected: Begin becomes active only after all three are present, the
pseudonym, the stratum, and the loaded session.

## Check 2: The email appears at once, with correct headers

Purpose: confirm the measured content has no entrance animation and that
the header summary is parsed correctly.

Steps:

1. Click Begin.
2. Watch the header summary card and the raw message block as the first
   email appears, and again each time you click Next.

Expected: the header card and the raw message are fully visible the
instant the screen changes. There is no fade or slide on them. The
summary card shows From, Return-Path, Reply-To, and the authentication
line for each email, with the values read from that message. A field
that is missing reads "(not present)".

## Check 3: A fast deliberate click records a small two digit value

Purpose: this is the timing integrity check. It proves that no
transition is being counted as participant time.

Steps:

1. On an email, select a verdict so Next becomes active.
2. As soon as you can after the email is on screen, click Next once,
   deliberately and quickly.
3. Read the line printed in the console, `email <id> time_ms <number>`.

Expected: the number is a small two digit millisecond value, in the tens
of milliseconds, not in the hundreds. A value such as 20 to 90 is right
for a quick human click. If you were to see a steady floor of a few
hundred milliseconds on every email, that would mean an animation was
sitting on the measured path, and the timer would be inflated. Seeing a
genuine two digit value confirms the start reading fires the moment the
content paints and the stop reading fires on the first line of the
click.

## Check 4: Ground truth never shows on screen but is saved

Purpose: confirm the true label is hidden from the participant during
triage yet present in the output.

Steps:

1. Work through the session emails. Watch every part of the triage
   screen, the headers, the raw message, the checklist, and the
   controls.
2. Finish the questionnaire and download the CSV and the JSON.
3. Open both files.

Expected: nowhere on the triage screen does the word phishing or benign
appear as a stated answer for the email in front of you. The verdict
buttons are choices, not the answer. In the downloaded CSV the
`ground_truth` column is filled in, `benign` for email_01 and
`phishing` for email_02, and the JSON carries the same labels.

## Check 5: Questionnaire gating and complete output

Purpose: confirm the questionnaire requires all nine ratings and that
both downloads are well formed.

Steps:

1. After the last email, the questionnaire appears.
2. Leave one of the nine statements unrated and confirm Finish is
   disabled.
3. Rate all nine. Add a sentence in the open box.
4. Click Finish, then download the CSV and the JSON.

Expected: Finish unlocks only when all nine statements are rated. The
open box is optional. The CSV has a header row and one row per email,
with `ess_1` through `ess_9` filled with the numbers you chose and
`ess_open` carrying your sentence. The JSON has the participant block,
the questionnaire answers, and one record per email with its `time_ms`
and the checklist items you ticked. The file names include the
pseudonym and a timestamp.
