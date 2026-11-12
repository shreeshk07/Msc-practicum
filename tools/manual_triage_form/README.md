# Manual triage form

A self contained web form for the human study. A participant reviews a
set of emails one at a time, decides whether each is phishing or benign,
and answers a short questionnaire at the end. The form records how long
each decision took, at millisecond precision, and writes the results to
a CSV file and a JSON file that the participant downloads and hands back.

The form is one HTML file with its styles and scripts embedded. There
are no frameworks, no external fonts, and no calls to the network. It
runs offline.

This form does not contain the detection engine and does not score
anything. It only presents emails and records what the person decides.

## Files in this folder

- `index.html` is the whole form.
- `manifest.json` lists the emails for one session.
- `TEST_PLAN.md` lists five manual checks to run before a session.

## Building a session manifest

Each session is defined by `manifest.json`. It is a list, and each entry
has three fields:

- `email_id` is a short stable label for the email. It goes into the
  output so you can join the results back to the source later. Keep it
  free of anything that would tell the participant the answer.
- `filename` is the path to the raw `.eml` file, relative to
  `index.html`. Put your session emails in a folder next to the form,
  for example `session_emails/`, and point each entry at the right file.
- `ground_truth` is the true label, `phishing` or `benign`. It is
  written to the output so you can mark each decision right or wrong
  during analysis. It is never shown on screen while the person works.
  The participant cannot see it.

To prepare a real session, replace the two sample entries with one entry
per email you want reviewed, in the order you want them shown. The
welcome screen and the progress label adjust to the number of entries.
The study design calls for twenty emails per session, so the manifest
will normally have twenty entries.

The emails themselves are plain `.eml` files with full headers. The form
parses the header block for the summary card, so make sure each file has
a real header section, a blank line, then the body. The sample files
show the expected shape.

## Keeping participants anonymous

The form never asks for a name. The only identifier is a pseudonym
chosen from a fixed list, P1 through P10, and a stratum, SOC analyst or
student. Keep the mapping from pseudonym to real person on paper or in a
separate file that does not travel with the results. The CSV and JSON
that the form produces carry only the pseudonym, the stratum, the
decisions, the timings, and the ground truth. There is nothing in them
that identifies a person on its own.

## How the timer works

The timer measures the time from the moment an email is readable to the
moment the participant commits the decision by clicking Next.

When an email is shown, the form writes the header summary and the raw
message into the page, then asks the browser for one animation frame.
Inside that frame, which runs just before the content is painted, it
reads `performance.now()` and stores it as the start time. So the clock
starts when the email is actually on screen, not when the code began
preparing it.

When the participant clicks Next, the very first line of the click
handler reads `performance.now()` again. The difference between the two
readings is the decision time. It is rounded to a whole number of
milliseconds and stored as `time_ms`. The reading happens before the
form renders the next email and before any animation runs, so nothing
that happens after the click can be counted as participant time.

Each decision time is also printed to the browser console as the session
runs, in the form `email <id> time_ms <number>`, which is handy when you
verify the timing during testing.

## Why animation is kept off the measured path

Motion is pleasant on a form, but it is dangerous on the part of the
screen that is being timed. If the email content faded or slid in, the
participant could not read it until the motion finished, and that wait
would be added to their decision time. A few hundred milliseconds of
animation, repeated across twenty emails and several people, would bend
the result.

So the email content, meaning the header summary card and the raw
message block, has no entrance animation at all. It appears at once. The
only things that animate are the surrounding chrome that is not being
timed: the progress bar, the buttons, and the welcome, questionnaire,
and finish screens. The stylesheet has a note at the top repeating this
rule for anyone who edits it later.

The form also respects the operating system setting for reduced motion.
If a participant has asked their system to reduce motion, every non
essential animation and transition is switched off across the whole
page.

## Running the form

There are two ways to open it, and both work offline.

The simplest is to double click `index.html`. Browsers block a local
page from reading other local files automatically, so the form will ask
you to select the session files by hand. Choose `manifest.json` and all
of its `.eml` files together in the file picker. The form matches each
manifest entry to a file by its name, then loads the session.

The other way is to serve the folder over a local address, which lets
the form read the files on its own with no picker step. From this
folder, run a small static server, for example:

```
python -m http.server 8000
```

Then open `http://localhost:8000/` in the browser. Nothing leaves the
machine. The server is only there so the page can read sibling files.

## Output

On the finish screen the participant downloads two files.

The CSV has one row per email with these columns: `pseudonym`,
`stratum`, `email_id`, `verdict`, `confidence`, `time_ms`,
`checklist_items_ticked`, `reason`, then `ess_1` through `ess_9`,
`ess_open`, and `ground_truth`. The questionnaire answers are the same
on every row, which keeps the file easy to load in any tool.

The JSON holds the same information in a nested shape: the participant
block, a timestamp, the questionnaire answers once, and a list of the
per email records including which checklist items were ticked.

Instruct participants to download both files before closing the tab.
The browser shows a leave warning while a session holds undownloaded
responses, including on the finish screen, and the warning is only
switched off once a download has begun. The warning cannot protect
against a browser crash, so collect the downloads promptly.
