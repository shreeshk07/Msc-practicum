# PhishTriage

**Automated Phishing Email Triage Using Rule-Based Analysis for Security Operations**

Author: Shreesh Kallihal · Student ID: 24261335
MSc Cybersecurity, National College of Ireland (MSCCYB1_B)
Practicum implementation

## What this is

A small standalone Python tool. It reads an RFC-5322 email file
(`.eml`), pulls evidence out of the headers and body, scores it
against a set of weighted rules, and writes a structured triage
report. There are twenty seven rules across four categories (six
auth, six header, eight url, seven content). Twenty five are active;
HDR-005 and URL-002 are registered placeholders that return None
until GeoIP and WHOIS adapters exist.

The idea is to do the first-line investigation steps a SOC analyst
would do on a user-reported email, so the analyst can spend their
time on the cases that need human judgement.

It runs in six stages, in the order data flows through them:

1. **Parser**: reads an `.eml` file, normalises it, and exposes
   headers and body parts as structured objects.
2. **Auth checker**: finds the `Authentication-Results` header and
   parses the SPF, DKIM, and DMARC outcomes.
3. **Indicators**: pulls out URLs, sender and reply-to domains, and
   compares the From-address domain against the Return-Path. URL-002
   is a registered placeholder for a future domain-age check and
   currently never fires.
4. **Scoring engine**: reads `config/rules.yaml`, evaluates each
   rule against the parsed evidence, sums the weighted
   contributions, and maps the total to a risk band (LOW, MEDIUM,
   HIGH, CRITICAL).
5. **Reporting**: writes a Markdown report for human reading and a
   JSON document shaped like a TheHive case for SOC ingestion.
6. **Experiment runner**: drives the pipeline over a labelled
   corpus, times each email, and records decisions and evidence to
   a CSV for later statistical analysis.

## Why rule-based, not ML

Two reasons. First, every decision is explainable: the engine
records which rule fired, what evidence triggered it, and how much
it contributed. Second, there's no training step and no model
artefacts to manage. Any small team that can run Python can deploy
it. The trade-off is that detection accuracy will be lower than a
trained ML system on novel attack variants. The research question
is specifically about **triage time reduction at comparable
decision quality**, not about beating ML on accuracy.

## Requirements

- Python 3.13. This is the version the project was developed and tested on.
- `pip` and the standard `venv` module.
- Git Bash or WSL on Windows, only for the `.sh` download scripts in `tools/`. Everything else runs from cmd, PowerShell, or any other shell.
- An internet connection for the corpus and indicator download scripts.

## Install

Windows (cmd):

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

macOS or Linux:

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Check the install by running the test suite:

```
pytest tests/ -q
```

The versions in `requirements.txt` are minimum versions (`>=`), so a fresh install resolves to the latest compatible releases.

## Run on a single email

```
python triage.py --input tests/fixtures/sample_phishing.eml
```

Prints a Markdown report to stdout. Options:

- `--json` prints the TheHive case JSON to stdout instead of Markdown.
- `--quiet` prints a single line per email and suppresses the report body.
- `--write` also writes the Markdown report and the TheHive case JSON under `results/per_email/`.

## Run over a corpus

Corpus runs go through the experiment runner, not `triage.py`. The multi-line commands in this README use `\` to continue a line (bash). In Windows cmd, use `^` at the end of each line instead, or put the whole command on one line.

```
python run_experiment.py custom \
  --sa data/raw/spamassassin \
  --sample spamassassin:spam_2=40 \
  --output results/spamassassin_spam.csv
```

## Configuration

All rule weights, thresholds, and risk band cut-offs live in
`config/rules.yaml` and `config/settings.yaml`. The Python code has
no magic numbers for scoring. That means you can tune the engine or
run ablation experiments without touching code.

## Project layout

```
phishtriage/
├── README.md                       this file
├── LICENSE                         MIT licence for the code
├── requirements.txt                Python dependencies (minimum versions)
├── triage.py                       CLI entrypoint for a single email
├── run_experiment.py               CLI entrypoint for corpus runs and analysis
├── config/
│   ├── rules.yaml                  rule definitions, weights, thresholds
│   └── settings.yaml               output paths, risk bands, runtime knobs
├── phishtriage/
│   ├── parser.py                   stage 1: .eml ingestion
│   ├── auth.py                     stage 2: SPF/DKIM/DMARC parsing
│   ├── indicators.py               stage 3: URLs, domains, mismatches
│   ├── scoring.py                  stage 4: rule engine
│   ├── reporting.py                stage 5: report generation
│   ├── experiment.py               stage 6: corpus driver, timer, statistics
│   └── utils.py                    shared helpers
├── tests/
│   ├── fixtures/                   small hand-curated .eml files
│   └── test_*.py                   pytest test modules
├── tools/
│   ├── manual_triage_form/         participant web form for the human study
│   ├── convert_json_to_manual.py   form JSON exports to manual baseline CSVs
│   ├── convert_form_to_manual.py   form CSV export to a manual baseline CSV
│   ├── fn_readout.py               per false negative readout for a run CSV
│   └── download_*.sh               corpus and indicator download scripts
├── participant_package/            form, manifest, and the 20 session emails given to participants
├── data/                           corpora land here after the download scripts run (gitignored)
├── results/                        frozen run outputs and combined analysis
└── docs/
    ├── manual_checklist.md         the human-baseline checklist used in the experiment
    ├── experiment_protocol.md      the full experiment protocol
    ├── calibration_notes.md        calibration history and recall analysis
    └── ethics/                     ethics package for the human study
```

## Datasets

The primary evaluation uses three publicly available corpora:

- **Nazario phishing corpus (2023 to 2025)**: confirmed phishing
  emails, used for the phishing class.
  Source: https://monkey.org/~jose/phishing/
- **phishing_pot**: curated modern phishing samples, used for the
  phishing class.
  Source: https://github.com/rf-peixoto/phishing_pot
- **SpamAssassin ham**: legitimate mail, used for the benign
  baseline class.
  Source: https://spamassassin.apache.org/old/publiccorpus/

The Champa et al. 2024 dataset was dropped from the primary metric
because its CSV format strips the email headers. With no headers a
header based engine cannot read SPF, DKIM, DMARC, or the From and
Reply-To lines, so it cannot fairly be scored on that data.

These corpora are widely used in academic phishing research and
hold no personal data of living subjects who could be re-identified
from the corpus alone. The ethics package for the human study is in
`docs/ethics/`.

## Testing

```
pytest tests/ -v
```

The suite currently has 112 tests, all passing.

## Reproducing the experiment

The full protocol is in `docs/experiment_protocol.md`. In short: a
fixed sample is drawn from each corpus, and each email is triaged
two ways. For the manual baseline, ten participants review the
emails on the web form in `tools/manual_triage_form/`, following the
checklist in `docs/manual_checklist.md`. The form records the time
spent on each email at millisecond precision and exports the
verdicts, confidence, reasons, and times to CSV and JSON. For the
automated baseline, the pipeline triages the same emails and records
its own decisions and times. The two are then compared per email,
with a paired t-test on triage time and McNemar's test on decision
agreement.

### One-time setup

```
bash tools/download_modern_corpora.sh   # Nazario 2023 to 2025 and phishing_pot into data/raw/
bash tools/download_corpora.sh          # SpamAssassin ham baseline into data/raw/
bash tools/download_iocs.sh             # URLhaus indicators into data/iocs/
```

On Windows, run the `.sh` scripts from Git Bash or WSL.

### Run the experiment

```
# 20-email pilot, quick smoke test
python run_experiment.py pilot

# Frozen v3b corpus run: 55 modern phishing + 25 legitimate (the headline test)
python run_experiment.py custom \
  --sa data/raw/spamassassin \
  --nazario data/raw/nazario/phishing-2024.mbox \
  --nazario data/raw/nazario/phishing-2025.mbox \
  --phishing-pot data/raw/phishing_pot \
  --sample spamassassin:easy_ham=15 \
  --sample spamassassin:hard_ham=10 \
  --sample nazario:phishing-2024=15 \
  --sample nazario:phishing-2025=15 \
  --sample phishing_pot:all=25 \
  --output results/operational_v3b.csv

# Analyse a CSV
python run_experiment.py analyse --csv results/operational_v3b.csv

# Analyse with a manual baseline CSV joined in (paired t-test)
python run_experiment.py analyse --csv results/session_auto.csv \
                                 --manual results/manual/all_manual.csv
```

### Analysing the human study sessions

Each participant session exports a JSON file from the form. To build the manual baseline CSVs and run the paired analysis:

```
python tools/convert_json_to_manual.py \
  --json-dir results/raw_sessions \
  --manifest tools/manual_triage_form/session_emails/manifest.json \
  --out-dir results/manual

python run_experiment.py analyse --csv results/session_auto.csv \
                                 --manual results/manual/all_manual.csv
```

The converter validates every file (email count, manifest match, verdict values, repeated emails) and writes nothing if any check fails. It produces one `{pseudonym}_manual.csv` per participant and a combined `all_manual.csv`. The raw session exports are not part of this repository, see Data and ethics below.

### Modern corpus pilot (v3b, clean 80 email modern sample)

| Metric    | Value |
|-----------|-------|
| Precision | 0.978 |
| Recall    | 0.800 |
| F1        | 0.880 |

The recall gap is structural, not a tuning defect, and is
documented in `docs/calibration_notes.md`. The automated pipeline
triages each email in milliseconds, against tens to low hundreds of
seconds for manual triage, which is the time trade-off the research
question targets.

## Data and ethics

The human study followed the ethics package in `docs/ethics/`. Under the consent form, participants are identified by pseudonym only and the results are kept for thirty days after final submission of the dissertation, then deleted. For that reason the participant level records are not part of this repository: the raw session exports (`results/raw_sessions/`) and the per participant manual CSVs (`results/manual/`). Both paths are listed in `.gitignore`.

Included instead:

- `results/analyse_output_final.txt` is the combined analysis output for the 20 email session set: timing, accuracy, and the paired comparison, with summary statistics per pseudonym.
- `results/ess_summary.txt` is the combined questionnaire summary.
- `results/session_auto.csv` is the automated engine output on the same 20 emails.
- `results/operational_v3b.csv` is the frozen 80 email corpus run behind the precision, recall, and F1 figures above.
- `results/manual_results_template.csv` is the column layout for a manual baseline file.
- `participant_package/` and `tools/manual_triage_form/` hold the form and session emails, so the study can be repeated with new participants.

The `--manual` analysis step needs a manual baseline CSV collected from your own sessions with the form, in the layout produced by `tools/convert_json_to_manual.py`.

## License

Code: MIT. Datasets: their original licences apply.
