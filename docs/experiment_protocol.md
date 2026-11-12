# Experiment Protocol

This is the experimental plan behind the research question committed
to in CA2.

> **Research question.** To what extent can an automated phishing email
> triage system based on rule-based analysis reduce the mean
> time-to-triage compared to traditional manual phishing triage, while
> maintaining comparable decision accuracy in a security operations
> workflow?

## Design

A **within-subjects controlled comparison**. Each email is
triaged both ways, manually by each of the ten participants using
the checklist on the web form and automatically by the pipeline,
and the manual and automated outcomes are compared on the same
metrics. The within-subjects design removes dataset variation as a
confounder and produces per-email deltas that are directly
attributable to the choice of method.

## Sample

Five corpora go into the evaluation. SpamAssassin ham is kept as the
legitimate-mail baseline; the other four are modern phishing sources.

| Source                                       | Class    | n   | Licence       |
|----------------------------------------------|----------|-----|---------------|
| Nazario phishing corpus (2023/2024/2025)     | phishing | 30  | CC-BY 4.0     |
| phishing_pot (rf-peixoto curated pots)       | phishing | 10  | CC BY-NC 4.0  |
| Champa et al. 2024 curated dataset (Figshare)| phishing | 10  | CC-BY 4.0     |
| SpamAssassin `easy_ham/`                     | benign   | 30  | public domain |
| SpamAssassin `hard_ham/`                     | benign   | 20  | public domain |

**Total: 100 emails** (50 phishing, 50 benign).

Source URLs and download tooling:

- Nazario: https://monkey.org/~jose/phishing/ via
  `tools/download_modern_corpora.sh`.
- phishing_pot: https://github.com/rf-peixoto/phishing_pot via
  `tools/download_modern_corpora.sh` (git clone).
- Champa et al. 2024: https://figshare.com/articles/dataset/Phishing_Email_Curated_Datasets/24899943
  via `tools/download_modern_corpora.sh` (Figshare ndownloader).
- SpamAssassin ham: https://spamassassin.apache.org/old/publiccorpus/
  via `tools/download_corpora.sh` (kept as the established baseline).

For the human timing study, each participant triages the same
fixed set of twenty emails from this corpus in a session of about
two hours. Ten participants therefore give two hundred paired
manual and automated observations, which is enough for the paired
statistical tests on per-email time deltas to have meaningful
power while keeping each session short enough to limit fatigue.
The full set of one hundred emails is still used to measure the
automated detector's own precision and recall.

Sampling is **deterministic**: emails are sorted by file SHA-256
and the first n are taken from each subset. This is reproducible
without storing a random seed and survives re-downloads of the
corpus.

## Conditions

**Condition A, Manual triage.** Each participant follows
`docs/manual_checklist.md` for every email on the web form. The
form records the time spent on each email at millisecond
precision, and captures the verdict, the confidence level, and a
short reason, which it exports to CSV and JSON.

**Condition B, Automated triage.** Same emails are processed by
`triage.py`. The pipeline records its own elapsed time per email
and writes a verdict and evidence trail to the per-email JSON.

To control for fatigue and ordering effects, every participant
sees the same twenty emails, and the order of those emails is
randomised independently for each participant. The manual and
automated records are joined by the SHA-256 hash of the raw email
bytes.

## Metrics

**Primary**

- **Mean time-to-triage (MTT)**, in seconds, per condition per email.
- **Time reduction percentage**: `(MTT_manual - MTT_auto) / MTT_manual * 100`.

**Secondary**

- **Decision accuracy**: precision, recall, F1 of each condition's
  verdicts against the corpus ground-truth labels.
- **Decision agreement**: kappa between each participant's verdicts
  and the automated band, computed per participant and then averaged
  across the ten participants, with the spread reported, rather than
  pooling all participants into one figure.
- **Evidence completeness**: scored by hand against the eight-item
  rubric in `manual_checklist.md` for both conditions during the
  analysis phase. The web form records the ticked checklist items in
  its export so the manual side can be scored from that record.

## Statistical tests

The comparison is paired at the level of each email, manual
versus automated. Across ten participants triaging twenty emails
each, this gives two hundred paired observations.

- **Paired t-test** on the per-email time deltas, manual minus
  automated. Null: `MTT_auto = MTT_manual`. Alternative:
  `MTT_auto < MTT_manual`. α = 0.05.
- Because each participant contributes twenty observations, the
  two hundred are not fully independent. The analysis accounts for
  participant as a grouping factor, for example by reporting per
  participant means alongside the pooled result, so that one
  participant cannot dominate the outcome.
- **McNemar's test** on the 2x2 disagreement table of decisions,
  auto correct versus manual correct. α = 0.05.
- **Bootstrap 95% confidence interval** on the time reduction
  percentage (5,000 resamples).

If the per-email delta is not approximately normally distributed,
checked with a Shapiro-Wilk test, the **Wilcoxon signed-rank
test** is used as the non parametric fallback in place of the
paired t-test.

The significance test, t-test or Wilcoxon, runs only when there are
at least 8 pairs. Below that the analyser reports descriptive
statistics only. The main study's two hundred pairs clears this
floor easily.

The Cohen's kappa figures, the bootstrap confidence interval, the
per-participant means, and the manual-condition precision, recall and
F1 are produced by `run_experiment.py analyse --manual`. The ESS item
means are computed by hand from the exported questionnaire CSV during
the analysis phase.

## Pilot run (validation step)

Before the main experiment, a **pilot run on 20 emails** is
executed to confirm the pipeline produces stable, structured
output and to calibrate the per-email manual checklist time.
Pilot data is reported in the final dissertation but is not pooled
with the main results.

## Threats to validity

- **Analyst variation.** The manual baseline comes from ten
  participants rather than one analyst, so inter-rater agreement
  across participants can be measured and reported. The checklist
  keeps each participant's procedure consistent, and the
  stratified split of five SOC analysts and five students lets a
  sub group comparison be made between the two groups.
- **Historical corpora vs live SOC traffic.** Public corpora are
  years old; the threat landscape has moved on. Mitigation:
  reporting is framed as a methodology comparison, not an absolute
  claim about contemporary attack detection rates.
- **Timing precision.** The web form records the time for each
  email at millisecond precision, so the coarse resolution of hand
  timing is no longer a concern. The one small timing risk is the
  gap between the moment an email's content paints and the moment
  the timer starts, and the form controls for this by starting the
  timer on the paint frame. The automated pipeline records its own
  elapsed time per run.
- **Configuration sensitivity.** Rule weights and thresholds drive
  the automated verdict. Mitigation: ablation runs (auth-only,
  auth+url, full) report the same metrics so the contribution of
  each rule category is quantified.

## Outputs

- `results/experiment.csv`: the automated runner's output, one row per
  email. This file holds the automated condition only.
- `results/per_email/<message-id>.json`: full automated report.
- The manual data lives in the per-participant form exports, one CSV
  and matching JSON per participant from the web form, and in the
  converted manual CSVs produced by `tools/convert_form_to_manual.py`,
  which are what `analyse --manual` reads.

Produced during the analysis phase after the study, these do not
exist yet:

- `results/analysis.ipynb`: Jupyter notebook reproducing the tests.
- `results/figures/`: boxplot of MTT distributions, bar chart of
  precision/recall/F1, confusion matrix.

## Ethics

The study involves ten human participants in a within-subjects
design, five working SOC analysts and five MSc Cybersecurity
students. Ethical approval from the National College of Ireland
Ethics Sub-Committee is required before any session takes place.
The supporting documents are the four files in `docs/ethics/`:
the participant information sheet, the consent form, the ESS
questionnaire, and the participant glossary.

Participants are identified only by a pseudonym, and no name,
email address, IP address, or demographic data is stored in the
results. The emails used are from the public research corpora
listed above and contain no live malicious content. The
participant information sheet holds the full detail on what data
is collected, how it is stored and kept anonymous, how long it is
retained, and the lawful basis for processing, so that this
protocol and that sheet do not drift apart. See
`docs/ethics/participant_information_sheet.md`.
