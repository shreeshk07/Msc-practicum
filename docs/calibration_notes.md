# Calibration Notes

These are the calibration decisions made on the rule engine, with the
empirical evidence that drove each one. This is the paper trail
behind the v1 rulebook, explaining why a particular weight or
condition was set the way it is.

---

## v0 baseline

The v0 rulebook (frozen in `config/rules.yaml`) was hand-designed
from the literature and from the SOC analyst-baseline checklist
before any empirical run. Weights were picked to reflect:

* How strong the signal is as a phishing indicator (cryptographic
  auth evidence > heuristic header anomalies > content language
  patterns).
* False-positive risk on legitimate mail (negative weight on
  AUTH-004 to lower FPs on authenticated correspondence).

## Pilot run, 20 emails balanced across SpamAssassin subsets

After the corpus runner was working, v0 was applied to a 20-email
balanced pilot from SpamAssassin: 5 each from `easy_ham`,
`hard_ham`, `spam`, and `spam_2`.

**v0 results**:

| Metric    | Value |
|-----------|-------|
| Precision | 0.50  |
| Recall    | 0.70  |
| F1        | 0.58  |
| Accuracy  | 0.50  |

The 7 false positives clustered around two patterns.

### Pilot finding #1: AUTH-005 fires on pre-2015 mail

RFC 7601 (Authentication-Results) was published in August 2015.
The SpamAssassin corpora are from 2002 to 2005 and predate the
standard entirely. AUTH-005 was therefore firing on **every email**
in the pilot with a +15 contribution and was just noise on this
corpus.

**Evidence** (one of the false-positive cases):

```
Re: RH 8 no DMA for DVD drive (easy_ham)
  AUTH-005  +15  Authentication-Results header is missing entirely
  HDR-001   +15  Display-name domain differs from Return-Path domain
  HDR-002   +12  Reply-To domain differs from From domain
  Total:    +42  -> MEDIUM band (false positive)
```

**Calibration v1**: AUTH-005 is now date-conditional. The rule
suppresses itself when the email's parsed Date is before 2015-01-01.
For modern mail (post-2015) and for mail with no parseable Date the
rule fires as before. RFC 7601's publication date is the natural
cut-off; the header's absence only carries information once the
standard exists.

### Pilot finding #2: HDR-001 / HDR-002 fire on mailing-list traffic

Mailing-list servers (Mailman, Listserv, Discourse, and so on)
routinely rewrite Return-Path and Reply-To. That's just how the
lists work. The original sender stays in the From header but the
envelope is now from the listserver. A naive mismatch detector
can't tell that apart from spoofing.

Several legitimate technical-mailing-list messages in the pilot
(`Re: RH 8 no DMA...`, `If you like graphic novels/comics`, etc.)
tripped both HDR-001 and HDR-002 for this reason.

**Calibration v1**: The parser now flags `is_mailing_list=True`
when any of the standard listserver-marker headers is present
(`List-Id`, `List-Unsubscribe`, `List-Post`, `Mailing-List`). The
header-mismatch analyser short-circuits on listserver mail and
does not flag HDR-001 or HDR-002. Other rules (auth, URL, content)
still run normally, so a phishing message that happens to go
through a list will still trip on its phishing signals.

## v1 calibration summary

The v0 to v1 changes are small and targeted:

* AUTH-005 evaluator gains a date check (no rulebook change).
* Parser gains `is_mailing_list` and `list_id` fields.
* `_analyse_headers` skips HDR-001 and HDR-002 when the message
  is a list message.

No weights changed, no rules removed. Both findings were
**rule-application errors**, not **rule-design errors**. The rules
themselves are still right for their target domain (modern
phishing); the calibration just narrows when they fire.

## Open calibration questions for the full run

When the 100-email full run is executed (per the CA2 protocol),
three more calibration questions can be answered:

1. **Are URL-002 and URL-007 worth their weights when offline?**
   Both need external data. With the offline default profile they
   never fire. The IOC list adapter (next session) will let
   URL-007 fire, and the WHOIS adapter will let URL-002 fire. The
   contribution of each to F1 is then a clean ablation.
2. **Is the LOW/MEDIUM threshold of 21 right?** The band
   distribution currently clusters in MEDIUM. A sensitivity sweep
   over the threshold (with v1 calibration) will say whether the
   cut-offs need a small shift.
3. **Should CNT-001 and CNT-002 be co-required?** Either alone is
   a weak signal, together they're very strong. A small "rule
   combination bonus" could be modelled if the data supports it.

These are deferred to the full-run analysis so each question gets
its own experiment.

---

## Operational pilot, 80 emails (40 phishing + 40 benign)

After v1 calibration was applied, an 80-email balanced operational
pilot was run combining modern phishing (Nazario 2024 mbox) with
legitimate mail (SpamAssassin easy_ham + hard_ham). This is the
question that actually matters: can the engine separate **modern
phishing** from **legitimate mail**? URLhaus IOC lookup was on.

**v1.1 results** (earlier pilot, superseded by v3b, all rules, with
live URLhaus IOC list of ~78,000 indicators):

| Metric            | Value            |
|-------------------|------------------|
| Precision         | 0.846            |
| Recall            | 0.55             |
| F1                | 0.667            |
| Accuracy          | 0.725            |
| Mean MTT          | 35.45 ms / email |
| Median MTT        | 26.48 ms / email |
| Min / Max MTT     | 9.5 / 194.7 ms   |

**Confusion matrix** (with phishing-positive bands = MEDIUM, HIGH, CRITICAL):

|                 | predicted phishing | predicted benign |
|-----------------|-------------------:|-----------------:|
| actual phishing | 22 (TP)            | 18 (FN)          |
| actual benign   |  4 (FP)            | 36 (TN)          |

### Pilot finding #3: modern phishing increasingly authenticates

A chunk of Nazario 2024 phishing emails pass SPF and DKIM because
the attackers send through compromised legitimate domains or
compromised mailbox tenants. AUTH-001/002/003 don't fire on these.
The engine catches them via content (CNT-001 / CNT-002) and URL
signals (URL-001 / URL-005), but those alone often score in the
LOW to MEDIUM range. Modern phishing language ("voicemail",
"storage notification", "expired token") doesn't always trip the
phrase list either.

**Mitigation already applied in v1.1**:
* The phrase lists in `config/settings.yaml` were extended with
  modern phishing terms seen in the FN sample (voicemail, storage,
  mailbox quota, expired, kindly proceed, secure token, reactivate
  your account, etc.).
* Content phrase matching now searches **subject + body** rather
  than body only. That alone moved several FNs into MEDIUM.

**Open work for the full implementation**:
* HTML-attachment-as-payload detection (modern phishing
  increasingly uses HTML attachments to evade URL filters).
* IPFS gateway and cloud-storage redirector hostnames as a soft
  URL rule.
* Compromised-tenant heuristics: legitimate auth + display-name
  brand spoof + content urgency may merit a small combination
  bonus.

### Bottom line on timing

The MTT figure is the headline result. On the frozen v3b run the
engine takes a median of 11.92 ms and a mean of 15.27 ms per email.
Against a typical manual SOC baseline of 30 to 180 seconds per
user-reported email that is a speed-up of three to four orders of
magnitude. On the clean modern sample the engine reaches precision
0.978 and recall 0.800, and the recall gap is structural and
documented later in this file.
The accuracy gap against ML-based detectors (Jadhav and Chandre 2025
report >95%) is the expected trade-off for an ML-free explainable
engine, and is consistent with the research question's stated emphasis
on triage time at comparable accuracy rather than maximal accuracy.

## Known limitations

### Non-Latin subjects

CNT-001, CNT-002, CNT-006, and CNT-007 all match against English
keywords or English regex patterns. A phishing email whose subject
is written in a non-Latin script (Arabic, CJK, Cyrillic, etc.) will
not trip any of those rules. In the v1.2 pilot, one of the 11
false negatives was such a case: a Nazario 2024 message from
`elitehealthgroupllc.com` with an Arabic-script subject. The email
fired only HDR-004 and CNT-004 and stayed in LOW.

This is treated as a known scope limitation rather than a defect.
A multilingual detector would need either:

* per-language keyword and regex sets (manageable but each language
  needs separate calibration), or
* a language-agnostic signal such as Unicode-script detection on
  the subject (cheap to add but very low precision: legitimate
  multilingual mail also uses non-Latin scripts).

Both are deferred to future work; the project scope is
English-language SOC operations. One Arabic case in 40 in the
operational pilot translates to a 2.5 % per-corpus blind spot
attributable to language, which is reported alongside the recall
figure rather than treated as a tunable parameter.

### Header-stripped corpora (Champa et al. 2024)

PhishTriage is a header-based rule engine. AUTH-001/002/003/005
score on the `Authentication-Results` header, HDR-001/002/004
score on Return-Path / Reply-To / X-Mailer, and HDR-005 scores
on the `Received` chain. Roughly one-third of the rule weight in
v1.3 comes from header signals.

The Champa et al. 2024 "Phishing Email Curated Datasets" CSVs on
Figshare (article 24899943) carry only `subject`, `body`, and a
numeric `label` per row. Every original RFC-5322 header is
discarded by the upstream curation step. When `iter_champa`
reconstructs an in-memory message for each row, it can only put
back fields that exist in the CSV: From/To/Date/Subject and a
generic Content-Type. There is no Authentication-Results header
and no X-Mailer.

The downstream effect on the v1.3 rule set is that two rules fire
on **every** Champa row, phishing and legitimate alike:

* AUTH-005 (+15): "Authentication-Results header is missing entirely"
* HDR-004 (+10): "Suspicious or generic mail user agent (or absent)"

Net contribution +25 puts it in the MEDIUM band (threshold 21). Phishing rows
that also trip URL/content rules land deeper into MEDIUM/HIGH;
legitimate rows stay at exactly +25 and become structural false
positives.

Observed in the 100-email mixed pilot (`results/operational_v3_modern.csv`):
**all 20 / 20 Champa legitimate rows misclassified at exactly score 25**
with identical `{AUTH-005, HDR-004}` fired-rule sets, pulling
precision down to 0.6769.

Conclusion: Champa is structurally unsuitable as a precision-test
ham source for this engine. It is not a rule-design problem (the
SpamAssassin/Nazario header-bearing pilot scored 0.90 precision on
the same rules). It is a dataset-format mismatch between
header-stripped CSV corpora and a header-based detector.

`iter_champa` is kept in the codebase for supplementary use. A
text-only scorer (e.g. body-content-only baseline, language-model
classifier ablation) could still consume the same Champa rows.
The primary operational metric is reported on Champa-excluded
corpora: SpamAssassin ham, Nazario phishing, and phishing_pot
phishing.

---

## v3b: redirector unwrapping and the "Email" regex fix

Two targeted changes were made after the v3 clean pilot. Neither is
a weight change.

* **CNT-007 defect fix.** The system-alert lure pattern's first group
  was `\b(mailbox|storage|mail|server|account)\b ...`. The `\bmail\b`
  alternative cannot match inside the word "Email": there is no word
  boundary between the leading "E" and "mail", so a subject such as
  "Email Service Alert" silently failed to fire CNT-007. The group is
  now `\b(mailbox|storage|e?mails?|server|account)\b`, which matches
  mail / email / emails. This is a defect fix, not a recalibration.
* **URL-008 (new rule, +20).** First-hop redirector unwrapping. When a
  URL's host is a known link-wrapper, click-tracker, or open-redirect
  (configurable list: acemlnc.com, doubleclick.net,
  safelinks.protection.outlook.com), or it carries a redirect
  parameter (`url=`, `redirectUrl=`, `target=`, `u=`), or a parameter
  value is a base64 blob that decodes to an http(s) URL, the engine
  extracts the embedded destination and re-checks **that** host for an
  IOC / IP-literal / punycode / suspicious-TLD signal. It fires only
  when the unwrapped destination differs from the first hop **and**
  independently trips one of those signals, so a wrapper around a
  clean destination (Safe Links pointing at microsoft.com) does not
  fire. This surfaces a signal the per-URL rules previously discarded
  by only ever seeing the wrapper host; it is not weight tuning.

**v3b results** (same clean 80-email modern pilot: SpamAssassin
easy_ham 15 + hard_ham 10, phishing_pot 25, Nazario 2024 15 +
Nazario 2025 15; IOC lists off, offline profile):

| Metric    | v3 clean | v3b   |
|-----------|---------:|------:|
| Precision | 0.977    | 0.978 |
| Recall    | 0.782    | 0.800 |
| F1        | 0.869    | 0.880 |
| Accuracy  | 0.838    | 0.850 |

Confusion (v3b): TP 44, FP 1, FN 11, TN 24.

The entire recall gain is a single email: a Nazario 2025 message with
the subject "Important: Email Service Alert" moved from LOW to MEDIUM
(score 14 to 36) once the CNT-007 `e?mails?` fix let the lure pattern match
"Email". **URL-008 fired zero times in this run.** That is expected
and reported honestly: with `data/iocs/` empty (the offline default
profile) the IOC-on-destination branch is dormant, and none of the
residual false negatives wrap a destination whose host is an IP
literal, punycode label, or suspicious TLD. URL-008 is implemented and
unit-tested against an IP-literal destination
(`test_url_008_unwraps_redirecturl_param`); it contributes on a
profile with a live IOC list, or against campaigns that hide an
IP/punycode destination behind a reputable first hop. Recall did not
reach the 0.85 target. That is reported as a finding, not chased with
larger weights.

## Structural recall limits of rule-based triage

After the v3b fixes, recall on the clean modern pilot plateaus at 0.80
with 11 false negatives remaining. These are not tuning defects. They
fall into three families that a header / URL / text rule engine cannot
close without capabilities this project deliberately excludes, in
favour of a stateless, explainable, auditable rulebook.

### Authenticated compromised-sender phishing

These are phishing messages sent from genuinely compromised but
legitimate mailboxes or tenants. SPF, DKIM, and DMARC all pass and
align, so AUTH-001/002/003 stay silent and AUTH-004 even subtracts 10.
The From-domain is a real, often long-established domain, so
HDR-001/002 do not fire and the domain-age and IOC URL rules see
nothing unusual. AUTH-006 and CNT-006/007 were added precisely to claw
back the subset of these that carry a credential-pretext subject, and
they recover the cases with a recognisable lure. But a compromised
sender whose subject and body are bland (a short "please review the
attached document", or a benign-looking reply in an existing thread)
leaves no header, URL, or language signal for any rule to score.
Catching these reliably needs sender-behaviour baselining (does this
account normally email this recipient, at this hour, with this writing
style) or a content model trained on intent rather than keywords.
Both require per-mailbox state or a trained classifier, which is the
ML route the project scopes out in favour of a stateless rulebook.

### Attachment-only payload

A second family delivers the whole attack inside an attachment: an
HTML "view document" page that renders a credential form locally, a
macro-bearing Office file, or a PDF whose embedded link leads to a
harvester, with a body that is empty or carries only a neutral
instruction to open the file. CNT-003 fires on executable and
macro-bearing MIME types and on risky extensions, but modern lures
increasingly attach `.html` / `.htm` or `.pdf` files that are not on
any executable list and are indistinguishable, by MIME type and
filename alone, from legitimate attachments. The phishing content
lives in the rendered attachment, which a static engine never opens.
Deciding that an `.html` attachment renders a fake Microsoft login, or
that a PDF's link reaches a credential page, requires detonating or
rendering the file in a sandbox. That is deliberately out of scope:
PhishTriage is a static, offline, millisecond-per-email triage stage,
and attachment detonation belongs to a downstream sandbox tier
(Cuckoo, a commercial detonation service, or the mail gateway), not to
the rule engine.

### Non-English subjects

The content rules (CNT-001/002/006/007) and the subject-brand checks
match English keywords and English-oriented regex, so a phishing
message written in Arabic, CJK, or Cyrillic trips none of them, and
even Latin-script non-English phishing (French, German, Spanish) is
only partially covered by the brand list. This is documented in fuller
form under "Non-Latin subjects" above; it is restated here as a
structural recall limit because it cannot be closed by adding more
English rules. Closing it needs either per-language phrase and regex
sets, each requiring its own calibration and false-positive control,
or a language-agnostic model. Unicode-script detection on the subject
is cheap but too imprecise to weight (legitimate multilingual mail
also uses non-Latin scripts) and a multilingual content classifier is
exactly the ML route the explainability remit rules out. The project
scope is English-language SOC operations, and non-English phishing is
reported as a measured blind spot rather than papered over.

Together these three families account for the bulk of the residual
false negatives. None is closable by adjusting a weight or adding
another English phrase: the first needs sender-behaviour state or
intent modelling, the second needs attachment detonation, the third
needs multilingual models. All three are downstream-tier or ML
capabilities the project scopes out by design. The engine's value
proposition is sub-30-millisecond, fully explained triage at high
precision; the honest recall of 0.80 against modern phishing is the
measured cost of staying inside that design, and is reported as such.
