# A Short Glossary for Participants

Here are plain explanations of the technical words you will meet while you review the emails. You do not need to memorise any of this. It is here so that nothing on the form is unclear. If a term still does not make sense, just ask the researcher.

**Phishing.** An email that tries to trick the reader into doing something harmful, such as giving away a password, sending money, or opening a dangerous file. It usually pretends to come from someone or some company the reader trusts.

**Triage.** Looking at an email and deciding what it is and what should happen next. In this study it means reading each email and deciding whether it is phishing or benign.

**Benign.** Safe and ordinary. An email that is not trying to trick or harm the reader.

**Email header.** The information at the top of an email that the mail system uses to deliver and label it. Most of it is hidden in normal email apps. It includes who the message is from, who it is to, the subject, the date, and the results of automatic security checks.

**From and display name.** The From line shows who the email claims to be from. The display name is the friendly part, such as "Account Security", while the actual address is the part with the @ sign. Attackers often set a trusted looking display name while the real address behind it belongs to someone else. This is called display name spoofing or brand impersonation.

**Return-Path.** The address the mail system uses for bounce messages if delivery fails. It is set behind the scenes. If the Return-Path is on a completely different domain from the From address, that can be a sign the email is not what it claims to be.

**Reply-To.** The address that a reply will go to, which can be different from the From address. Attackers sometimes set a Reply-To that sends your answer to them rather than to the real organisation.

**Authentication-Results.** A line written by the receiving mail server that records whether the email passed three automatic checks, SPF, DKIM, and DMARC, described next. It often reads as pass, fail, or none for each check.

**SPF, Sender Policy Framework.** A check that asks whether the server that sent the email is one the claimed domain has approved for sending mail. A fail means the message came from a server the domain did not authorise.

**DKIM, DomainKeys Identified Mail.** A digital signature added by the sending domain that lets the receiver confirm the message was really sent by that domain and was not changed on the way. A fail or a missing signature weakens trust in the sender.

**DMARC, Domain-based Message Authentication, Reporting and Conformance.** A policy that ties SPF and DKIM together and tells receivers what to do when an email claiming to be from a domain does not pass those checks. A DMARC fail is a strong warning sign.

**Look-alike domain and punycode.** A web or email address built to look like a real one at a glance, for example by swapping or adding a letter, or by using characters from another alphabet that look like ordinary letters. Punycode is the way browsers write those non standard characters, and seeing it in a link can be a clue that the address is disguised.

**URL shortener.** A service that turns a long web address into a short one. It hides where the link really goes, so a shortened link in a suspicious email deserves a closer look.

**Redirect link.** A link that first sends you through one address and then forwards you on to another. Attackers use this to hide the final, harmful destination behind a more trusted looking first address.
