# data

This folder is empty in the repository. The corpora and indicator lists are large and carry their own licences, so they are downloaded locally and ignored by git.

- `data/raw/` receives the Nazario phishing mboxes, phishing_pot, and the SpamAssassin archives.
- `data/iocs/` receives the URLhaus indicator list used by rule URL-007.

Run these from the repository root. On Windows, use Git Bash or WSL.

```
bash tools/download_modern_corpora.sh
bash tools/download_corpora.sh
bash tools/download_iocs.sh
```
