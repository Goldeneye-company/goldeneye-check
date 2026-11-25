# Reference projects

Each folder is a small real project with a known set of problems. `tests/test_corpus.py` scans it
and compares the result with `expected.json`:

- `findings` — what the scanner must find, with the places where it may be reported;
- `confirmed` — security measures that are implemented correctly; a finding with one of the listed CWE
  on these lines is a false positive, and the scanner must list each of them among its confirmed measures;
- `accepted` — findings the project knowingly leaves open and documents; any other finding that is not
  in `findings` is reported as "not in expected";
- `baseline` — how many expected findings the current version finds; the test fails if this number drops;
- `criteria` — the bar for the release; enforced when `strict` is `true`.

`python tests/test_corpus.py` prints the score for every project.

## ghalam

A document delivery portal on PHP 8.3, Apache and PostgreSQL (learning MVP, about 260 lines of code
and configuration). Used with the author's permission. Strings and comments are translated to English;
every line keeps its original number, so the line references in `expected.json` match the manual review.
The project has no SQL injection or XSS, so pattern rules alone find nothing. Its problems are missing
measures, unsafe platform defaults and access logic.

## ghalam-fixed

The same portal after the fixes of the manual review (about 2,800 lines of code, configuration and documentation): MFA, attempt limits under a lock,
roles, encrypted documents with SHA-256 and ClamAV, retention, backups, an append-only audit log, a TLS proxy
and hardened containers. Translated the same way, line numbers kept; DEPLOY.md (deployment instructions,
no code) is left out. The scanner must find nothing here except the unpinned base images that the README
leaves to the deployment. This is where false positives of the absence checks show up first.
