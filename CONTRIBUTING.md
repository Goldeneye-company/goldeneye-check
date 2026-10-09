# Contributing

## False positive or missed vulnerability

Open an issue and attach the code snippet where the rule fired by mistake or did not fire. Replace real keys and passwords with `XXXX`.

## New rule

1. Add the rule in opengrep format to one of the files in `gecheck/rules/`. In the `metadata.ge` block, set `severity` (critical, high, medium or low), `category`, `cwe`, and `title` and `fix` in three languages: `ru`, `kk`, `en`. In `fix`, describe what needs to be changed.
2. Add an example to `bench/make_fixture.py`: a vulnerable line with a `GE:Vnn` marker and, if possible, a similar safe line with a `GE:Snn` marker.
3. Run the tests and the benchmark:

```bash
python -m unittest discover -s tests
python bench/benchmark.py
```

A rule is accepted if it finds its example and does not fire on the safe lines.

## Requirements for changes

- The program only reads project files and never modifies them. The site check sends only GET requests.
- Secret values are never printed in full, either in the console or in reports.
- The user's source code is not sent anywhere.
