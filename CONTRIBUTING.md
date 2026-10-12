# Contributing

Useful contributions:

- A wrong grade. Open an issue with the report row, the result you expected,
  and what the same request returns from curl. Remove every key and private
  URL first.
- A secret shape the scan should know, with the provider's documentation of
  the format. A shape is added only when it can be matched without a flood
  of false hits in minified JavaScript.
- A header or database check that a defender would run first and that can
  be decided from GET and HEAD alone.
- Corrections to anything in the README that turns out not to hold.

Ground rules: `surface_audit/` stays standard-library only, supports Python
3.9, and sends only GET and HEAD; every request goes through
`surface_audit.net.fetch`, which refuses any other verb, and
`tests/test_read_only.py` must stay green. Every rule change ships with a
fake-server answer that fails it and one that passes it, and the test
asserts the exact row. A secret planted in a test is built from pieces at
run time, never committed whole, so no scanner trips on this repository.
When the tool gets no answer it reports an error and exits 2; a change that
turns a missing answer into a pass will not be merged.

Run the suite with `python -m unittest discover -s tests -v`. If a change
alters what the demo prints, regenerate the transcript with
`UPDATE_DEMO_TRANSCRIPT=1 python -m unittest tests.test_demo_transcript`
and say so in the pull request. The picture in `demo/terminal.svg` is
redrawn from the transcript by the maintainer, and its test fails until
then, which is expected on such a pull request.
