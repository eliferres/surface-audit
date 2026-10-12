# Security

## Reporting a problem

Report a security problem in surface-audit through GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. Please do not open a public issue for it.

You will get a reply within two business days. A confirmed hole earns a test that reproduces it and a release that fixes it, and the changelog entry for that release names the fix.

## What counts

The tool promises to read and never write. These are security problems in it:

- It sends any request other than GET or HEAD.
- A secret value it found, or the key from the config, is written to the report, the console or the JSON output.
- The key from the config is sent to any host other than the configured `postgrest_url`.
- It reports a pass for a check it did not complete, or exits 0 when a surface did not answer.

A wrong grade that is not one of these (a header read too strictly or too loosely, a missed secret shape) is a bug; the issue template covers it.

## Supported versions

Fixes land in the latest release only.
