<!--
Thanks for contributing to friTap! Please fill in the sections below.
Delete sections that don't apply.
-->

## Summary

<!-- One or two sentences: what does this PR change, and why? -->

## Motivation

<!-- Link to the issue this addresses (e.g. Closes #123) or describe the problem. -->

## Changes

<!-- Bullet list of the concrete changes, grouped by area if useful. -->

-

## Test plan

<!-- How did you verify this works? -->

- [ ] `pytest tests/unit -q` passes locally
- [ ] Tested against a real target (specify): <!-- e.g. Android 13 / com.example.app -->
- [ ] CI is green

## Checklist

- [ ] CHANGELOG.md updated (if user-visible)
- [ ] Documentation updated (`docs/`, README.md)
- [ ] If touching `requirements.txt` frida pin: also bumped `friTap/about.py` MAJOR and added a row to `compat.yml` (see [RELEASING.md](https://github.com/fkie-cad/friTap/blob/main/RELEASING.md))
- [ ] If touching `agent/`: ran `./dev/compile_agent.sh` and committed the regenerated `friTap/fritap_agent.js`

## Notes for reviewers

<!-- Anything that needs special attention, known limitations, or follow-ups planned. -->
