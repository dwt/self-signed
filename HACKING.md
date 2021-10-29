# How to execute the unit tests

> tox

This should execute the testsuite with all supported python versions.

# How to send patches

With unit tests please.
Please note that this project practices Semantic Versioning and [Dependable API Evolution](https://github.com/dwt/Dependable_API_Evolution)

# Release checklist

- Tests run with all versions of python that are configured in tox
- Increment version and tag
- upload new build with `rm -r dist/* && python -m build --sdist --wheel && twine upload dist/*`
- try upload to pypi with `twine upload --repository testpypi`
