# CI/CD Pipeline & PyPI Publishing Guide

This guide details the automated Continuous Integration and Continuous Deployment (CI/CD) pipelines configured for PyGenGuard to push directly to GitHub and release to PyPI.

---

## 1. CI Workflow (`.github/workflows/ci.yml`)

The continuous integration pipeline runs on every `push` and `pull_request` targeting `main` or `master`.

### Matrix Strategy
Tests across all supported Python versions:
- Python 3.9
- Python 3.10
- Python 3.11
- Python 3.12
- Python 3.13

### Stages
1. **Checkout Code**: Checks out the repository with full git history.
2. **Setup Python**: Configures the designated Python runtime from the matrix.
3. **Cache Dependencies**: Caches pip dependencies for ultra-fast CI runs.
4. **Install Dependencies**: Installs `pydantic>=2.0.0`, test runners (`pytest`, `pytest-asyncio`), and build tools (`build`, `twine`).
5. **Run Test Suite**: Executes the complete 770+ test suite via `pytest -v`.
6. **Lint & Formatting**: Validates code hygiene and import ordering.
7. **Package Build Validation**: Builds both sdist (`.tar.gz`) and wheel (`.whl`) and validates them using `twine check --strict`.

---

## 2. Publish to PyPI Workflow (`.github/workflows/publish.yml`)

The publishing workflow is triggered automatically when a Git release tag matching `v*` (e.g., `v1.0.0`) is pushed to GitHub, or manually via `workflow_dispatch`.

### Security: Trusted Publishing (OIDC)
The workflow uses PyPI's modern **Trusted Publishing (OpenID Connect / OIDC)** standard, eliminating long-lived API tokens in favor of short-lived, cryptographically verified GitHub Action tokens.

### Configuration Steps on PyPI:
1. Log in to [pypi.org](https://pypi.org) and go to **Account Settings > Publishing**.
2. Add a new **Trusted Publisher**:
   - **PyPI Project Name**: `pygenguard`
   - **Owner**: Your GitHub username or organization (e.g., `Jayasudhandesigner`)
   - **Repository Name**: `pygenguard`
   - **Workflow Name**: `publish.yml`
   - **Environment Name**: `pypi`

Alternatively, if using an API token, store it in your repository's GitHub Secrets as `PYPI_API_TOKEN`.

---

## 3. Releasing a New Version to GitHub and PyPI

### Step 1: Update Version
Update the version in `pyproject.toml` and `pygenguard/__init__.py`:
```toml
version = "1.0.0"
```

### Step 2: Commit & Push Changes
```bash
git add .
git commit -m "release: v1.0.0 with Jev System One & Dual-Layer Governance"
git push origin main
```

### Step 3: Tag the Release
```bash
git tag v1.0.0
git push origin v1.0.0
```

Once pushed, GitHub Actions will:
1. Trigger `.github/workflows/publish.yml`.
2. Build `pygenguard-1.0.0.tar.gz` and `pygenguard-1.0.0-py3-none-any.whl`.
3. Check distribution metadata with `twine check`.
4. Publish directly to [pypi.org/project/pygenguard/](https://pypi.org/project/pygenguard/).

---

## 4. Local Build & Verification

You can test the build and packaging locally at any time:

```bash
# Clean previous artifacts
Remove-Item -Recurse -Force dist, build, *.egg-info

# Build distribution
python -m build

# Check package validity
twine check dist/*

# Test local wheel install in clean environment
pip install dist/pygenguard-1.0.0-py3-none-any.whl
```
