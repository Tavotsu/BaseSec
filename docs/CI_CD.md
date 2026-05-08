# CI/CD Integration

BaseSec integrates with GitHub Actions, GitLab CI, Azure DevOps, and any CI system that supports Node.js.

## GitHub Actions

### Basic Workflow

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '18'
      - run: npm install -g basesec
      - run: basesec scan ./src --strict --format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### PR Comment with Markdown

```yaml
      - run: basesec scan ./src --format markdown --output report.md
      - uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: report.md
```

### Only Critical/High in CI

```yaml
      - run: basesec scan ./src --severity high --strict
```

## GitLab CI

```yaml
security-scan:
  image: node:18
  script:
    - npm install -g basesec
    - basesec scan ./src --strict --format json --output report.json
  artifacts:
    reports:
      sast: report.json
    paths:
      - report.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

## Azure DevOps

```yaml
steps:
  - task: NodeTool@0
    inputs:
      versionSpec: '18.x'
  - script: |
      npm install -g basesec
      basesec scan ./src --format sarif --output results.sarif
  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: results.sarif
      artifactName: security-report
```

## Docker

```dockerfile
FROM node:18-alpine
RUN npm install -g basesec
WORKDIR /app
COPY . .
RUN basesec scan . --strict --severity high
```

## Pre-commit Hook

Using [Husky](https://typicode.github.io/husky/):

```bash
npm install --save-dev husky lint-staged basesec
npx husky install
```

`.husky/pre-commit`:

```bash
basesec scan ./src --severity medium --no-cache
```

## Recommended CI Configuration

```bash
# Fast scan with cache disabled (clean environment)
basesec scan ./src --no-cache --severity low --strict

# Full report for artifacts
basesec scan ./src --format sarif --output security.sarif
basesec scan ./src --format html --output report.html
```

## SARIF Upload

SARIF output is compatible with:
- GitHub Advanced Security / Code Scanning
- Azure DevOps Advanced Security
- Any SARIF 2.1.0 consumer