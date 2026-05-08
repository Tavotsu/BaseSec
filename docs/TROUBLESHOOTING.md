# Troubleshooting

## Common Issues

### `Error: Cannot find module 'typescript'`

BaseSec requires `typescript` as a peer dependency. Install it in your project:

```bash
npm install --save-dev typescript
```

### False positives on framework imports

If BaseSec flags `express-validator` or `express-session` as Express framework usage when they are not:

- This was fixed in v0.1.0 via exact import matching
- Ensure you are on the latest version
- Use `--framework auto` (default) for automatic detection

### Taint analysis fails with `receivers is not iterable`

This error appears when the taint engine encounters an unexpected AST structure. It is non-fatal — the scan continues with other files. To suppress:

```bash
basesec scan ./src --no-taint
```

### Worker threads fail in ESM environment

If you see `Cannot find module` errors with `--workers`:

- Ensure you are using the built distribution (`dist/`), not `tsx`
- Worker threads require the bundled `dist/worker.js` file

### Cache grows too large

Cache files are stored in `os.tmpdir()` and expire after 24 hours. To clear manually:

```bash
# Find cache directory (platform-dependent)
# macOS/Linux: /tmp/basesec-cache-*
# Windows: %TEMP%\basesec-cache-*
rm -rf /tmp/basesec-cache-*
```

Or disable caching:

```bash
basesec scan ./src --no-cache
```

### Out of memory on large repositories

Reduce memory usage:

```bash
# Disable taint analysis (reduces memory significantly)
basesec scan ./src --no-taint

# Use fewer worker threads
basesec scan ./src --workers 1

# Ignore large directories
basesec scan ./src -i "migrations/**" -i "generated/**"
```

### False positive: safe string concatenation

If BaseSec flags safe concatenation like `"SELECT * FROM " + tableName` where `tableName` is a hardcoded constant:

- The rule conservatively flags all concatenation in query contexts
- Review findings manually or suppress specific rules:

```bash
basesec scan ./src -r SQLI-002,SQLI-003,SQLI-004  # skip string-concat rule
```

### SARIF upload fails in GitHub Actions

Ensure the SARIF file is generated before upload:

```yaml
- run: basesec scan ./src --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

If `upload-sarif` fails with "Invalid SARIF", validate the JSON:

```bash
node -e "JSON.parse(require('fs').readFileSync('results.sarif'))"
```

## Getting Help

- Open an issue: https://github.com/tavotsu/basesec/issues
- Check [FAQ.md](FAQ.md) for more questions
- Run with `--no-banner` for cleaner CI output