import { describe, it, expect } from 'vitest';
import { detectFrameworks } from '../../src/framework/detector';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('detectFrameworks', () => {
  let tmpDir: string;

  function createTempProject(files: Record<string, string>): string {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secbase-fw-'));
    for (const [relativePath, content] of Object.entries(files)) {
      const fullPath = path.join(tmpDir, relativePath);
      fs.mkdirSync(path.dirname(fullPath), { recursive: true });
      fs.writeFileSync(fullPath, content);
    }
    return tmpDir;
  }

  function cleanup() {
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  it('detects express from package.json dependencies', () => {
    const dir = createTempProject({
      'package.json': JSON.stringify({ dependencies: { express: '^4.18.0' } }),
      'app.ts': "import express from 'express';",
    });
    const detected = detectFrameworks('auto', [{ filePath: 'app.ts', content: "import express from 'express';" }], dir);
    expect(detected).toContain('express');
    cleanup();
  });

  it('detects nestjs from package.json', () => {
    const dir = createTempProject({
      'package.json': JSON.stringify({ dependencies: { '@nestjs/core': '^10.0.0' } }),
      'app.ts': "import { Controller } from '@nestjs/common';",
    });
    const detected = detectFrameworks('auto', [{ filePath: 'app.ts', content: "import { Controller } from '@nestjs/common';" }], dir);
    expect(detected).toContain('nestjs');
    cleanup();
  });

  it('detects mongoose from imports', () => {
    const dir = createTempProject({
      'package.json': JSON.stringify({}),
      'model.ts': "import mongoose from 'mongoose';",
    });
    const detected = detectFrameworks('auto', [{ filePath: 'model.ts', content: "import mongoose from 'mongoose';" }], dir);
    expect(detected).toContain('mongoose');
    cleanup();
  });

  it('returns forced framework when not auto', () => {
    const detected = detectFrameworks('express', [], '/tmp');
    expect(detected).toEqual(['express']);
  });

  it('detects typeorm from package.json', () => {
    const dir = createTempProject({
      'package.json': JSON.stringify({ dependencies: { typeorm: '^0.3.0' } }),
      'entity.ts': "import { Entity } from 'typeorm';",
    });
    const detected = detectFrameworks('auto', [{ filePath: 'entity.ts', content: "import { Entity } from 'typeorm';" }], dir);
    expect(detected).toContain('typeorm');
    cleanup();
  });

  it('returns empty array when no frameworks detected', () => {
    const dir = createTempProject({
      'package.json': JSON.stringify({ dependencies: { lodash: '^4.0.0' } }),
      'util.ts': 'import _ from "lodash";',
    });
    const detected = detectFrameworks('auto', [{ filePath: 'util.ts', content: 'import _ from "lodash";' }], dir);
    expect(detected).toEqual([]);
    cleanup();
  });
});