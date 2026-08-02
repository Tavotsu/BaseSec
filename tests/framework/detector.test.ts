import { describe, it, expect } from 'vitest';
import { detectFrameworks } from '../../src/framework/detector';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('detectFrameworks', () => {
  let tmpDir: string;

  function createTempProject(files: Record<string, string>): string {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-fw-'));
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

  it('does not falsely detect express from express-validator', () => {
    const dir = createTempProject({
      'package.json': JSON.stringify({ dependencies: { 'express-validator': '^7.0.0' } }),
      'app.ts': "import { body } from 'express-validator';",
    });
    const detected = detectFrameworks('auto', [{ filePath: 'app.ts', content: "import { body } from 'express-validator';" }], dir);
    expect(detected).not.toContain('express');
    cleanup();
  });

  it('does not falsely detect express from express-session import', () => {
    const dir = createTempProject({
      'package.json': JSON.stringify({}),
      'app.ts': "import session from 'express-session';",
    });
    const detected = detectFrameworks('auto', [{ filePath: 'app.ts', content: "import session from 'express-session';" }], dir);
    expect(detected).not.toContain('express');
    cleanup();
  });

  it('detects mongoose from @nestjs/mongoose package', () => {
    const dir = createTempProject({
      'package.json': JSON.stringify({ dependencies: { '@nestjs/mongoose': '^10.0.0' } }),
      'app.ts': "import { Module } from '@nestjs/common';",
    });
    const detected = detectFrameworks('auto', [{ filePath: 'app.ts', content: "import { Module } from '@nestjs/common';" }], dir);
    expect(detected).toContain('mongoose');
    cleanup();
  });

  it('detects frameworks from require syntax', () => {
    const dir = createTempProject({
      'package.json': JSON.stringify({}),
      'app.js': 'const express = require("express");',
    });
    const detected = detectFrameworks('auto', [{ filePath: 'app.js', content: 'const express = require("express");' }], dir);
    expect(detected).toContain('express');
    cleanup();
  });

  it('detects react from imports', () => {
    const content = "import React from 'react';";
    const detected = detectFrameworks('auto', [{ filePath: 'App.tsx', content }], '/nonexistent');
    expect(detected).toContain('react');
  });

  it('detects react from react-dom but not from react-query', () => {
    const dom = detectFrameworks('auto', [{ filePath: 'index.tsx', content: "import { render } from 'react-dom';" }], '/nonexistent');
    expect(dom).toContain('react');
    const query = detectFrameworks('auto', [{ filePath: 'hook.ts', content: "import { useQuery } from 'react-query';" }], '/nonexistent');
    expect(query).not.toContain('react');
  });

  it('detects nextjs and implies react', () => {
    const detected = detectFrameworks('auto', [{ filePath: 'page.tsx', content: "import Link from 'next/link';" }], '/nonexistent');
    expect(detected).toContain('nextjs');
    expect(detected).toContain('react');
  });

  it('does not detect nextjs from next-auth', () => {
    const detected = detectFrameworks('auto', [{ filePath: 'auth.ts', content: "import NextAuth from 'next-auth';" }], '/nonexistent');
    expect(detected).not.toContain('nextjs');
  });

  it('detects vue from imports and nuxt config', () => {
    const vue = detectFrameworks('auto', [{ filePath: 'C.ts', content: "import { defineComponent } from 'vue';" }], '/nonexistent');
    expect(vue).toContain('vue');
    const nuxt = detectFrameworks('auto', [{ filePath: 'nuxt.config.ts', content: 'export default defineNuxtConfig({});' }], '/nonexistent');
    expect(nuxt).toContain('vue');
  });

  it('detects angular from @angular imports', () => {
    const detected = detectFrameworks('auto', [{ filePath: 'app.component.ts', content: "import { Component } from '@angular/core';" }], '/nonexistent');
    expect(detected).toContain('angular');
  });

  it('detects svelte from imports', () => {
    const detected = detectFrameworks('auto', [{ filePath: 'App.svelte', content: "import { onMount } from 'svelte';" }], '/nonexistent');
    expect(detected).toContain('svelte');
  });

  it('expands implied react when nextjs is forced', () => {
    const detected = detectFrameworks('nextjs', [], '/tmp');
    expect(detected).toEqual(['nextjs', 'react']);
  });
});