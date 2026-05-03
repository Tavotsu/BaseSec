export interface DetectedFramework {
  name: string;
  version?: string;
  confidence: 'high' | 'medium' | 'low';
  source: 'package.json' | 'imports';
}

import * as fs from 'node:fs';
import * as path from 'node:path';

const FRAMEWORK_PACKAGES: Record<string, string[]> = {
  express: ['express'],
  nestjs: ['@nestjs/core', '@nestjs/common'],
  mongoose: ['mongoose'],
  typeorm: ['typeorm', '@nestjs/typeorm'],
  sequelize: ['sequelize'],
};

const FRAMEWORK_IMPORTS: Record<string, string[]> = {
  express: ["from 'express'", 'require("express")', "require('express')", 'import express'],
  nestjs: ["from '@nestjs/", "@Controller", "@Module", "@Injectable"],
  mongoose: ["from 'mongoose'", 'require("mongoose")', "require('mongoose')", "mongoose.model", "mongoose.connect"],
  typeorm: ["from 'typeorm'", "require('typeorm')", "require(\"typeorm\")", "@Entity"],
  sequelize: ["from 'sequelize'", 'require("sequelize")'],
};

export function detectFrameworks(
  framework: 'auto' | 'express' | 'nestjs',
  parsedFiles: { filePath: string; content: string }[],
  projectRoot?: string,
): string[] {
  if (framework !== 'auto') return [framework];

  const detected = new Map<string, DetectedFramework>();

  detectFromPackageJson(projectRoot ?? process.cwd(), detected);
  detectFromImports(parsedFiles, detected);

  return [...detected.keys()];
}

function detectFromPackageJson(
  projectRoot: string,
  detected: Map<string, DetectedFramework>,
): void {
  const pkgPath = path.join(projectRoot, 'package.json');
  if (!fs.existsSync(pkgPath)) return;

  try {
    const content = fs.readFileSync(pkgPath, 'utf-8');
    const pkg = JSON.parse(content);
    const allDeps = {
      ...(pkg.dependencies ?? {}),
      ...(pkg.devDependencies ?? {}),
    };

    for (const [fwk, packages] of Object.entries(FRAMEWORK_PACKAGES)) {
      for (const packageName of packages) {
        if (packageName in allDeps) {
          detected.set(fwk, {
            name: fwk,
            version: allDeps[packageName]?.replace?.(/^[\^~]>=*/, ''),
            confidence: 'high',
            source: 'package.json',
          });
          break;
        }
      }
    }
  } catch {
    // Invalid package.json, skip
  }
}

function detectFromImports(
  parsedFiles: { filePath: string; content: string }[],
  detected: Map<string, DetectedFramework>,
): void {
  for (const file of parsedFiles) {
    for (const [fwk, patterns] of Object.entries(FRAMEWORK_IMPORTS)) {
      if (detected.has(fwk) && detected.get(fwk)!.confidence === 'high') continue;
      for (const pattern of patterns) {
        if (file.content.includes(pattern)) {
          if (!detected.has(fwk)) {
            detected.set(fwk, {
              name: fwk,
              confidence: 'medium',
              source: 'imports',
            });
          }
          break;
        }
      }
    }
  }
}