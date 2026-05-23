export interface DetectedFramework {
  name: string;
  version?: string;
  confidence: 'high' | 'medium' | 'low';
  source: 'package.json' | 'imports';
}

import * as fs from 'node:fs';
import * as path from 'node:path';
import { logger } from '../utils/logger';

const FRAMEWORK_PACKAGES: Record<string, string[]> = {
  express: ['express'],
  nestjs: ['@nestjs/core', '@nestjs/common'],
  mongoose: ['mongoose', '@nestjs/mongoose'],
  typeorm: ['typeorm', '@nestjs/typeorm'],
  sequelize: ['sequelize'],
  fastify: ['fastify'],
  koa: ['koa'],
  prisma: ['@prisma/client'],
};

const FRAMEWORK_IMPORTS: Record<string, string[]> = {
  express: ["from 'express'", "from \"express\"", 'require("express")', "require('express')", 'import express from', 'import * as express from'],
  nestjs: ["from '@nestjs/", "@Controller", "@Module", "@Injectable"],
  mongoose: ["from 'mongoose'", "from \"mongoose\"", 'require("mongoose")', "require('mongoose')", 'mongoose.model', 'mongoose.connect'],
  typeorm: ["from 'typeorm'", "from \"typeorm\"", "require('typeorm')", "require(\"typeorm\")", '@Entity'],
  sequelize: ["from 'sequelize'", "from \"sequelize\"", 'require("sequelize")', "require('sequelize')"],
  fastify: ["from 'fastify'", "from \"fastify\"", "require('fastify')", "require(\"fastify\")", "from '@fastify/", "fastify-plugin"],
  koa: ["from 'koa'", "from \"koa\"", "require('koa')", "require(\"koa\")", "from '@koa/", "koa-router", "@koa/router", "koa-bodyparser"],
  prisma: ["from '@prisma/client'", "from \"@prisma/client\"", "require('@prisma/client')", "require(\"@prisma/client\")", ".prisma/client", "PrismaClient"],
};

function isExactImportMatch(content: string, pattern: string): boolean {
  if (pattern.startsWith('from ') || pattern.startsWith('import ')) {
    const idx = content.indexOf(pattern);
    if (idx === -1) return false;
    const afterPattern = idx + pattern.length;
    if (afterPattern < content.length) {
      const nextChar = content[afterPattern];
      if (nextChar === '/' || nextChar === '-' || nextChar === '_') return false;
    }
    return true;
  }
  return content.includes(pattern);
}

export function detectFrameworks(
  framework: 'auto' | 'express' | 'nestjs' | 'mongoose' | 'typeorm' | 'fastify' | 'koa' | 'prisma',
  parsedFiles: { filePath: string; content: string }[],
  projectRoot?: string,
): string[] {
  if (framework !== 'auto') return [framework];

  const detected = new Map<string, DetectedFramework>();

  detectFromPackageJson(projectRoot ?? process.cwd(), detected);
  detectFromImports(parsedFiles, detected);

  return [...detected.keys()];
}

function detectFromImports(
  parsedFiles: { filePath: string; content: string }[],
  detected: Map<string, DetectedFramework>,
): void {
  for (const file of parsedFiles) {
    for (const [fwk, patterns] of Object.entries(FRAMEWORK_IMPORTS)) {
      if (detected.has(fwk) && detected.get(fwk)!.confidence === 'high') continue;
      for (const pattern of patterns) {
        if (isExactImportMatch(file.content, pattern)) {
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
            version: allDeps[packageName]?.replace?.(/^[\^~>=]+/, ''),
            confidence: 'high',
            source: 'package.json',
          });
          break;
        }
      }
    }
  } catch (e) {
    logger.warn(`Failed to read/parse package.json in ${projectRoot}`, e);
  }
}