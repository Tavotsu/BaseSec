import { describe, it, expect } from 'vitest';
import { detectTypeORMPatterns } from '../../src/framework/typeorm';
import { createSourceFile } from '../helpers';

describe('detectTypeORMPatterns', () => {
  it('detects query builders', () => {
    const code = `const qb = dataSource.createQueryBuilder();`;
    const sourceFile = createSourceFile(code);
    const result = detectTypeORMPatterns(sourceFile);
    expect(result.hasQueryBuilder).toBe(true);
  });

  it('detects repository find', () => {
    const code = `const user = userRepository.findOne({ id });`;
    const sourceFile = createSourceFile(code);
    const result = detectTypeORMPatterns(sourceFile);
    expect(result.hasRepositoryFind).toBe(true);
  });

  it('detects raw query with dynamic input (concat)', () => {
    const code = `const users = await db.query("SELECT * FROM " + userInput);`;
    const sourceFile = createSourceFile(code);
    const result = detectTypeORMPatterns(sourceFile);
    expect(result.hasRawQueryWithoutParams).toBe(true);
    expect(result.lineNumbers.length).toBeGreaterThan(0);
  });

  it('detects raw query with dynamic input (template literal)', () => {
    const code = 'const users = await db.query(`SELECT * FROM users WHERE id = ${id}`);';
    const sourceFile = createSourceFile(code);
    const result = detectTypeORMPatterns(sourceFile);
    expect(result.hasRawQueryWithoutParams).toBe(true);
  });

  it('does not flag parameterized raw query', () => {
    const code = `const users = await db.query("SELECT * FROM users WHERE id = $1", [id]);`;
    const sourceFile = createSourceFile(code);
    const result = detectTypeORMPatterns(sourceFile);
    expect(result.hasRawQueryWithoutParams).toBe(false);
  });
});
