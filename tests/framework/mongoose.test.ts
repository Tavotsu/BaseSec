import { describe, it, expect } from 'vitest';
import { detectMongoosePatterns } from '../../src/framework/mongoose';
import * as ts from 'typescript';

function createSourceFile(code: string, fileName = 'test.ts'): ts.SourceFile {
  return ts.createSourceFile(fileName, code, ts.ScriptTarget.Latest, true);
}

describe('detectMongoosePatterns', () => {
  it('detects lean() without select()', () => {
    const code = `const users = await User.find().lean();`;
    const sourceFile = createSourceFile(code);
    const result = detectMongoosePatterns(sourceFile, code);
    expect(result.hasLeanWithoutSelect).toBe(true);
  });

  it('does not flag lean() with select()', () => {
    const code = `const users = await User.find().select('name email').lean();`;
    const sourceFile = createSourceFile(code);
    const result = detectMongoosePatterns(sourceFile, code);
    expect(result.hasLeanWithoutSelect).toBe(false);
  });

  it('detects direct query pass with taint source', () => {
    const code = `const users = await User.find(req.body);`;
    const sourceFile = createSourceFile(code);
    const result = detectMongoosePatterns(sourceFile, code);
    expect(result.hasDirectQueryPass).toBe(true);
  });

  it('detects findById with taint source', () => {
    const code = `const user = await User.findById(req.params.id);`;
    const sourceFile = createSourceFile(code);
    const result = detectMongoosePatterns(sourceFile, code);
    expect(result.hasDirectQueryPass).toBe(true);
  });

  it('detects spread of req object in query', () => {
    const code = `const results = await Model.find({ ...req.body });`;
    const sourceFile = createSourceFile(code);
    const result = detectMongoosePatterns(sourceFile, code);
    expect(result.hasDirectQueryPass).toBe(true);
  });

  it('does not flag safe find with literal', () => {
    const code = `const users = await User.find({ status: 'active' });`;
    const sourceFile = createSourceFile(code);
    const result = detectMongoosePatterns(sourceFile, code);
    expect(result.hasDirectQueryPass).toBe(false);
  });

  it('detects $where with req', () => {
    const code = `User.$where(req.query.filter);`;
    const sourceFile = createSourceFile(code);
    const result = detectMongoosePatterns(sourceFile, code);
    expect(result.hasWhereOperator).toBe(true);
  });

  it('detects where() with process', () => {
    const code = `User.where(process.argv[2]);`;
    const sourceFile = createSourceFile(code);
    const result = detectMongoosePatterns(sourceFile, code);
    expect(result.hasWhereOperator).toBe(true);
  });

  it('detects Schema definition', () => {
    const code = `const userSchema = new Schema({ name: String });`;
    const sourceFile = createSourceFile(code);
    const result = detectMongoosePatterns(sourceFile, code);
    expect(result.schemaNames).toContain('Schema');
  });

  it('detects model() call with string name', () => {
    const code = `module.exports = model('User', userSchema);`;
    const sourceFile = createSourceFile(code);
    const result = detectMongoosePatterns(sourceFile, code);
    expect(result.schemaNames).toContain('User');
  });

  it('returns empty results for non-mongoose code', () => {
    const code = `const x = 1 + 2;`;
    const sourceFile = createSourceFile(code);
    const result = detectMongoosePatterns(sourceFile, code);
    expect(result.hasLeanWithoutSelect).toBe(false);
    expect(result.hasDirectQueryPass).toBe(false);
    expect(result.hasWhereOperator).toBe(false);
    expect(result.schemaNames).toHaveLength(0);
  });

  it('detects findOneAndUpdate with taint source', () => {
    const code = `await User.findOneAndUpdate(req.body);`;
    const sourceFile = createSourceFile(code);
    const result = detectMongoosePatterns(sourceFile, code);
    expect(result.hasDirectQueryPass).toBe(true);
  });

  it('detects findByIdAndDelete with taint source', () => {
    const code = `await User.findByIdAndDelete(req.params.id);`;
    const sourceFile = createSourceFile(code);
    const result = detectMongoosePatterns(sourceFile, code);
    expect(result.hasDirectQueryPass).toBe(true);
  });
});