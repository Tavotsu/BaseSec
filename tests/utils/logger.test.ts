import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { logger } from '../../src/utils/logger';

describe('logger', () => {
  let logSpy: any;
  let warnSpy: any;
  let errorSpy: any;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('does not log when isVerbose is false', () => {
    logger.isVerbose = false;
    logger.log('test');
    logger.warn('test');
    logger.error('test');
    expect(logSpy).not.toHaveBeenCalled();
    expect(warnSpy).not.toHaveBeenCalled();
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it('logs when isVerbose is true', () => {
    logger.isVerbose = true;
    logger.log('test1');
    logger.warn('test2');
    logger.error('test3');
    expect(logSpy).toHaveBeenCalledWith('test1');
    expect(warnSpy).toHaveBeenCalledWith('Warning:', 'test2');
    expect(errorSpy).toHaveBeenCalledWith('Error:', 'test3');
  });
});
