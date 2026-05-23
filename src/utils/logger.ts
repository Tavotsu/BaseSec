export const logger = {
  isVerbose: false,

  log(...args: any[]) {
    if (this.isVerbose) {
      console.log(...args);
    }
  },

  warn(...args: any[]) {
    if (this.isVerbose) {
      console.warn('Warning:', ...args);
    }
  },

  error(...args: any[]) {
    if (this.isVerbose) {
      console.error('Error:', ...args);
    }
  }
};
