export const pool = {
  query(sql: string): Promise<string[]> {
    return Promise.resolve([sql]);
  },
};
