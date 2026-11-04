import { NextRequest, NextResponse } from 'next/server';

const db = { query: async (sql: string): Promise<unknown[]> => [sql] };

export async function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get('q');
  const rows = await db.query(`SELECT id, name FROM users WHERE name = '${q}'`);
  return NextResponse.json(rows);
}

export async function POST(req: NextRequest) {
  const { email } = await req.json();
  return NextResponse.json({ accepted: email });
}
