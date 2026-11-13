import { NextResponse } from 'next/server';

async function handler() {
  return NextResponse.json({ total: 0 });
}

export { handler as GET };
