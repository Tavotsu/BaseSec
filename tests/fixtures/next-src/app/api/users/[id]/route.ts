import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  return NextResponse.json({ id: params.id, session });
}
