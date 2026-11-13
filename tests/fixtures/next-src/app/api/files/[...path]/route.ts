export async function GET(req: Request, { params }: { params: { path: string[] } }) {
  return Response.json(params.path);
}
