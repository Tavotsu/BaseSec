'use server';

export async function saveName(formData: FormData) {
  return String(formData.get('name'));
}
