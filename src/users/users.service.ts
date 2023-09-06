import { UserModel } from "./users.model";

export async function getUsers() {
  return UserModel.getUsers();
}

export async function getUser(slug: string) {
  return UserModel.getUserBySlug(slug);
}

export async function updateUser(slug: string, values: Record<string, any>) {
  return UserModel.updateUserBySlug(slug, values);
}