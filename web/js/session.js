// Who's signed in, and what they can do. The server enforces every permission;
// the UI only uses this to hide what you can't use.
export const session = { me: null };

export function can(permission) {
  return Boolean(session.me?.permissions?.includes(permission));
}

export function canAny(...permissions) {
  return permissions.some(can);
}
