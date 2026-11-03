/**
 * Payee handle rules (`name@dpay`, see docs/APP_DESIGN.md). Port of `Handles.kt`:
 * local part 3–30 chars of `a–z`, `0–9` and `.`; starts with a letter; no `..`; no trailing `.`.
 */
export const HANDLE_SUFFIX = '@dpay';
const PATTERN = /^[a-z][a-z0-9.]{2,29}$/;
const MAX_LENGTH = 30;

export const RESERVED_HANDLES: ReadonlySet<string> = new Set(['admin', 'support', 'dpay', 'bank', 'help', 'test']);

export function isValidLocalPart(local: string): boolean {
  return PATTERN.test(local) && !local.includes('..') && !local.endsWith('.');
}

export function localPart(handle: string): string {
  return handle.endsWith(HANDLE_SUFFIX) ? handle.slice(0, -HANDLE_SUFFIX.length) : handle;
}

export const fullHandle = (local: string): string => local + HANDLE_SUFFIX;

/** "Asha K. Rao" → "asha.k.rao", trimmed to the rules (may still need a user edit). */
export function suggestHandle(fullName: string): string {
  const words = fullName.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 0);
  let s = words.join('.').replace(/^[^a-z]+/, '').slice(0, MAX_LENGTH).replace(/\.+$/, '');
  while (s.includes('..')) s = s.replaceAll('..', '.');
  return s;
}
