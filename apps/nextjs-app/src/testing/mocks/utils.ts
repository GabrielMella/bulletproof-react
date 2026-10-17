import Cookies from 'js-cookie';
import { delay } from 'msw';

import { db } from './db';

// Server-side opaque token store (mock/test only): token → userId.
// Tokens are cryptographically random and cannot be forged by constructing
// a Base64-encoded payload.
const tokenStore = new Map<string, string>();

const generateToken = (): string => {
  const bytes = new Uint8Array(32);
  if (typeof window === 'undefined') {
    // Node.js: synchronous random bytes
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    (require('crypto') as typeof import('crypto')).randomFillSync(bytes);
  } else {
    // Browser (MSW service worker)
    window.crypto.getRandomValues(bytes);
  }
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

export const hash = (str: string) => {
  let hash = 5381,
    i = str.length;

  while (i) {
    hash = (hash * 33) ^ str.charCodeAt(--i);
  }
  return String(hash >>> 0);
};

export const networkDelay = () => {
  const delayTime = process.env.TEST
    ? 200
    : Math.floor(Math.random() * 700) + 300;
  return delay(delayTime);
};

const omit = <T extends object>(obj: T, keys: string[]): T => {
  const result = {} as T;
  for (const key in obj) {
    if (!keys.includes(key)) {
      result[key] = obj[key];
    }
  }

  return result;
};

export const sanitizeUser = <O extends object>(user: O) =>
  omit<O>(user, ['password', 'iat']);

export function authenticate({
  email,
  password,
}: {
  email: string;
  password: string;
}) {
  const user = db.user.findFirst({
    where: {
      email: {
        equals: email,
      },
    },
  });

  if (user?.password === hash(password)) {
    const sanitizedUser = sanitizeUser(user);
    const token = generateToken();
    tokenStore.set(token, user.id);
    return { user: sanitizedUser, jwt: token };
  }

  const error = new Error('Invalid username or password');
  throw error;
}

export const AUTH_COOKIE = `bulletproof_react_app_token`;

export function requireAuth(cookies: Record<string, string>) {
  try {
    const token = cookies[AUTH_COOKIE] || Cookies.get(AUTH_COOKIE);
    if (!token) {
      return { error: 'Unauthorized', user: null };
    }

    const userId = tokenStore.get(token);
    if (!userId) {
      return { error: 'Unauthorized', user: null };
    }

    const user = db.user.findFirst({
      where: {
        id: {
          equals: userId,
        },
      },
    });

    if (!user) {
      return { error: 'Unauthorized', user: null };
    }

    return { user: sanitizeUser(user) };
  } catch (err: any) {
    return { error: 'Unauthorized', user: null };
  }
}

export function requireAdmin(user: any) {
  if (user.role !== 'ADMIN') {
    throw Error('Unauthorized');
  }
}
