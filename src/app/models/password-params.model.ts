export interface PasswordParams {
  id: string;
  name: string;
  domain: string;
  username: string;
  counter: number;
  length: number;
  includeUppercase: boolean;
  includeLowercase: boolean;
  includeNumbers: boolean;
  symbols: string;
  createdAt: string;
  updatedAt: string;
}

export function createDefaultParams(): PasswordParams {
  const now = new Date().toISOString();
  return {
    id: crypto.randomUUID(),
    name: '',
    domain: '',
    username: '',
    counter: 1,
    length: 20,
    includeUppercase: true,
    includeLowercase: true,
    includeNumbers: true,
    symbols: '!@#$%^&*()_+-=',
    createdAt: now,
    updatedAt: now,
  };
}
