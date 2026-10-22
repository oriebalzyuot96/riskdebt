import fs from 'node:fs';

fs.cpSync(new URL('../../rules', import.meta.url), new URL('../rules', import.meta.url), { recursive: true });
