# Contributing

Use Node.js 20 or newer and the pnpm version declared in `package.json`.

Before submitting a change, run:

```sh
pnpm check
pnpm pack --dry-run
```

Parser changes must include tests for valid markup, malformed input, lifecycle
cleanup, and active-content rejection. A parse failure must preserve readable
source text.
