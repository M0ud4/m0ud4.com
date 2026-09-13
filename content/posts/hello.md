---
title: "Sample post — delete me"
date: 2026-09-13
draft: true
tags: ["meta"]
summary: "A throwaway post to show how writeups render — code, callouts, headings."
---

This is a formatting sample so you can see the theme with real content. It's
marked `draft: true`, so it won't publish. Delete it once the first real post
lands.

## A code block

```c
// the kind of thing a writeup shows
char buf[64];
strcpy(buf, attacker_controlled);   // no bounds check
```

## Inline bits

A finding usually comes down to one line: `system(cmd)` reached with
`cmd` under your control. The writeup is the path from *input* to that line.

> Callouts render like this — handy for the "aha" moment.

That's it. The theme handles the rest.
