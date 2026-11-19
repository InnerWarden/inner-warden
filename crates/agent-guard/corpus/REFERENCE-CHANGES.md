# Why the release safety suite's reference changed

`reference.tsv` is what the release safety suite holds the guard to. A pull
request that changes it adds a line here, newest last: the date, the cases whose
verdict moved (before and after), and why the new verdict is the right one. CI
refuses a reference change without a new line here.

- 2026-11-19: first reference. proof 246/246 caught, 243/246 stopped for an
  agent, 0/160 false positives; attack-2026-11 325/325 caught, 275/325 stopped,
  0/117 false positives; real 4/5 caught, 25/31 false positives (the lines the
  guard refused during the guard's own development, the backlog this suite
  measures).
