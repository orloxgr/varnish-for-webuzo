# Native VCL load completion — 0.12.1

The previous loader ran a command-argument `varnishadm -t 10 vcl.load ...`.
Compilation that exceeded ten seconds could finish successfully in the manager
after the client had reported a communication failure. The transaction retained
the previous active policy, and the error incorrectly claimed the new policy
had been rejected.

Only `vcl.load` now uses native `varnishadm -p` pass mode, with exactly one
generated, quoted load command on stdin followed by EOF. Native pass mode waits
for the response to become readable; it does not impose an independent compiler
deadline. The existing timeout still bounds reading a started response, and
other administration commands retain their existing bounded command calls.
No daemon timeout, compiler, system unit or Varnish policy is changed.

Pass mode can exit zero even when VCL validation fails. The loader therefore
requires exactly one complete native frame, its declared byte length and status
200. An incomplete, malformed, extra or non-success frame is not accepted as a
successful load. The generation must also be present in `vcl.list` before apply
can activate it. If a load reply is lost, only the exact newly generated name
can recover success. If registration cannot be verified, the source is retained
and the previous policy stays active.

Original failure output can contain generated VCL and credentials. It is written
atomically to a UID-0, mode-0600 diagnostic file under the root-private application
state directory. Panel errors show a fixed category or numeric native status and
the diagnostic location, never compiler output. Confirmed absent candidates are
removed; uncertain candidates are retained for verification and later cleanup.
Cleanup also tolerates registered, unused generations whose source was already
deleted by the old timeout handler, without weakening file ownership or symlink
checks. This prevents a cleanup error after an otherwise successful apply.

## Isolated native evidence

An owned ephemeral Varnish daemon with a compiler wrapper delayed by 13 seconds
reproduced the failure. The old command exited 2 at 10.005 seconds with a CLI
communication error. A subsequent native listing showed the candidate available
and the previous boot policy still active. Pass mode returned a complete status
200 reply at 13.084 seconds. A genuinely invalid VCL returned status 106 despite
the client exiting zero, and was correctly rejected by the new loader.

The maintained regression suite exercises delayed native compilation, actual VCC
rejection, whole-frame byte lengths including UTF-8, quoted generated paths,
lost replies, exact registration, unavailable verification and root-private
diagnostics. Normal transaction and lifecycle tests cover preserved configuration
and application of a new generation without a service restart.

The larger sanitized three-enabled-site policy and exact native module from the
reported installation also compiled and loaded successfully in an isolated Lab
daemon. This establishes that the policy can load; it is not a claim that an
actual production installation has been upgraded or accepted.

This release changes the native loader only. Its VCL, native cookie module,
cookie defaults and WordPress integration are unchanged from 0.12.0. A normal
Webuzo ZIP installation and the operator's website acceptance remain separate
checks. No live reconcile, purge, service restart or production configuration
change was performed during qualification.

Native behavior reference: the Varnish project's
[`varnishadm` pass-mode implementation](https://github.com/varnishcache/varnish-cache/blob/master/bin/varnishadm/varnishadm.c).
