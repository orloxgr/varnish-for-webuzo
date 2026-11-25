# Unified HTML document representations

UltraCache publishes one HTML body per URL and actual cookie/locale context.
The body describes its configured image main/fallback chain. HTML document
requests with AVIF, WebP or unrestricted Accept therefore reuse the same native
object when the producer has no other reason to vary on Accept.

The proxy forwards actual Accept unchanged. Genuine Accept negotiation remains
separate, including JSON/XML responses and application-defined HTML variation.
Cookie policy, private fragments, nonce ownership and HTTP compression are
independent. Projection v1 uses the opaque canonical HTML identity `html`.

The ordinary signed parent Warm covers this same HTML identity. Its signature
still binds the actual Accept of that request; authentication does not create
an image-format cache dimension. Old HTML publications are retired through the
existing application invalidation and native refresh lifecycle.
