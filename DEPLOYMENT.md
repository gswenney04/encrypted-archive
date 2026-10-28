# Deployment verification

2026-10-28, America/Los_Angeles.

Live URL: https://gswenney04.github.io/encrypted-archive/

GitHub Pages publishes main /docs over HTTPS. Repository is public; content and the separate continuation bundle are ciphertext. Public metadata and generic technical files are not encrypted.

Verified on the actual live site: unlock with owner-provided password; wrong password rejected; relock/reload returns to encrypted page; perspective selection; tree and all view tabs; 390px phone viewport has no page-level horizontal overflow. No application console errors observed during initial unlock. Crypto roundtrip, tamper rejection, Web Crypto compatibility, and complete workspace restoration passed in local checks before deployment.

Not exhaustively retested during publication: every profile/deep link, search/filter combination, or browser download. Earlier layout/data tests are preserved in the encrypted continuation workspace. Do not treat publication as verification of historical claims.

Never put decrypted research or passwords in commits, issues, logs or public files. See README for authorized restoration and updates.
