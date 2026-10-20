# Password Manager

A frontend-only, deterministic password generator built with Angular. Your master secret and each site's domain, username, counter, length, and character settings determine its password. There is no account service or backend. Saved site settings stay in this browser's local storage.

## Generate passwords

Enter your master secret, then select a saved set or choose **+ New** and enter the site settings. Passwords regenerate as you edit. **Save** keeps the settings, without saving a plaintext master secret or generated password. **Copy** copies the password and then clears both the master secret and generated password from the app. A failed copy leaves them available for retry. The app does not automatically overwrite the clipboard; clear it yourself when finished, and consider your device’s clipboard history or sync settings.

Use a long, independently generated master secret or a passphrase made from randomly selected words.

Both manual and key-unlocked sessions lock when leaving the page. A non-empty master password clears two minutes after its last edit or security-key unlock. Editing the master-password field restarts that timer; other typing, clicking, and account changes do not. Clearing the field cancels the timer. On returning to a suspended tab, the app checks elapsed time before allowing more use.

After unlocking with a physical key, click **Copy password** to copy and clear both secrets. Safari requires clipboard writes to start during a fresh user action; key verification and password generation can outlast or consume that action. The app starts a promised clipboard write before awaiting generation when the browser supports it. If copying is denied, it keeps the current secrets available and asks for a new click rather than repeating a denied write in the background. Other transient write failures get up to five attempts. Leaving the page or reaching the session timeout still locks the app after a failed copy.

The existing password-generation algorithm and manual master-secret entry are unchanged. Security-key unlock is optional and supplies the same master secret to that algorithm, so enrolling a key does not change existing generated passwords.

## Optional physical security key

Use a FIDO2 security key with WebAuthn PRF (`hmac-secret`) support, such as a compatible YubiKey, and a browser/OS combination that supports PRF for external keys. FIDO2 support alone does not guarantee PRF compatibility. Serve the app over HTTPS or use `http://localhost` for local development.

1. Enter the **exact existing master secret**, including spaces and capitalization. The app cannot verify it against a remote account; enrolling a different secret produces different passwords.
2. Give the key a recognizable label and click **Register key**. Complete the browser's key registration prompt. This creates the credential; it does not yet save an encrypted master-secret copy.
3. Click **Finish setup**, keeping the same physical key available, and complete the next browser prompt. This separate click starts PRF evaluation and encryption. The app verifies decryption before saving the encrypted record. If this step fails, retry **Finish setup** to reuse the pending credential rather than registering another one.
4. Clear the master-secret field. To use it again, select the enrolled key and choose its unlock action, then follow the browser's PIN/touch or biometric prompt.

Between registration and **Finish setup**, the pending credential metadata stays only in this page's memory. Cancelling setup, editing or clearing the master secret, or leaving the page discards that pending state. Start registration again if you discard it. Cancelling does not remove a credential that was already created on the physical key.

The browser obtains a repeatable PRF secret from the credential. HKDF-SHA-256 derives an AES-256-GCM key, which encrypts the original master secret with a fresh nonce. Only encrypted master-secret copies and public credential metadata are saved. The decrypted secret exists temporarily in memory. Copying a password clears both secrets from the app; the master-password field also clears two minutes after its last edit or unlock. Use the lock/clear control to end a session sooner. Removing a key's saved record only removes its encrypted copy from this browser; it does not erase credentials on the physical key.

Enroll a spare physical key using the **same exact master secret**. Each key has its own encrypted copy and can unlock the same generator inputs independently.

## If a key prompt fails

The app identifies whether the failure happened during registration, finishing setup, or unlocking. A browser `NotAllowedError` can mean cancellation, a timeout, an unavailable credential, or a browser restriction; it does not by itself establish that PRF is unsupported. The [WebAuthn request exception documentation](https://www.w3.org/TR/webauthn-3/#sctn-getAssertion) describes this error as covering multiple causes.

If registration completed and **Finish setup** fails, keep the registered key connected, select that external key in the browser prompt, and retry **Finish setup**. No encrypted record is saved until this step succeeds. The two separate app clicks give each browser request a fresh user action, which addresses a possible cause of failures in Safari's [user-gesture handling](https://developers.yubico.com/WebAuthn/Concepts/Handle_WebKit_User_Gesture.html). The error alone cannot confirm that this caused a previous failure.

A message saying the key/browser did not provide PRF means that operation did not return the required extension output. Check the exact key model and firmware, browser, operating system, and USB/NFC connection against [Yubico's PRF guidance](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html). Registration support and PRF evaluation support are separate requirements. Continue using manual master-secret entry if the combination is incompatible.

For a site-access or hostname error, use HTTPS or localhost and the same hostname used for registration. Do not move between production, localhost, an IP address, or a different domain partway through setup.

For temporary diagnostics, build and deploy the updated app, then use **Option–Command–R** in Safari to [reload from origin without cached resources](https://developer.apple.com/documentation/safari-technology-preview-release-notes/stp-release-27). Keep the site's saved data. Under **Security keys & backup**, confirm **Build key-debug-20261019-1**, select **Enable temporary diagnostics**, reproduce the failed step, and choose **Copy diagnostics**. If the marker is missing or the old generic error remains, confirm that the tab loaded the updated build before diagnosing the key.

Diagnostics are off by default. They retain at most 50 requests with 16 events each, in memory only: browser user agent, origin (no path or query), secure context and user activation, request stages and timing, PRF presence/length, and error names/codes. They exclude secrets, credential IDs, and PRF bytes, and never write to storage, the network, or the console. Copying is an explicit action. Turn diagnostics off or reload to clear the in-memory report.

## Back up and recover

Export a backup after saving settings or enrolling keys, and keep it somewhere safe. The JSON includes **plaintext site settings** (including domains and usernames), encrypted master-secret copies, and public credential metadata. It does not include a plaintext master secret, generated passwords, or the key's PRF secret. Treat the file as private because the site settings reveal accounts.

Import merges the backup with existing browser data. Existing site-setting IDs and existing credential/domain pairs win, so importing does not overwrite current entries. Backups support up to 10,000 site settings and 32 security-key records, within a 1 MiB UTF-8 file limit. Invalid or oversized backups are rejected without changing stored data.

For another browser or computer, open the app at the **same origin**, import the backup, and use the same physical key. Credentials are scoped to their relying-party domain; records from a different domain cannot be unlocked there. Keep your deployment domain stable. A physical key alone does not contain the saved encrypted master-secret copy: clearing browser data without a backup can lose that copy.

If you lose a key, use an enrolled spare with its backup record, or enter the original master secret manually. The master secret plus the original site settings is sufficient to regenerate passwords. There is no server-side recovery. Removing local records cannot revoke a lost key's access to old backup files; changing the underlying master secret also changes generated passwords and requires updating them on the relevant websites.

If saved security-key data is reported as invalid, manual master-secret entry remains available. Key management and import are disabled in that profile to preserve the damaged data. You can restore a valid backup in a fresh browser profile at the same domain without deleting the original data.

## Security boundaries and compatibility

This feature protects the saved master secret at rest. Someone who already knows the master secret can still generate passwords manually. A compromised browser, malicious extension, or modified app can read secrets while the app is unlocked. JavaScript cannot guarantee that copies of secrets have been erased from browser memory. Only use a trusted app deployment and device.

WebAuthn and PRF support depends on the key firmware, connection type, browser, and operating system. Test enrollment, lock/unlock, backup restore, and a spare key on your actual devices before relying on them. Automated tests use simulated WebAuthn behavior; they do not establish compatibility with a physical key.

References: [Yubico's PRF implementation guide](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html) and the [W3C WebAuthn PRF extension specification](https://www.w3.org/TR/webauthn-3/#prf-extension).

## Development

Use Node.js 22.22.3 or newer within the 22.x release line. The `.nvmrc` file pins Node.js 22.23.3 for local development and CI. With nvm installed, select it before installing dependencies:

```sh
nvm install
nvm use
npm ci
npm start
```

Angular 22.2 uses TypeScript 6.0.x; see the [Angular compatibility table](https://angular.dev/reference/versions) for supported Node.js, TypeScript, and RxJS versions. Run the checks and production build with:

```sh
npm test
npm run build
```

The build output is static and can be hosted without a backend. Development enrollment on localhost creates separate credentials from production; it does not enroll a key for the production domain.

## Saved-settings errors

Unreadable or malformed saved site settings produce a visible error. Invalid records are never silently dropped. Saving, deleting, and importing recheck storage and stop if it is damaged or unreadable. The app updates the saved list only after a successful write. Manual generation remains available.

Use **Download original settings for recovery** to retain the exact stored text before attempting recovery. This recovery file can contain readable account details and is not an importable backup. Keep the original browser data; restore a valid backup in a fresh profile at the same origin, or repair a copy of the recovery data before any manual restoration.

## Production hosting hardening

The app's HTML CSP allows scripts only from its own origin, without inline scripts. Angular currently needs inline styles, so the style policy retains that permission. The app refuses to initialize inside a frame as a fallback. This JavaScript check is weaker than browser-enforced response headers.

For full framing protection, use a host or proxy that serves the following HTTP response headers on the HTML document:

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none';
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
```

`frame-ancestors` must be a response header; adding it to an HTML meta tag has no effect. GitHub Pages does not offer repository-configurable custom response headers; use a header-capable host or proxy for these headers. Verify them on the deployed HTML response and test that an iframe is refused.

Use a dedicated HTTPS origin for this app. Other applications under the same hostname share its local-storage boundary even when their URL paths differ. A custom hostname can isolate storage, but response headers still need hosting support.

Before changing domains:

1. Export a valid backup and confirm that you know the exact master secret, or can unlock it at the current domain.
2. Configure the dedicated hostname, HTTPS, response headers, and the production base path (the current workflow builds for `/password-mgr/`; a root deployment needs `/`).
3. Import settings at the new origin and manually enter the original master secret. Existing key credentials are domain scoped and may not unlock there; enroll the keys again at the new domain.
4. Verify identical generated passwords, key unlock, and a new backup before retiring the old deployment. Local storage is not transferred automatically.

No domain or hosting migration is performed by the application changes alone.
The repository is now hardware signed