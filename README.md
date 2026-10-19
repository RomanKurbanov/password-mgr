# Password Manager

A frontend-only, deterministic password generator built with Angular. Your master secret and each site's domain, username, counter, length, and character settings determine its password. There is no account service or backend. Saved site settings stay in this browser's local storage.

## Generate passwords

Enter your master secret, then select a saved set or choose **+ New** and enter the site settings. Passwords regenerate as you edit. **Save** keeps the settings, without saving a plaintext master secret or generated password. **Copy** copies the password and clears the master secret, as before; the app attempts to clear the clipboard after 30 seconds, subject to browser permissions.

The existing password-generation algorithm and manual master-secret entry are unchanged. Security-key unlock is optional and supplies the same master secret to that algorithm, so enrolling a key does not change existing generated passwords.

## Optional physical security key

Use a FIDO2 security key with WebAuthn PRF (`hmac-secret`) support, such as a compatible YubiKey, and a browser/OS combination that supports PRF for external keys. FIDO2 support alone does not guarantee PRF compatibility. Serve the app over HTTPS or use `http://localhost` for local development.

1. Enter the **exact existing master secret**, including spaces and capitalization. The app cannot verify it against a remote account; enrolling a different secret produces different passwords.
2. Give the key a recognizable label and start registration in the security-key controls. Complete the browser's key registration prompt.
3. Complete the separate encryption/verification step and its browser prompt. Enrollment requires two interactions so PRF evaluation works with keys that cannot return PRF output during registration. The app verifies decryption before saving the encrypted record.
4. Clear the master-secret field. To use it again, select the enrolled key and choose its unlock action, then follow the browser's PIN/touch or biometric prompt.

The browser obtains a repeatable PRF secret from the credential. HKDF-SHA-256 derives an AES-256-GCM key, which encrypts the original master secret with a fresh nonce. Only encrypted master-secret copies and public credential metadata are saved. The decrypted secret exists temporarily in memory. Copying a password clears it; key-unlocked sessions also lock automatically after five minutes. Use the lock/clear control to end a session sooner. Removing a key's saved record only removes its encrypted copy from this browser; it does not erase credentials on the physical key.

Enroll a spare physical key using the **same exact master secret**. Each key has its own encrypted copy and can unlock the same generator inputs independently.

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

```sh
npm ci
npm start
```

Use Node.js 22.x, one of the versions listed for Angular 18.2 in the [Angular compatibility table](https://angular.dev/reference/versions). Run the checks and production build with:

```sh
npm test
npm run build
```

The build output is static and can be hosted without a backend. Development enrollment on localhost creates separate credentials from production; it does not enroll a key for the production domain.
