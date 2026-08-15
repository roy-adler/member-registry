# Registration sanity checks and admin review

Date: 2026-08-15

## Problem

Public registration is flooded with bots that submit nonsense names (`znuizmwpmg`, `trlsqqgroy`), nonsense addresses (`omexixgdfz`, `jttunroumi`), and fake numbers (`+1-969-321-2467`). Name and email are required today; address and phone are optional and unchecked.

Members are mostly in Switzerland but can be international. Address and phone are important and must become required. Checks should stay lenient for real people.

## Goal

1. Reject only obvious junk at submit time.
2. Require name, email, address, and phone.
3. Auto-approve registrations that look real (and whose Swiss address, if it looks Swiss, is found in the official directory).
4. After email confirmation, put anything fishy or unverifiable on an admin **Needs review** list. Those people are not in the main member list and not in CSV export until an admin confirms.

## Non-goals

- CAPTCHA, honeypot, or rate limiting
- Requiring a Swiss-shaped address
- Looking up foreign addresses
- Blocking registration when geo.admin.ch is down
- Telling the registrant they are in review

## Member states

A member is in exactly one admin list:

| List | Email confirmed | Approved | In CSV export |
| --- | --- | --- | --- |
| Pending email | no | — | no |
| Needs review | yes | no | no |
| Members | yes | yes | yes |

**Approved** means auto-approved at registration, confirmed by an admin, imported via CSV, or already present before this change.

Flow:

1. Submit form → hard checks. Fail → flash error, nothing stored.
2. Pass → save member. If any review flags, `approved=false`; otherwise `approved=true`.
3. Email confirmation works as today. After confirm, flagged members appear under **Needs review**, not **Members**.
4. Admin **Confirm** sets `approved=true` and clears flags. **Delete** removes the member. **Edit** can fix fields first; saving an edit does not auto-approve.

## Data model

Add to `Member`:

- `approved` — boolean, default `false` for new public registrations (then set true when there are no flags). Existing rows and CSV imports: `true`.
- `review_reasons` — string, default `''`. Comma-separated tokens from: `name`, `phone`, `address_lookup`. Empty when approved.

Startup must add these columns on existing SQLite databases (`create_all` does not migrate). A small `ensure_schema()` helper runs `ALTER TABLE` if the columns are missing, then marks all current rows `approved=true`.

## Validation

Shared functions in a dedicated module (e.g. `validation.py`), called from `POST /register` only. Admin edit and CSV import do not run these checks.

Default phone region is `CH` so numbers like `079 123 45 67` parse as Swiss.

### Name

Unicode letters, spaces, hyphens, apostrophes, and dots are allowed (`Jean-Luc`, `Müller`, `O'Neill`).

**Reject** if empty, has no letters, or looks like a random dump: after stripping allowed punctuation, there is no space, length is at least 8, and either the vowel ratio (`aeiouy` plus `äöüàéèê`) is below 0.25 or there are 5 or more consonants in a row. This rejects `znuizmwpmg` and `trlsqqgroy` and keeps `Christopher` (single word, but pronounceable — that is a review flag, not a reject).

**Flag `name`** if it passes the reject rules but is a single word.

**OK** otherwise (two or more words of letters).

### Address

Must not be gibberish. It does **not** have to look Swiss. `Bahnhofstrasse 10, 8001 Zürich` and `10 Downing Street, London` are both OK. `omexixgdfz` is not.

**Reject** if empty, has no digit, has no letter, or is a single nonsense token (no space, no number).

**OK** if it has letters, a digit, and at least one space.

**Swiss lookup** (after local checks pass): treat the address as Swiss-looking only if it contains a 4-digit token in 1000–9658 that is **not** the first number in the string (so `Bahnhofstrasse 10, 8001 Zürich` matches and `1234 Main Street` does not). Then GET `https://api3.geo.admin.ch/rest/services/api/SearchServer` with `searchText=<address>`, `type=locations`, a clear User-Agent (`member-registry`), and a 3 second timeout. One request per registration.

- At least one result → address verified, no flag.
- Zero results, HTTP error, or timeout → still save the member, flag `address_lookup`.
- No Swiss-range postcode → skip lookup, no address flag.

### Phone

Use the `phonenumbers` library.

**Reject** if empty or not a possible number (`is_possible_number` is false). Catches letters and truncated junk.

**Flag `phone`** if possible but not valid (`is_valid_number` is false). Catches unassigned area codes such as `+1-969-321-2467`.

**OK** if valid (Swiss or other countries).

### Auto-approve vs review

- No flags → `approved=true`.
- Any flag → `approved=false` and store the tokens in `review_reasons`.

The confirmation-sent page does not mention review.

## Admin UI

Keep the current dashboard layout. Add a **Needs review** section (email confirmed, `approved=false`).

Each row shows name, email, address, phone, and human-readable reasons:

- `name` → Name looks unusual
- `phone` → Phone number may not be valid
- `address_lookup` → Address not found in Swiss directory

Actions: **Confirm** (`POST`) and **Delete** (existing). Edit remains available.

**Members** lists only `confirmed and approved`. **Pending email** stays `confirmed=false`.

CSV export uses the same filter as **Members**. CSV import creates `confirmed=true`, `approved=true`, empty `review_reasons`.

## Public form

Name, email, address, and phone are required in HTML and on the server. Flash messages match today’s style, e.g. “Please enter a valid name.” Placeholders stay generic (street with a number; phone example `+41 79 123 45 67`).

## Error handling

- Validation errors: flash and redirect to `/`, no DB write.
- Lookup failure: log a warning, flag `address_lookup`, continue.
- Do not call the lookup when local address checks already rejected.

## Tests

- Reject bot names `znuizmwpmg`, `trlsqqgroy`.
- Reject bot addresses `omexixgdfz`, `jttunroumi`.
- Reject a non-number phone; flag `+1-969-321-2467` as `phone` (possible, not valid).
- Accept a normal Swiss name, address with postcode, and valid `+41` number; mock a successful lookup → auto-approve.
- Accept a foreign address with no Swiss postcode without calling lookup and without an address flag.
- Swiss-looking address + mocked empty lookup → saved with `address_lookup`, `approved=false`.
- Lookup timeout/error → same as empty lookup, registration succeeds.
- After email confirm, unapproved members are absent from `/admin` member table and `/admin/export`, present in Needs review.
- Admin Confirm moves them to Members and into export.
- Existing DB rows are treated as approved after schema ensure.
- CSV import marks members approved.

## Dependencies

- `phonenumbers` for phone parsing and validity.
- `urllib` or `urllib.request` from the stdlib for the geo.admin.ch GET (no extra HTTP client required).
