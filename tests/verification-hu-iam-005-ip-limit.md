# HU-IAM-005 direct-peer login limit verification

`mvn -B -q verify` passed in a Java 21 Maven Docker image. Unit/HTTP tests
cover a denied IP before credential lookup, the 429 response, rejection of a
short HMAC key and rejection of a nonnumeric peer before database access.

The packaged API started against isolated PostgreSQL 17.11 with all eleven
IAM changesets and a temporary 32-byte HMAC key and RSA signing pair.

- Eleven requests for an unknown account from one direct peer returned ten
  generic 401 responses and then 429. Each request carried a different
  untrusted `X-Forwarded-For`; PostgreSQL held exactly ten attempts with one
  distinct 32-byte digest. No raw IP column exists.
- After ageing only those synthetic attempts past five minutes, twelve
  concurrent requests returned ten 401 and two 429. Exactly ten attempts
  remained in the current five-minute window. The advisory transaction lock
  serialized the check and insert across the simultaneous requests.
- The API records an attempt before credential lookup. PostgreSQL clock time
  controls the window, and requests fail closed if persistence is unavailable.
- Stopping the isolated database made login return sanitized HTTP 503, without
  a credential lookup or internal connection details. The database was restarted.

The temporary service, database and keys were removed. This slice limits the
direct network peer. The Gateway/Auth integration still needs a reviewed,
spoof-resistant contract for the original client IP before the per-client
limit can be claimed behind a reverse proxy. Administrator unlock and outbox
delivery also remain separate work.
