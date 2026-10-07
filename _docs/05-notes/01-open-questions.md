# 01 – Open questions and todo

Add new questions at the bottom of their section. Move answered ones to "Answered" with a one-line answer
or a link to the doc that answers them.

## Todo

- [ ] Repository updates that change 0 rows should return a "not modified" error.

## Open questions

- Why is a random string better than a ULID for IDs? (IDs are still ULIDs by default; see [04-plan/02-steps.md](../04-plan/02-steps.md) breaking checklist.)
- Make the password hasher an interface (`config.PasswordHasher` is still a struct with a TODO).
- What is `activeTeamId` for? (Org teams, step 9.)
- What are `common/types` `RawBodyMetaKey = "goauth.rawBody"`, `Transform`, `Document Operation` for?
- Make the full name optional.

## Answered / done

- [x] Add admin ban endpoints.
- [x] Add the account model.
- [x] Move all `birukbelay/gocmn` functions into this library.
- [x] Remove `session.HashedToken` and use just the token (step 2).
- [x] Drop `password` from the user table; passwords live on the `credential` account.
- [x] What can move from `compat` to the main codebase? Everything; `compat/` is deleted (step 4).
- [x] What is `src/sessions` for and where should it go? It became `src/app/services/session`, with the
      middleware in `src/app/adapters/huma` (step 4).
- [x] What are the new `Sessions`, `SessionResolver` and cookie functions? The better-auth session manager,
      its request middleware and the signed-cookie manager (see [04-plan/02-steps.md](../04-plan/02-steps.md), step 4).
- [x] Fix column lengths: sizes removed except where MySQL needs them for indexes.
