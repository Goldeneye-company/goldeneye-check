# Pre-launch checklist

Items that `gecheck` cannot check automatically.

## Spending

- [ ] A monthly spending limit is set in the OpenAI, Anthropic and Google AI consoles.
- [ ] Spending alerts are enabled at your cloud provider and AI providers.
- [ ] Endpoints that call AI models have a per-user request limit.
- [ ] The length of text a user can send to a model is limited.

## Access

- [ ] Two-factor authentication is enabled on GitHub, your hosting, domain registrar, cloud provider and payment system.
- [ ] Keys that ever ended up in git or in messages have been reissued.
- [ ] Development and the live site use different keys.
- [ ] Service accounts and tokens have only the permissions they need.
- [ ] Former project members no longer have access.

## Data

- [ ] Supabase: RLS is enabled on all tables and Advisors → Security shows no warnings.
- [ ] Firebase: the rules contain no `if true`, and users can access only their own data.
- [ ] The database is not reachable directly from the internet.
- [ ] Backups run automatically, and restoring from them has been tested.
- [ ] Personal data is stored in line with the laws of your country.

## Application

- [ ] You have checked with two different users that one cannot see the other's data.
- [ ] Every operation that changes or deletes data checks the user's permissions on the server.
- [ ] Input is validated on the server, not only in the browser.
- [ ] Error messages do not show technical details to users.
- [ ] File uploads are limited by type and size.
- [ ] Login, sign-up and password reset are protected against brute force.

## Website

- [ ] `gecheck site` finds no critical or high issues on your domain.
- [ ] The site has a privacy policy and the owner's contact details.

Completing every item does not guarantee security. If the project handles payments or personal data, consider ordering a manual review: https://goldeneye.kz/en/audit/
