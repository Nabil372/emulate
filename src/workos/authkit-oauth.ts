import { createHash, timingSafeEqual } from 'node:crypto';
import type { WorkOSStore } from './store.js';
import type { WorkOSConnectApplication } from './entities.js';

/**
 * The AuthKit domain acting as an OAuth 2.1 authorization server for MCP clients: what
 * `/oauth2/authorize`, `/oauth2/token` and `/oauth2/register` share with the discovery documents.
 * Kept out of the route files because the documents advertise exactly what the routes enforce, and
 * one list is what keeps the two from drifting.
 */

/** The scopes a production AuthKit domain advertises. A dynamically registered client is limited to these. */
export const AUTHKIT_OAUTH_SCOPES = ['email', 'offline_access', 'openid', 'profile'] as const;

/** Only S256: production advertises no other, and OAuth 2.1 drops `plain`. */
export const AUTHKIT_CODE_CHALLENGE_METHODS = ['S256'] as const;

/** `none` is a public client, which `/oauth2/register` maps to a PKCE-only application. */
export const AUTHKIT_TOKEN_ENDPOINT_AUTH_METHODS = ['none', 'client_secret_post', 'client_secret_basic'] as const;

/** RFC 7591 `application_type`, the two values production's registration accepts. */
export const AUTHKIT_APPLICATION_TYPES = ['web', 'native'] as const;

/**
 * Whether the application is a public client: one that cannot keep a secret, so PKCE is its only
 * proof. `uses_pkce` is the field WorkOS gives an application for exactly this, and
 * `/oauth2/register` sets it for `token_endpoint_auth_method: none`.
 */
export function isPublicClient(application: WorkOSConnectApplication): boolean {
  return application.application_type === 'oauth' && application.uses_pkce;
}

/** RFC 7636 §4.6 for S256. Constant-time, because the verifier is a secret until the exchange. */
export function pkceMatches(codeVerifier: string, codeChallenge: string): boolean {
  const computed = Buffer.from(createHash('sha256').update(codeVerifier).digest('base64url'));
  const expected = Buffer.from(codeChallenge);
  return computed.length === expected.length && timingSafeEqual(computed, expected);
}

/**
 * The scopes an application can currently grant. Seeded and dashboard applications configured
 * with none retain the historical standard default. Dynamic registration stores its defaults
 * explicitly, so clearing those scopes must leave none. Read at every authorize, exchange and
 * refresh, so a scope removed from the application stops being issued.
 */
export function availableScopes(application: WorkOSConnectApplication): string[] {
  return application.was_dynamically_registered || application.scopes.length > 0
    ? application.scopes
    : [...AUTHKIT_OAUTH_SCOPES];
}

/** RFC 7636 §4.1: 43 to 128 unreserved characters. */
export function isValidCodeVerifier(value: string): boolean {
  return /^[A-Za-z0-9\-._~]{43,128}$/.test(value);
}

/**
 * RFC 8707 §2: a resource is an absolute URI with no fragment. Checked wherever a client hands one
 * over, so a malformed value is refused as `invalid_target` instead of being carried on a code.
 */
export function isValidResourceUri(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.hash === '' && !value.includes('#');
  } catch {
    return false;
  }
}

/**
 * The `aud` for a token bound to `resource`. A bound resource is always one the environment has
 * registered (see `resolveAuthorizeResource` and the token endpoint's binding); with none, the
 * audience falls back to the application's `audience` and then its `client_id`, which is what this
 * surface minted before indicators existed.
 */
export function resolveAudience(application: WorkOSConnectApplication, resource: string | null): string {
  return resource ?? application.audience ?? application.client_id;
}

export type AuthorizeResourceResult =
  | { ok: true; resource: string | null }
  | { ok: false; description: string | undefined };

/**
 * The RFC 8707 `resource` of an `/oauth2/authorize` request, resolved the way production's
 * authorize handler does it (`validateResource` and the default-resource fallback that follows it):
 *
 * - A dynamically registered client's `resource` is validated only once the environment has
 *   registered resources. Then a malformed or fragment-bearing value, or one matching no registered
 *   resource, is `invalid_target` on the callback, with a description only for the malformed case.
 *   With no resources registered the parameter is ignored, for backwards compatibility.
 * - Any other client's `resource` is ignored: production gates resource indicators for those
 *   behind an environment feature flag, so the flag-off path is the one reproduced.
 * - A dynamically registered client that ends up bound to nothing (it omitted `resource`, or
 *   nothing is registered) is bound to the resource flagged `default`, when one exists, so its
 *   tokens still carry a resource audience. Some MCP clients omit the parameter entirely.
 *
 * Wildcard patterns are refused at registration here, so matching is exact.
 */
export function resolveAuthorizeResource(
  ws: WorkOSStore,
  application: WorkOSConnectApplication,
  resource: string | null,
): AuthorizeResourceResult {
  if (!application.was_dynamically_registered) return { ok: true, resource: null };
  const registered = ws.authkitOauthResources.all();
  let bound: string | null = null;
  if (resource !== null && registered.length > 0) {
    if (!isValidResourceUri(resource)) {
      let parses = true;
      try {
        new URL(resource);
      } catch {
        parses = false;
      }
      return {
        ok: false,
        description: parses
          ? 'Invalid target: resource URIs cannot contain a URL fragment.'
          : 'Invalid target: resource URI is malformed.',
      };
    }
    const match = registered.find((r) => r.uri === resource);
    if (!match) return { ok: false, description: undefined };
    bound = match.uri;
  }
  if (bound === null) bound = registered.find((r) => r.default)?.uri ?? null;
  return { ok: true, resource: bound };
}

/**
 * Whether a code exchange is answered with a refresh token, as production decides it
 * (`shouldIssueRefreshToken` in the application consent tokens service): always when the grant
 * carries `offline_access`; otherwise a dynamically registered client, which today means an MCP
 * client, gets one exactly when it did not ask for `openid`, since outside OIDC mode issuing one
 * is at the server's discretion and some connectors never send a scope yet fail without one; any
 * other client gets none. The `grant_types` a client registered play no part.
 */
export function shouldIssueRefreshToken(application: WorkOSConnectApplication, scopes: readonly string[]): boolean {
  if (scopes.includes('offline_access')) return true;
  if (application.was_dynamically_registered) return !scopes.includes('openid');
  return false;
}
