// Cloud Function backing true persistent Google Drive access for Vault.
//
// Not deployable via CLI from the dev machine this was written on (no node/npm/firebase/gcloud
// installed) — deploy by pasting this file and package.json into the GCP Console's inline Cloud
// Functions/Cloud Run source editor. See the project README-adjacent plan for the exact console
// steps (billing plan, OAuth consent screen publishing status, Secret Manager, Firestore rules).
//
// Two modes, one function, both requiring a verified Firebase ID token (onCall handles that
// verification and CORS automatically — request.auth is never trustable client input):
//   'exchange' — one-time: trades an OAuth authorization code (from the client's initCodeClient
//                popup) for a refresh token, stored server-side, never returned to the client.
//   'mint'     — every app open, plus a proactive background timer: turns the stored refresh
//                token into a fresh access token, no Google UI involved at all.

const {onCall, HttpsError} = require('firebase-functions/v2/https');
const {setGlobalOptions} = require('firebase-functions/v2');
const admin = require('firebase-admin');
admin.initializeApp();

// Bounds worst-case cost/abuse blast radius for near-zero effort. Open to any Google account (by
// design — see below), so this is the only real cap on cost from a burst of traffic, legitimate
// or not.
setGlobalOptions({maxInstances: 10});

// No owner allowlist, deliberately: anyone who signs in gets their own isolated driveTokens/{uid}
// doc and their own Drive grant — never anyone else's. Each signed-in user only ever touches their
// own data, so opening this up doesn't create a cross-user data risk, only a shared-quota one
// (this function's calls all still run under this one Cloud project's billing and this one OAuth
// client's rate limits, regardless of who's calling).

// Same OAuth client Vault already uses for Drive access (see GOOGLE_OAUTH_CLIENT_ID in index.html)
// — this function only newly uses a capability (the authorization-code flow) that client already
// supports, not a new OAuth client.
const CLIENT_ID = '713625816347-61h6pgrra3ec7639kq3o8v3vdfpgmsjb.apps.googleusercontent.com';

// Must exactly match the page origin initCodeClient runs from in popup mode: no path, no trailing
// slash. This is a project-page GitHub Pages site (vaibhavkannas.github.io/Vault/), but per
// Google's own code-model docs the origin never includes the path, so this is correct as-is.
const REDIRECT_URI = 'https://vaibhavkannas.github.io';

// How much life an access token needs left before we bother reusing it instead of asking Google
// for a new one.
const REFRESH_SKEW_MS = 2 * 60 * 1000;

exports.driveAuth = onCall(async (request) => {
  if(!request.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
  const uid = request.auth.uid;
  const tokenDoc = admin.firestore().collection('driveTokens').doc(uid);

  async function tokenRequest(body){
    let res, json;
    try{
      res = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: new URLSearchParams({
          client_id: CLIENT_ID,
          client_secret: process.env.DRIVE_OAUTH_CLIENT_SECRET,
          ...body
        })
      });
      json = await res.json();
    } catch(e){
      throw new HttpsError('internal', 'Could not reach Google.');
    }
    return {ok: res.ok, json};
  }

  if(request.data && request.data.mode === 'exchange'){
    const code = request.data.code;
    if(!code) throw new HttpsError('invalid-argument', 'Missing code.');
    const {ok, json} = await tokenRequest({code, redirect_uri: REDIRECT_URI, grant_type: 'authorization_code'});
    if(!ok || !json.refresh_token){
      // Log only the error field, never the full response — a *successful* response contains a
      // live access/refresh token in plaintext, which would otherwise land in Cloud Logging.
      console.error('Drive auth exchange failed:', json && json.error);
      throw new HttpsError('internal', 'Google did not return offline access — try reconnecting.');
    }
    const expiresAt = Date.now() + (json.expires_in ? json.expires_in * 1000 : 55 * 60 * 1000);
    await tokenDoc.set({
      refreshToken: json.refresh_token,
      accessToken: json.access_token,
      accessTokenExpiresAt: expiresAt,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    return {accessToken: json.access_token, expiresIn: json.expires_in};
  }

  // mode: 'mint' (default). Serve the cached access token directly when it still has life left,
  // rather than round-tripping to Google on every single call — this is called on every app open
  // plus a periodic background refresh while the app stays open.
  const snap = await tokenDoc.get();
  if(!snap.exists) throw new HttpsError('failed-precondition', 'No Drive grant on file.', {reason: 'NO_GRANT'});
  const data = snap.data();
  if(data.accessToken && data.accessTokenExpiresAt && data.accessTokenExpiresAt - Date.now() > REFRESH_SKEW_MS){
    return {accessToken: data.accessToken, expiresIn: Math.floor((data.accessTokenExpiresAt - Date.now()) / 1000)};
  }

  const {ok, json} = await tokenRequest({refresh_token: data.refreshToken, grant_type: 'refresh_token'});
  if(!ok){
    if(json.error === 'invalid_grant'){
      // The refresh token itself is dead (revoked, or — if the OAuth consent screen was left in
      // "Testing" publishing status — force-expired by Google after 7 days regardless of use).
      // Not recoverable by retrying; only a fresh one-time consent fixes it.
      await tokenDoc.delete();
      throw new HttpsError('failed-precondition', 'Drive access was revoked.', {reason: 'GRANT_REVOKED'});
    }
    console.error('Drive auth refresh failed:', json.error);
    throw new HttpsError('internal', 'Could not refresh Drive access.');
  }
  const expiresAt = Date.now() + (json.expires_in ? json.expires_in * 1000 : 55 * 60 * 1000);
  await tokenDoc.update({accessToken: json.access_token, accessTokenExpiresAt: expiresAt});
  return {accessToken: json.access_token, expiresIn: json.expires_in};
});
