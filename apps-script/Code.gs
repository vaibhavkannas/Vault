// Apps Script backend behind Vault's persistent Google Drive access.
//
// Deploy as a Web App: Deploy > New deployment > type "Web app" > Execute as "Me", Who has
// access "Anyone". The resulting /exec URL goes into index.html's APPS_SCRIPT_URL constant.
//
// Requires two Script Properties, set once via Project Settings > Script Properties (never in
// this source, so they stay out of the repo and out of anyone with only Viewer access):
//   DRIVE_OAUTH_CLIENT_SECRET — the Vault OAuth client's secret, from GCP Console > Credentials.
//   FIREBASE_WEB_API_KEY      — Vault's Firebase Web API key (the same one already public in
//                               index.html's firebaseConfig — not actually a secret, just kept
//                               here too rather than hardcoded, for one less place to edit later).
//
// Two "modes" from the client, mirroring the app's own mintDriveAccessToken()/
// grantDriveAccessOneTime() split:
//   'exchange' — one-time: trades an OAuth authorization code for a refresh token, stores it.
//   'mint'     — every app open, plus a periodic background refresh: turns the stored refresh
//                token into a fresh access token. No Google UI involved at all.

const CLIENT_ID = '713625816347-61h6pgrra3ec7639kq3o8v3vdfpgmsjb.apps.googleusercontent.com';
// Must exactly match the page origin initCodeClient runs from in popup mode: no path, no
// trailing slash.
const REDIRECT_URI = 'https://vaibhavkannas.github.io';
// How much life a cached access token needs left before we bother reusing it instead of asking
// Google for a new one.
const REFRESH_SKEW_MS = 2 * 60 * 1000;

function doPost(e){
  let req;
  try{
    req = JSON.parse(e.postData.contents);
  } catch(err){
    return jsonOutput({error: 'invalid-argument'});
  }

  const uid = verifyIdToken(req.idToken);
  if(!uid) return jsonOutput({error: 'unauthenticated'});

  if(req.mode === 'exchange') return jsonOutput(handleExchange(uid, req.code));
  return jsonOutput(handleMint(uid));
}

function jsonOutput(obj){
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}

// Apps Script has no equivalent to firebase-admin's local ID-token signature verification, so
// this asks Firebase's own servers instead: a 200 response — scoped to this exact Firebase
// project via the API key in the URL — with a matching user is Google itself vouching the token
// is genuine, unexpired, and not from some other Firebase project. Anything else is rejected.
function verifyIdToken(idToken){
  if(!idToken) return null;
  const key = PropertiesService.getScriptProperties().getProperty('FIREBASE_WEB_API_KEY');
  const res = UrlFetchApp.fetch(
    'https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' + key,
    {
      method: 'post',
      contentType: 'application/json',
      payload: JSON.stringify({idToken: idToken}),
      muteHttpExceptions: true
    }
  );
  if(res.getResponseCode() !== 200) return null;
  let body;
  try{ body = JSON.parse(res.getContentText()); } catch(err){ return null; }
  if(!body.users || !body.users.length) return null;
  return body.users[0].localId;
}

function tokenRequest(body){
  const clientSecret = PropertiesService.getScriptProperties().getProperty('DRIVE_OAUTH_CLIENT_SECRET');
  const payload = Object.assign({client_id: CLIENT_ID, client_secret: clientSecret}, body);
  const res = UrlFetchApp.fetch('https://oauth2.googleapis.com/token', {
    method: 'post',
    payload: payload,
    muteHttpExceptions: true
  });
  let json;
  try{ json = JSON.parse(res.getContentText()); } catch(err){ json = {}; }
  return {ok: res.getResponseCode() === 200, json: json};
}

function handleExchange(uid, code){
  if(!code) return {error: 'invalid-argument'};
  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try{
    const result = tokenRequest({code: code, redirect_uri: REDIRECT_URI, grant_type: 'authorization_code'});
    const json = result.json;
    if(!result.ok || !json.refresh_token){
      // Log only the error field, never the full response — a *successful* response contains a
      // live access/refresh token in plaintext, which would otherwise land in Apps Script's own
      // execution log.
      console.error('Drive auth exchange failed: ' + (json && json.error));
      return {error: 'internal', message: 'Google did not return offline access — try reconnecting.'};
    }
    const expiresAt = Date.now() + (json.expires_in ? json.expires_in * 1000 : 55 * 60 * 1000);
    const props = {};
    props['refreshToken_' + uid] = json.refresh_token;
    props['accessToken_' + uid] = json.access_token;
    props['accessTokenExpiresAt_' + uid] = String(expiresAt);
    PropertiesService.getScriptProperties().setProperties(props);
    return {accessToken: json.access_token, expiresIn: json.expires_in};
  } finally {
    lock.releaseLock();
  }
}

function handleMint(uid){
  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try{
    const scriptProps = PropertiesService.getScriptProperties();
    const refreshToken = scriptProps.getProperty('refreshToken_' + uid);
    if(!refreshToken) return {error: 'failed-precondition', reason: 'NO_GRANT'};

    // Serve the cached access token directly when it still has life left, rather than
    // round-tripping to Google on every single call — this is called on every app open plus a
    // periodic background refresh while the app stays open.
    const cachedAccessToken = scriptProps.getProperty('accessToken_' + uid);
    const cachedExpiresAt = Number(scriptProps.getProperty('accessTokenExpiresAt_' + uid) || 0);
    if(cachedAccessToken && cachedExpiresAt - Date.now() > REFRESH_SKEW_MS){
      return {accessToken: cachedAccessToken, expiresIn: Math.floor((cachedExpiresAt - Date.now()) / 1000)};
    }

    const result = tokenRequest({refresh_token: refreshToken, grant_type: 'refresh_token'});
    const json = result.json;
    if(!result.ok){
      if(json.error === 'invalid_grant'){
        // The refresh token itself is dead (revoked, or — if the OAuth consent screen was left
        // in "Testing" publishing status — force-expired by Google after 7 days regardless of
        // use). Not recoverable by retrying; only a fresh one-time consent fixes it.
        scriptProps.deleteProperty('refreshToken_' + uid);
        scriptProps.deleteProperty('accessToken_' + uid);
        scriptProps.deleteProperty('accessTokenExpiresAt_' + uid);
        return {error: 'failed-precondition', reason: 'GRANT_REVOKED'};
      }
      console.error('Drive auth refresh failed: ' + json.error);
      return {error: 'internal', message: 'Could not refresh Drive access.'};
    }
    const expiresAt = Date.now() + (json.expires_in ? json.expires_in * 1000 : 55 * 60 * 1000);
    scriptProps.setProperties({
      ['accessToken_' + uid]: json.access_token,
      ['accessTokenExpiresAt_' + uid]: String(expiresAt)
    });
    return {accessToken: json.access_token, expiresIn: json.expires_in};
  } finally {
    lock.releaseLock();
  }
}
