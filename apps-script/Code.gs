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

// ---------- Expiring-document email digest ----------
//
// Independent of the Drive-token logic above: this reads Firestore directly (not via doPost) and
// is only ever invoked by a time-driven trigger (see createDailyDigestTrigger, run once manually
// from the Apps Script editor — never called from doPost). Requires the 'datastore' and
// 'script.send_mail' scopes declared in appsscript.json.
//
// Auth model: ScriptApp.getOAuthToken() mints a token for whoever the script executes as — the
// project owner, since both the web app (executeAs: USER_DEPLOYING) and every trigger created by
// that same owner always run as them. The project owner has full IAM on their own Firestore data,
// so this reaches the Firestore REST API the same way the Admin SDK or gcloud would: authenticated
// as a principal with IAM permission, which bypasses Firestore Security Rules entirely (rules only
// gate the Firebase-client-SDK-style access path). No service account or private key involved.

const FIRESTORE_PROJECT_ID = 'elite-vault-7b00a';
const FIRESTORE_BASE = 'https://firestore.googleapis.com/v1/projects/' + FIRESTORE_PROJECT_ID + '/databases/(default)/documents';
const VAULT_APP_URL = 'https://vaibhavkannas.github.io/Vault/';
// Send only on these days-until-expiry milestones, not every day across the full lookahead/grace
// window — an unrenewed document would otherwise generate up to 44 emails (14 down through -30)
// before its owner acts or turns the digest off. Recomputed fresh from daysUntil() every run, so
// this needs no "already sent" tracking of its own.
const DIGEST_MILESTONE_DAYS = [14, 7, 3, 1, 0, -1, -7, -30];

function firestoreFetch(path){
  const res = UrlFetchApp.fetch(FIRESTORE_BASE + path, {
    headers: {Authorization: 'Bearer ' + ScriptApp.getOAuthToken()},
    muteHttpExceptions: true
  });
  let json;
  try{ json = JSON.parse(res.getContentText()); } catch(err){ json = {}; }
  return {ok: res.getResponseCode() === 200, json: json};
}

function firestoreListAll(collectionPath){
  let out = [];
  let pageToken = null;
  do{
    const qs = pageToken ? ('?pageToken=' + encodeURIComponent(pageToken)) : '';
    const result = firestoreFetch('/' + collectionPath + qs);
    if(!result.ok){
      console.error('Firestore list failed for ' + collectionPath + ': ' + JSON.stringify(result.json));
      break;
    }
    out = out.concat(result.json.documents || []);
    pageToken = result.json.nextPageToken;
  } while(pageToken);
  return out;
}

// Unwraps Firestore REST's typed-value JSON. Only covers the value types this app's own documents
// actually use (string/boolean/integer/null/array-of-integer-or-string) — not a general-purpose
// Firestore type mapper.
function firestoreFieldsToObject(fields){
  const obj = {};
  for(const key in (fields || {})){
    const val = fields[key];
    if(val.stringValue !== undefined) obj[key] = val.stringValue;
    else if(val.booleanValue !== undefined) obj[key] = val.booleanValue;
    else if(val.integerValue !== undefined) obj[key] = Number(val.integerValue);
    else if(val.nullValue !== undefined) obj[key] = null;
    else if(val.arrayValue !== undefined){
      obj[key] = (val.arrayValue.values || []).map(function(v){
        if(v.integerValue !== undefined) return Number(v.integerValue);
        if(v.stringValue !== undefined) return v.stringValue;
        return null;
      });
    }
  }
  return obj;
}

// Reverse of firestoreFieldsToObject — wraps a plain JS value in Firestore REST's typed-value
// shape. Only covers what this file actually needs to write (string/boolean/number/null); extend
// if a future write needs another type.
function toFirestoreValue(v){
  if(v === null || v === undefined) return {nullValue: null};
  if(typeof v === 'string') return {stringValue: v};
  if(typeof v === 'boolean') return {booleanValue: v};
  if(typeof v === 'number') return {integerValue: String(v)};
  throw new Error('toFirestoreValue: unsupported type ' + typeof v);
}
// A single write helper for both shapes Code.gs needs: `merge:true` does a partial update (only
// the given fields change, like the client's own `.update()`/`.set({merge:true})`) via Firestore's
// updateMask query params; `merge:false` replaces the whole document (like a plain `.set()`) by
// omitting them — Firestore's PATCH method already does either depending on that one difference,
// so this needs no separate firestoreSet()/firestoreUpdate() pair.
function firestoreWrite(path, fieldsObj, merge){
  const fields = {};
  for(const k in fieldsObj) fields[k] = toFirestoreValue(fieldsObj[k]);
  const maskQs = merge
    ? ('?' + Object.keys(fieldsObj).map(function(k){ return 'updateMask.fieldPaths=' + encodeURIComponent(k); }).join('&'))
    : '';
  const res = UrlFetchApp.fetch(FIRESTORE_BASE + path + maskQs, {
    method: 'patch',
    contentType: 'application/json',
    headers: {Authorization: 'Bearer ' + ScriptApp.getOAuthToken()},
    payload: JSON.stringify({fields: fields}),
    muteHttpExceptions: true
  });
  return res.getResponseCode() === 200;
}

// Looks up each subscriber's real address via the Identity Platform Admin API's project-scoped
// accounts:lookup (batched by localId) rather than trusting the client-writable `email` field
// stored alongside the subscription doc — any signed-in user can rewrite that field via the
// Firestore JS SDK (there's no Security Rule constraining it to their own verified address), and
// this MailApp.sendEmail call below runs as the project owner, so an unverified field here is a
// way to redirect that send to an arbitrary address.
//
// Deliberately NOT the plain /v1/accounts:lookup?key=... endpoint verifyIdToken() above uses —
// that's the client-facing surface for verifying a single caller's own ID token. Bulk lookup by
// UID needs this project-scoped endpoint instead, authenticated purely via the OAuth token (no API
// key), the same one the Admin SDK's getUsers()/listUsers() call under the hood.
function resolveVerifiedEmails(uids){
  if(!uids.length) return {};
  const res = UrlFetchApp.fetch(
    'https://identitytoolkit.googleapis.com/v1/projects/' + FIRESTORE_PROJECT_ID + '/accounts:lookup',
    {
      method: 'post',
      contentType: 'application/json',
      headers: {Authorization: 'Bearer ' + ScriptApp.getOAuthToken()},
      payload: JSON.stringify({localId: uids}),
      muteHttpExceptions: true
    }
  );
  let body;
  try{ body = JSON.parse(res.getContentText()); } catch(err){ body = {}; }
  if(!body.users || !body.users.length){
    // Never silently swallow this — an admin lookup that resolves nobody despite real uids to look
    // up is exactly the failure mode that already cost a long debugging session once.
    console.error('resolveVerifiedEmails: resolved 0 of ' + uids.length + ' uid(s) — HTTP ' + res.getResponseCode() + ': ' + res.getContentText());
  }
  const map = {};
  (body.users || []).forEach(function(u){ if(u.email) map[u.localId] = u.email; });
  return map;
}

function listEmailDigestSubscribers(){
  const uids = firestoreListAll('emailDigestSubscribers').map(function(d){ return d.name.split('/').pop(); });
  const verified = resolveVerifiedEmails(uids);
  return uids
    .map(function(uid){ return {uid: uid, email: verified[uid]}; })
    .filter(function(s){ return !!s.email; });
}

function listActiveDocumentsForUser(uid){
  return firestoreListAll('users/' + uid + '/documents')
    .map(function(d){ return firestoreFieldsToObject(d.fields); })
    // Mirrors index.html's own `!d.archived` check exactly (not `=== false`), so legacy documents
    // with no archived field at all are still treated as active, same as the client does. Also
    // excludes anything already soft-deleted (see runTrashCleanup below) — a document the user just
    // deleted has no business showing up in a reminder about it.
    .filter(function(doc){ return !doc.archived && doc.expiry && !doc.deletedAt; });
}

function listCategoryLabelsForUser(uid){
  const map = {};
  firestoreListAll('users/' + uid + '/categories').forEach(function(d){
    const fields = firestoreFieldsToObject(d.fields);
    if(fields.id) map[fields.id] = fields.label || fields.id;
  });
  return map;
}

// Expiry dates are plain "YYYY-MM-DD" strings with no timezone (see index.html's own
// parseLocalDate/daysUntil) — parse the components as a local date rather than via `new
// Date(dateStr)`, which would interpret it as UTC midnight. Apps Script's Date "local" methods
// resolve against this project's configured timeZone (Asia/Kolkata, see appsscript.json), so this
// agrees with what an IST-based user sees in-app.
function parseLocalDate(dateStr){
  const parts = dateStr.split('-').map(Number);
  return new Date(parts[0], parts[1] - 1, parts[2]);
}

function daysUntil(dateStr){
  const t = new Date();
  t.setHours(0, 0, 0, 0);
  return Math.round((parseLocalDate(dateStr) - t) / 86400000);
}

// A document can override the global milestone schedule with its own days-before-expiry list
// (doc.reminderDays, set from the client's Edit Document form — e.g. a passport might warrant a
// heads-up 90 days out, not just 14). Falls back to the shared schedule when unset.
function milestoneDaysForDoc(doc){
  return (Array.isArray(doc.reminderDays) && doc.reminderDays.length) ? doc.reminderDays : DIGEST_MILESTONE_DAYS;
}

function buildDigestRowsForUser(uid){
  const labels = listCategoryLabelsForUser(uid);
  return listActiveDocumentsForUser(uid)
    .map(function(doc){
      return {
        doc: doc,
        title: doc.title,
        category: labels[doc.category] || doc.category,
        days: daysUntil(doc.expiry)
      };
    })
    .filter(function(d){
      // Already-expired documents stay in every digest for as long as they're active (not yet
      // archived) — an unresolved overdue item deserves ongoing visibility, unlike the sparse
      // milestone schedule below, which exists specifically to avoid daily noise for something
      // that isn't due yet.
      if(d.days < 0) return true;
      return milestoneDaysForDoc(d.doc).includes(d.days);
    })
    .sort(function(a, b){ return a.days - b.days; });
}

function formatDaysLabel(days){
  if(days === 0) return 'expires today';
  if(days === 1) return 'expires tomorrow';
  if(days > 1) return 'expires in ' + days + ' days';
  if(days === -1) return 'expired 1 day ago';
  return 'expired ' + (-days) + ' days ago';
}

function buildDigestText(rows){
  const lines = rows.map(function(r){ return '- ' + r.title + ' (' + r.category + ') — ' + formatDaysLabel(r.days); });
  return 'Documents needing attention in Vault:\n\n' + lines.join('\n') + '\n\n' + 'Open Vault: ' + VAULT_APP_URL +
    '\n\n—\nYou\'re receiving this because email reminders are turned on in Vault → Settings.';
}

function escapeHtml(str){
  return String(str).replace(/[&<>"']/g, function(c){
    return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
  });
}

// Three severity tiers, matching the same palette the app itself uses for its own status pills
// (index.html's --danger/--warning/--success tokens) so the email and the in-app UI read as the
// same product rather than two different-looking things. Email clients strip <style> blocks and
// most external stylesheets, so every rule here has to be inline to render reliably in Gmail/
// Outlook/etc — there's no separate stylesheet to maintain in sync.
function digestSeverityFor(days){
  if(days < 0) return {bg: '#fce8e6', fg: '#c5221f'};       // overdue — matches --danger/--danger-bg
  if(days <= 7) return {bg: '#f7edd9', fg: '#8a5a05'};       // due soon — matches --warning/--warning-bg
  return {bg: '#e6f4ea', fg: '#157a34'};                     // further out — matches --success/--success-bg
}

function buildDigestRowHtml(r){
  const sev = digestSeverityFor(r.days);
  return '<tr>' +
    '<td style="padding:14px 0;border-bottom:1px solid #f1f3f4;">' +
      '<div style="font-size:14px;color:#1f1f1f;font-weight:500;">' + escapeHtml(r.title) + '</div>' +
      '<div style="font-size:12px;color:#5f6368;margin-top:2px;">' + escapeHtml(r.category) + '</div>' +
    '</td>' +
    '<td style="padding:14px 0;border-bottom:1px solid #f1f3f4;text-align:right;white-space:nowrap;vertical-align:top;">' +
      '<span style="display:inline-block;padding:4px 10px;border-radius:999px;font-size:11px;font-weight:600;background:' + sev.bg + ';color:' + sev.fg + ';">' +
        escapeHtml(formatDaysLabel(r.days)) +
      '</span>' +
    '</td>' +
  '</tr>';
}

function buildDigestHtml(rows){
  const rowsHtml = rows.map(buildDigestRowHtml).join('');
  const count = rows.length;
  const heading = count + ' document' + (count === 1 ? '' : 's') + ' need' + (count === 1 ? 's' : '') + ' your attention';
  return '<div style="background:#f1f3f4;padding:32px 16px;font-family:Roboto,Arial,sans-serif;">' +
    '<table role="presentation" width="100%" style="max-width:520px;margin:0 auto;border-collapse:collapse;">' +
      '<tr><td style="background:#1a73e8;border-radius:16px 16px 0 0;padding:20px 28px;">' +
        '<span style="color:#ffffff;font-size:18px;font-weight:500;">🛡️ Vault</span>' +
      '</td></tr>' +
      '<tr><td style="background:#ffffff;border-left:1px solid #dadce0;border-right:1px solid #dadce0;padding:24px 28px 4px;">' +
        '<p style="margin:0 0 4px;font-size:16px;color:#1f1f1f;font-weight:500;">' + escapeHtml(heading) + '</p>' +
        '<p style="margin:0 0 12px;font-size:13px;color:#5f6368;">Here\'s what\'s coming up or overdue in your Vault.</p>' +
      '</td></tr>' +
      '<tr><td style="background:#ffffff;border-left:1px solid #dadce0;border-right:1px solid #dadce0;padding:0 28px;">' +
        '<table role="presentation" width="100%" style="border-collapse:collapse;">' + rowsHtml + '</table>' +
      '</td></tr>' +
      '<tr><td style="background:#ffffff;border:1px solid #dadce0;border-top:none;border-radius:0 0 16px 16px;padding:20px 28px 28px;">' +
        '<a href="' + VAULT_APP_URL + '" style="display:inline-block;background:#1a73e8;color:#ffffff;text-decoration:none;padding:10px 22px;border-radius:999px;font-size:14px;font-weight:500;">Open Vault</a>' +
      '</td></tr>' +
    '</table>' +
    '<p style="text-align:center;color:#80868b;font-size:11px;margin:20px auto 0;max-width:520px;">' +
      'You\'re receiving this because email reminders are turned on in Vault → Settings. This mailbox isn\'t monitored.' +
    '</p>' +
  '</div>';
}

function sendEmailDigests(){
  const subscribers = listEmailDigestSubscribers();
  let sent = 0;
  subscribers.forEach(function(sub){
    try{
      const rows = buildDigestRowsForUser(sub.uid);
      if(!rows.length) return;
      const subject = rows.length + ' document' + (rows.length === 1 ? '' : 's') + ' need attention — Vault';
      // `name` only customizes the display name shown to the recipient — MailApp always sends from
      // the Apps Script project owner's own Gmail address underneath, the same for every recipient.
      // There's no way to make each user see their own address as sender without a verified custom
      // domain / Workspace delegated-sending setup, which is out of scope for a personal-Gmail-based
      // project like this one.
      MailApp.sendEmail(sub.email, subject, buildDigestText(rows), {htmlBody: buildDigestHtml(rows), name: 'Vault'});
      sent++;
    } catch(err){
      // One user's bad data or a transient failure must not abort everyone else's digest.
      console.error('Digest failed for uid ' + sub.uid + ': ' + err);
    }
  });
  // A "completed with no error" run otherwise leaves an empty Cloud log either way, whether it
  // genuinely sent nothing (no one had a document due) or actually mailed several people — no way
  // to tell them apart without this.
  console.log('Email digest: sent to ' + sent + ' of ' + subscribers.length + ' subscriber(s).');
}

// ---------- Push notifications (FCM) ----------
//
// Mirrors the email digest above: an independent subscriber list (pushSubscribers, storing an FCM
// token instead of an email), enumerated and sent to from the same daily trigger. Auth is the same
// ScriptApp.getOAuthToken() pattern already used for Firestore reads — FCM's HTTP v1 send API
// accepts the same kind of OAuth bearer token, just with the 'firebase.messaging' scope added in
// appsscript.json, so no separate credential/service account is needed here either.

const FCM_SEND_URL = 'https://fcm.googleapis.com/v1/projects/' + FIRESTORE_PROJECT_ID + '/messages:send';

function firestoreDelete(path){
  const res = UrlFetchApp.fetch(FIRESTORE_BASE + path, {
    method: 'delete',
    headers: {Authorization: 'Bearer ' + ScriptApp.getOAuthToken()},
    muteHttpExceptions: true
  });
  return res.getResponseCode() === 200 || res.getResponseCode() === 404; // 404 = already gone
}

function listPushSubscribers(){
  return firestoreListAll('pushSubscribers')
    .map(function(d){
      const fields = firestoreFieldsToObject(d.fields);
      return {uid: d.name.split('/').pop(), token: fields.token};
    })
    .filter(function(s){ return !!s.token; });
}

// Data-only (no `notification` block) — sending both let the platform auto-display the
// `notification` half independently of the client's own onBackgroundMessage handler in sw.js
// (which also calls showNotification), producing two separate on-screen notifications from a
// single send. FCM data-payload values must all be strings, which title/body already are.
function sendPushNotification(token, title, body, data){
  const payload = {
    message: {
      token: token,
      webpush: {fcm_options: {link: VAULT_APP_URL}},
      data: Object.assign({title: title, body: body}, data || {})
    }
  };
  const res = UrlFetchApp.fetch(FCM_SEND_URL, {
    method: 'post',
    contentType: 'application/json',
    headers: {Authorization: 'Bearer ' + ScriptApp.getOAuthToken()},
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  });
  if(res.getResponseCode() === 200) return {ok: true};
  let json;
  try{ json = JSON.parse(res.getContentText()); } catch(err){ json = {}; }
  const details = (json.error && json.error.details) || [];
  // FCM v1's documented shape for a dead token: HTTP 404 plus a typed error detail carrying this
  // code. Checking both, since relying on the status code alone is one signal short of certain.
  const unregistered = res.getResponseCode() === 404 || details.some(function(d){ return d.errorCode === 'UNREGISTERED'; });
  return {ok: false, unregistered: unregistered, error: json.error};
}

function sendPushReminders(){
  const subscribers = listPushSubscribers();
  let sent = 0;
  subscribers.forEach(function(sub){
    try{
      const rows = buildDigestRowsForUser(sub.uid); // already sorted soonest-first
      if(!rows.length) return;
      const title = rows.length + ' document' + (rows.length === 1 ? '' : 's') + ' need attention';
      const top = rows[0];
      const body = rows.length === 1
        ? top.title + ' — ' + formatDaysLabel(top.days)
        : top.title + ' (' + formatDaysLabel(top.days) + ') and ' + (rows.length - 1) + ' more';
      const result = sendPushNotification(sub.token, title, body, {});
      if(result.ok){
        sent++;
      } else {
        console.error('Push failed for uid ' + sub.uid + ': ' + JSON.stringify(result.error));
        // A token FCM reports as unregistered will never work again — delete it so the job stops
        // silently retrying a dead subscription forever.
        if(result.unregistered) firestoreDelete('/pushSubscribers/' + sub.uid);
      }
    } catch(err){
      // One user's bad data or a transient failure must not abort everyone else's reminders.
      console.error('Push reminder failed for uid ' + sub.uid + ': ' + err);
    }
  });
  console.log('Push reminders: sent to ' + sent + ' of ' + subscribers.length + ' subscriber(s).');
}

// ---------- Archived-document auto-delete ----------
//
// Opt-in only — archiveRetentionSubscribers/{uid} only exists for an account that picked
// something other than "Never" in Settings (see setArchiveRetention in index.html). Deletes both
// the Firestore record and the underlying Drive file once a document has been archived at least
// that many days. Getting Drive access for the delete reuses handleMint(uid) — the exact same
// per-user token-minting path Code.gs already runs for the client's own 'mint' calls — since
// ScriptApp.getOAuthToken() only ever grants the PROJECT OWNER's own Drive access, never an
// arbitrary user's; each user's Drive folder lives in their own account, not the owner's.
function listArchiveRetentionSubscribers(){
  return firestoreListAll('archiveRetentionSubscribers')
    .map(function(d){
      const fields = firestoreFieldsToObject(d.fields);
      return {uid: d.name.split('/').pop(), archiveRetentionDays: fields.archiveRetentionDays};
    })
    .filter(function(s){ return !!s.archiveRetentionDays; });
}

function listArchivedDocumentsForUser(uid){
  return firestoreListAll('users/' + uid + '/documents')
    .map(function(d){
      const obj = firestoreFieldsToObject(d.fields);
      obj.id = d.name.split('/').pop();
      return obj;
    })
    // !doc.deletedAt matters here specifically: a document can be BOTH archived and already
    // soft-deleted (the user archived it, then later deleted it manually from the 3-dot menu) —
    // without this, runArchiveCleanup would keep "moving" an already-trashed document into Deleted
    // again on every run, each time stamping a fresh deletedAt and pushing its real purge date back
    // indefinitely instead of counting down from when it actually landed in trash.
    .filter(function(doc){ return doc.archived && doc.archivedAt && !doc.deletedAt; });
}

function daysSinceIso(isoString){
  return Math.floor((Date.now() - new Date(isoString).getTime()) / 86400000);
}

function driveDeleteFileForUser(uid, fileId){
  const mintResult = handleMint(uid);
  if(mintResult.error) return false;
  const res = UrlFetchApp.fetch('https://www.googleapis.com/drive/v3/files/' + fileId, {
    method: 'delete',
    headers: {Authorization: 'Bearer ' + mintResult.accessToken},
    muteHttpExceptions: true
  });
  return res.getResponseCode() === 200 || res.getResponseCode() === 404; // 404 = already gone
}

// meta/vault holds vaultFolderId (see index.html's provisionVault/loadUserData) — needed here so
// runArchiveCleanup can find-or-create that user's own Vault/Deleted folder without the client
// having to separately publish it anywhere else.
function getVaultFolderIdForUser(uid){
  const result = firestoreFetch('/users/' + uid + '/meta/vault');
  if(!result.ok) return null;
  return firestoreFieldsToObject(result.json.fields).vaultFolderId || null;
}
// Per-user counterparts to index.html's own driveFindFolder/driveCreateFolder/driveFindOrCreateFolder
// — same query/create shape, just authenticated with that user's own minted Drive token
// (handleMint) instead of the browser's live OAuth session, since this runs from the daily trigger
// with no user present at all.
function driveFindFolderForUser(uid, name, parentId, accessToken){
  const escaped = name.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  const parentClause = parentId ? ("'" + parentId + "' in parents") : "'root' in parents";
  const q = encodeURIComponent(parentClause + " and name='" + escaped + "' and mimeType='application/vnd.google-apps.folder' and trashed=false");
  const res = UrlFetchApp.fetch('https://www.googleapis.com/drive/v3/files?q=' + q + '&fields=files(id)', {
    headers: {Authorization: 'Bearer ' + accessToken},
    muteHttpExceptions: true
  });
  if(res.getResponseCode() !== 200) return null;
  let json;
  try{ json = JSON.parse(res.getContentText()); } catch(err){ return null; }
  return (json.files && json.files.length) ? json.files[0].id : null;
}
function driveCreateFolderForUser(name, parentId, accessToken){
  const body = {name: name, mimeType: 'application/vnd.google-apps.folder'};
  if(parentId) body.parents = [parentId];
  const res = UrlFetchApp.fetch('https://www.googleapis.com/drive/v3/files', {
    method: 'post',
    contentType: 'application/json',
    headers: {Authorization: 'Bearer ' + accessToken},
    payload: JSON.stringify(body),
    muteHttpExceptions: true
  });
  if(res.getResponseCode() !== 200) return null;
  let json;
  try{ json = JSON.parse(res.getContentText()); } catch(err){ return null; }
  return json.id;
}
function driveFindOrCreateFolderForUser(uid, name, parentId){
  const mintResult = handleMint(uid);
  if(mintResult.error) return null;
  const existing = driveFindFolderForUser(uid, name, parentId, mintResult.accessToken);
  return existing || driveCreateFolderForUser(name, parentId, mintResult.accessToken);
}
// Moves a file to a new parent, removing whatever parent(s) it actually has right now (fetched
// fresh rather than assumed) — avoids needing a separate category-id-to-Drive-folder-id lookup
// just to know what to remove.
function driveMoveFileForUser(uid, fileId, toParentId){
  const mintResult = handleMint(uid);
  if(mintResult.error) return false;
  const token = mintResult.accessToken;
  const getRes = UrlFetchApp.fetch('https://www.googleapis.com/drive/v3/files/' + fileId + '?fields=parents', {
    headers: {Authorization: 'Bearer ' + token},
    muteHttpExceptions: true
  });
  if(getRes.getResponseCode() !== 200) return false;
  let getJson;
  try{ getJson = JSON.parse(getRes.getContentText()); } catch(err){ return false; }
  const removeParents = (getJson.parents || []).join(',');
  const moveUrl = 'https://www.googleapis.com/drive/v3/files/' + fileId + '?addParents=' + toParentId
    + (removeParents ? '&removeParents=' + encodeURIComponent(removeParents) : '');
  const moveRes = UrlFetchApp.fetch(moveUrl, {
    method: 'patch',
    contentType: 'application/json',
    headers: {Authorization: 'Bearer ' + token},
    payload: JSON.stringify({}),
    muteHttpExceptions: true
  });
  return moveRes.getResponseCode() === 200;
}

// Moves an overdue-archived document into Vault/Deleted and marks deletedAt, rather than deleting
// it outright — the same 30-day trash window a manual delete from the app gives (see
// confirmDeleteDocument in index.html), so this feature can't surprise anyone with an unrecoverable
// deletion just because they turned a setting on. runTrashCleanup() below is what actually purges
// it for good, once TRASH_RETENTION_DAYS have passed since THIS move (deletedAt), not since the
// original archivedAt.
function runArchiveCleanup(){
  const subscribers = listArchiveRetentionSubscribers();
  let moved = 0;
  subscribers.forEach(function(sub){
    try{
      const overdue = listArchivedDocumentsForUser(sub.uid).filter(function(doc){
        return daysSinceIso(doc.archivedAt) >= sub.archiveRetentionDays;
      });
      if(!overdue.length) return;
      const vaultFolderId = getVaultFolderIdForUser(sub.uid);
      if(!vaultFolderId){
        console.error('Archive cleanup: no vaultFolderId on file for uid ' + sub.uid + ' — skipping');
        return;
      }
      const deletedFolderId = driveFindOrCreateFolderForUser(sub.uid, 'Deleted', vaultFolderId);
      if(!deletedFolderId){
        console.error('Archive cleanup: could not find/create the Deleted folder for uid ' + sub.uid);
        return;
      }
      overdue.forEach(function(doc){
        try{
          const deletedAt = new Date().toISOString();
          if(doc.driveFileId) driveMoveFileForUser(sub.uid, doc.driveFileId, deletedFolderId);
          firestoreWrite('/users/' + sub.uid + '/documents/' + doc.id, {deletedAt: deletedAt}, true);
          firestoreWrite('/trashSubscribers/' + sub.uid, {uid: sub.uid, updatedAt: deletedAt}, false);
          moved++;
        } catch(err){
          console.error('Archive cleanup: failed to move document ' + doc.id + ' for uid ' + sub.uid + ' to trash: ' + err);
        }
      });
    } catch(err){
      // One user's bad data or a transient failure must not abort everyone else's cleanup.
      console.error('Archive cleanup failed for uid ' + sub.uid + ': ' + err);
    }
  });
  console.log('Archive cleanup: moved ' + moved + ' document(s) to trash across ' + subscribers.length + ' subscriber(s) with retention set.');
}

// ---------- Trash (Recently deleted) permanent purge ----------
//
// Mirrors the other subscriber-registry jobs above: trashSubscribers/{uid} exists for any account
// with at least one soft-deleted document, written directly by the client (confirmDeleteDocument)
// or by runArchiveCleanup above — either path into "Recently deleted" gets the same eventual purge.
// Unlike archiveRetentionSubscribers, this isn't opt-in/configurable — every soft-delete already
// implies "yes, purge this once its time is up," so there's no separate retention-days field to
// read here, just TRASH_RETENTION_DAYS (keep this in sync with index.html's own constant of the
// same name).
const TRASH_RETENTION_DAYS = 30;

function listTrashSubscribers(){
  return firestoreListAll('trashSubscribers').map(function(d){ return d.name.split('/').pop(); });
}

function listDeletedDocumentsForUser(uid){
  return firestoreListAll('users/' + uid + '/documents')
    .map(function(d){
      const obj = firestoreFieldsToObject(d.fields);
      obj.id = d.name.split('/').pop();
      return obj;
    })
    .filter(function(doc){ return !!doc.deletedAt; });
}

function runTrashCleanup(){
  const uids = listTrashSubscribers();
  let purged = 0;
  uids.forEach(function(uid){
    try{
      const expired = listDeletedDocumentsForUser(uid).filter(function(doc){
        return daysSinceIso(doc.deletedAt) >= TRASH_RETENTION_DAYS;
      });
      expired.forEach(function(doc){
        try{
          if(doc.driveFileId) driveDeleteFileForUser(uid, doc.driveFileId);
          firestoreDelete('/users/' + uid + '/documents/' + doc.id);
          purged++;
        } catch(err){
          console.error('Trash cleanup: failed to purge document ' + doc.id + ' for uid ' + uid + ': ' + err);
        }
      });
    } catch(err){
      // One user's bad data or a transient failure must not abort everyone else's cleanup.
      console.error('Trash cleanup failed for uid ' + uid + ': ' + err);
    }
  });
  console.log('Trash cleanup: permanently deleted ' + purged + ' document(s) across ' + uids.length + ' subscriber(s) with items in trash.');
}

// Single entry point for the existing daily trigger (see createDailyDigestTrigger below) — email,
// push, and archive-cleanup subscribers are all independent, independently-toggled sets, so this
// fans out to all three rather than needing more triggers (which would re-risk the
// duplicate-trigger footgun createDailyDigestTrigger already guards against, for extra manual
// setup+consent cycles with no real benefit). Each one's own try/catch keeps a failure in one from
// taking down the others.
function runDailyDigest(){
  try{ sendEmailDigests(); } catch(err){ console.error('sendEmailDigests failed: ' + err); }
  try{ sendPushReminders(); } catch(err){ console.error('sendPushReminders failed: ' + err); }
  try{ runArchiveCleanup(); } catch(err){ console.error('runArchiveCleanup failed: ' + err); }
  try{ runTrashCleanup(); } catch(err){ console.error('runTrashCleanup failed: ' + err); }
}

// One-off setup — run manually, once, from the Apps Script editor. Never called from doPost.
// Apps Script does not prevent duplicate triggers, and a duplicate would silently double-send
// every digest forever with no visible error, hence the existence check.
function createDailyDigestTrigger(){
  const existing = ScriptApp.getProjectTriggers().filter(function(t){
    return t.getHandlerFunction() === 'runDailyDigest';
  });
  if(existing.length > 0){
    Logger.log('runDailyDigest trigger already exists (' + existing.length + ') — not creating another.');
    return;
  }
  ScriptApp.newTrigger('runDailyDigest').timeBased().everyDays(1).atHour(8).create();
  Logger.log('Created daily trigger for runDailyDigest at ~8am ' + Session.getScriptTimeZone());
}
