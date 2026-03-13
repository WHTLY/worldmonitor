import { validateApiKey } from './_api-key.js';

export const config = { runtime: 'edge' };

export default async function handler(req) {
  const result = validateApiKey(req);
  const payload = {
    nodeEnv: process.env.NODE_ENV || '',
    publicWebApi: process.env.WORLDMONITOR_PUBLIC_WEB_API || '',
    url: req.url,
    headers: {
      origin: req.headers.get('origin') || '',
      referer: req.headers.get('referer') || '',
      host: req.headers.get('host') || '',
      xForwardedHost: req.headers.get('x-forwarded-host') || '',
      secFetchSite: req.headers.get('sec-fetch-site') || '',
      secFetchMode: req.headers.get('sec-fetch-mode') || '',
      userAgent: req.headers.get('user-agent') || '',
    },
    validateApiKey: result,
  };

  return new Response(JSON.stringify(payload, null, 2), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
    },
  });
}
