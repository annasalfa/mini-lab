import express from 'express'
import { generateKeyPair, exportJWK, SignJWT } from 'jose'
const ISSUER = process.env.ISSUER || 'http://auth:8080'
const AUDIENCE = process.env.AUDIENCE || 'graphql-api'
const PORT = Number(process.env.PORT || 8080)
let keyPair, kid, publicJwk
async function setupKeys(){ keyPair = await generateKeyPair('RS256'); publicJwk = await exportJWK(keyPair.publicKey); kid = Math.random().toString(36).slice(2); publicJwk.kid = kid; publicJwk.alg = 'RS256' }
const app = express(); app.use(express.json())
app.get('/.well-known/jwks.json', async (_req, res) => res.json({ keys: [publicJwk] }))
app.get('/token', async (req, res) => {
  try {
    const sub = req.query.sub || 'user-123'
    const tenantId = req.query.tenantId || '11111111-1111-1111-1111-111111111111'
    const scope = (req.query.scope || 'secret:read secret:write').toString()
    const now = Math.floor(Date.now()/1000)
    const jwt = await new SignJWT({ scope, tenantId })
      .setProtectedHeader({ alg:'RS256', kid })
      .setIssuedAt(now).setIssuer(ISSUER).setAudience(AUDIENCE)
      .setExpirationTime('15m').setSubject(sub.toString())
      .sign(keyPair.privateKey)
    res.json({ access_token: jwt, token_type: 'Bearer', expires_in: 900 })
  } catch (e) { console.error(e); res.status(500).json({ error: 'token_error' }) }
})
setupKeys().then(()=> app.listen(PORT, ()=> console.log(`JWKS/Token server on :${PORT}`)))
