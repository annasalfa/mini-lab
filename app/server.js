import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import bodyParser from 'body-parser'
import { ApolloServer } from '@apollo/server'
import { expressMiddleware } from '@apollo/server/express4'
import { Pool } from 'pg'
import crypto from 'node:crypto'
import { createRemoteJWKSet, jwtVerify } from 'jose'

const PORT = Number(process.env.PORT || 4000)
const DATABASE_URL = process.env.DATABASE_URL
const VAULT_ADDR = process.env.VAULT_ADDR || 'http://vault:8200'
const VAULT_TOKEN = process.env.VAULT_TOKEN || 'root'
const TRANSIT_KEY_NAME = process.env.TRANSIT_KEY_NAME || 'sek'
const AUTH_ISSUER = process.env.AUTH_ISSUER || 'http://auth:8080'
const AUTH_AUDIENCE = process.env.AUTH_AUDIENCE || 'graphql-api'
const JWKS_URL = process.env.JWKS_URL || 'http://auth:8080/.well-known/jwks.json'

const pool = new Pool({ connectionString: DATABASE_URL })
const jwks = createRemoteJWKSet(new URL(JWKS_URL))

const typeDefs = `#graphql
  type SecretMeta { id: ID!, tenantId: ID!, ownerId: ID!, createdAt: String! }
  type Query { ping: String!, getSecretMeta(id: ID!): SecretMeta, revealSecret(id: ID!): String! }
  type Mutation { storeSecret(tenantId: ID!, ownerId: ID!, plaintext: String!): SecretMeta! }
`

const resolvers = {
  Query: {
    ping: () => "pong",
    getSecretMeta: async (_p, { id }, ctx) => { const row = await getRow(id); enforceOwnership(ctx, row); return toMeta(row) },
    revealSecret: async (_p, { id }, ctx) => {
      const row = await getRow(id); enforceOwnership(ctx, row); needScope(ctx, 'secret:read')
      const dek = await unwrapDEK(row.wrapped_dek)
      const plaintext = decryptAESGCM(dek, row.iv, row.tag, row.ciphertext, { tenantId: row.tenant_id, ownerId: row.owner_id, recordId: row.id, keyId: row.key_id })
      return plaintext.toString('utf8')
    }
  },
  Mutation: {
    storeSecret: async (_p, { tenantId, ownerId, plaintext }, ctx) => {
      needScope(ctx, 'secret:write'); if (ctx.user.tenantId !== tenantId) throw new Error('cross-tenant denied')
      const recordId = crypto.randomUUID(); const dek = crypto.randomBytes(32)
      const { iv, ciphertext, tag } = encryptAESGCM(dek, Buffer.from(plaintext, 'utf8'), { tenantId, ownerId, recordId, keyId: TRANSIT_KEY_NAME })
      const { wrapped, key_version } = await wrapDEK(dek)
      const row = await insertRow({ id: recordId, tenant_id: tenantId, owner_id: ownerId, key_id: TRANSIT_KEY_NAME, key_version, wrapped_dek: wrapped, iv, tag, ciphertext })
      return toMeta(row)
    }
  }
}

function toMeta(row){ return { id: row.id, tenantId: row.tenant_id, ownerId: row.owner_id, createdAt: row.created_at.toISOString() } }

async function getRow(id){ const { rows } = await pool.query('SELECT * FROM secrets WHERE id = $1', [id]); if (rows.length === 0) throw new Error('not_found'); return rows[0] }
async function insertRow(row){
  const res = await pool.query(`INSERT INTO secrets (id, tenant_id, owner_id, key_id, key_version, wrapped_dek, iv, tag, ciphertext) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [row.id, row.tenant_id, row.owner_id, row.key_id, row.key_version, row.wrapped_dek, row.iv, row.tag, row.ciphertext]); return res.rows[0] }

function encryptAESGCM(key, plaintextBuf, aadObj){ const iv = crypto.randomBytes(12); const cipher = crypto.createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(Buffer.from(JSON.stringify(aadObj))); const ciphertext = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]); const tag = cipher.getAuthTag(); return { iv, ciphertext, tag } }
function decryptAESGCM(key, iv, tag, ciphertext, aadObj){ const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv); decipher.setAAD(Buffer.from(JSON.stringify(aadObj))); decipher.setAuthTag(tag); return Buffer.concat([decipher.update(ciphertext), decipher.final()]) }

async function wrapDEK(dek){
  const payload = { plaintext: Buffer.from(dek).toString('base64') }
  const r = await fetch(`${VAULT_ADDR}/v1/transit/encrypt/${TRANSIT_KEY_NAME}`, { method:'POST', headers:{'X-Vault-Token':VAULT_TOKEN,'Content-Type':'application/json'}, body: JSON.stringify(payload) })
  if (!r.ok) throw new Error('vault_encrypt_failed'); const js = await r.json(); return { wrapped: js.data.ciphertext, key_version: js.data.key_version || 1 }
}
async function unwrapDEK(wrapped){
  const payload = { ciphertext: wrapped }
  const r = await fetch(`${VAULT_ADDR}/v1/transit/decrypt/${TRANSIT_KEY_NAME}`, { method:'POST', headers:{'X-Vault-Token':VAULT_TOKEN,'Content-Type':'application/json'}, body: JSON.stringify(payload) })
  if (!r.ok) throw new Error('vault_decrypt_failed'); const js = await r.json(); return Buffer.from(js.data.plaintext, 'base64')
}

async function authMiddleware(req, _res, next){
  try{
    const auth = req.headers['authorization'] || ''
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null
    if (!token) throw new Error('missing_token')
    const { payload } = await jwtVerify(token, jwks, { issuer: AUTH_ISSUER, audience: AUTH_AUDIENCE })
    req.user = { sub: payload.subject || payload.sub, scope: payload.scope || '', tenantId: payload.tenantId }
    return next()
  } catch(e){ return next(e) }
}
function needScope(ctx, s){ const scopes = (ctx.user.scope || '').split(/\s+/); if (!scopes.includes(s)) throw new Error('insufficient_scope') }
function enforceOwnership(ctx, row){ if (ctx.user.tenantId !== row.tenant_id) throw new Error('cross-tenant denied') }

const app = express(); app.use(cors()); app.use('/graphql', bodyParser.json(), authMiddleware)
const server = new ApolloServer({ typeDefs, resolvers }); await server.start()
app.use('/graphql', expressMiddleware(server, { context: async ({ req }) => ({ user: req.user }) }))
app.get('/healthz', (_req,res)=>res.json({ok:true})); app.listen(PORT, ()=> console.log(`GraphQL API on :${PORT}/graphql`))
