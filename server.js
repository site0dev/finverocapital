import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import nodemailer from 'nodemailer';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createClient } from '@supabase/supabase-js';

const required = [
  'SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY',
  'SMTP_HOST',
  'SMTP_PORT',
  'SMTP_USER',
  'SMTP_PASSWORD',
  'MAIL_FROM'
];
for (const name of required) if (!process.env[name]) throw new Error(`Missing environment variable: ${name}`);

const app = express();
const port = Number(process.env.PORT || 10000);
const __filename = fileURLToPath(import.meta.url);
const projectRoot = path.dirname(__filename);

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ crossOriginEmbedderPolicy: false, contentSecurityPolicy: false }));
app.use(express.json({ limit: '300kb' }));

const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: String(process.env.SMTP_SECURE || 'true').toLowerCase() === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD }
});

const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false });
const loginLimiter = rateLimit({ windowMs: 15 * 15 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
app.use('/api/admin', apiLimiter);

function hashToken(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function createToken() { return crypto.randomBytes(32).toString('hex'); }
function clean(value, max = 500) { return value == null ? null : String(value).trim().slice(0, max); }
function positiveAmount(value) { const n = Number(value); return Number.isFinite(n) && n > 0 ? n : null; }
function escapeHtml(value) { return String(value).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;'); }

async function getAdminSession(req) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7).trim();
  if (!token) return null;

  const tokenHash = hashToken(token);
  const { data: session, error: sessionError } = await supabaseAdmin
    .from('admin_sessions')
    .select('token, admin_user_id, expires_at, last_used')
    .eq('token_hash', tokenHash)
    .gt('expires_at', new Date().toISOString())
    .maybeSingle();

  if (sessionError || !session) return null;

  const { data: admin, error: adminError } = await supabaseAdmin
    .from('admin_users')
    .select('id, username, active')
    .eq('id', session.admin_user_id)
    .maybeSingle();

  if (adminError || !admin || !admin.active) return null;

  await supabaseAdmin.from('admin_sessions').update({ last_used: new Date().toISOString() }).eq('token_hash', tokenHash);
  return { token, tokenHash, session, admin };
}

function requireAdmin(req, res, next) {
  getAdminSession(req).then(session => {
    if (!session) return res.status(401).json({ ok:false, error:'Session administrateur invalide ou expirée.' });
    req.adminSession = session;
    next();
  }).catch(error => {
    console.error('Admin session error:', error);
    res.status(500).json({ ok:false, error:'Impossible de vérifier la session administrateur.' });
  });
}

app.get('/health', (_req, res) => res.json({ ok:true, service:'finverocapital' }));

// ---------- ADMINISTRATION : authentification ----------
app.post('/api/admin/login', loginLimiter, async (req, res) => {
  try {
    const username = clean(req.body?.username, 80);
    const password = String(req.body?.password || '');
    if (!username || !password) return res.status(400).json({ ok:false, error:'Identifiants requis.' });

    const { data: admin, error } = await supabaseAdmin
      .from('admin_users')
      .select('id, username, password_hash, active')
      .ilike('username', username)
      .maybeSingle();

    if (error) throw error;
    if (!admin || !admin.active || !admin.password_hash) return res.status(401).json({ ok:false, error:'Identifiants invalides.' });

    const valid = await bcrypt.compare(password, admin.password_hash);
    if (!valid) return res.status(401).json({ ok:false, error:'Identifiants invalides.' });

    const token = createToken();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    const { error: insertError } = await supabaseAdmin.from('admin_sessions').insert({
      admin_user_id: admin.id,
      token_hash: hashToken(token),
      expires_at: expiresAt,
      last_used: new Date().toISOString()
    });
    if (insertError) throw insertError;

    res.json({ ok:true, token, username:admin.username, expires_at:expiresAt });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ ok:false, error:'Connexion administrateur impossible.' });
  }
});

app.get('/api/admin/session', requireAdmin, (req, res) => {
  res.json({ ok:true, username:req.adminSession.admin.username, expires_at:req.adminSession.session.expires_at });
});

app.post('/api/admin/logout', requireAdmin, async (req, res) => {
  await supabaseAdmin.from('admin_sessions').delete().eq('token_hash', req.adminSession.tokenHash);
  res.json({ ok:true });
});

// ---------- ADMINISTRATION : lecture réelle Supabase ----------
app.get('/api/admin/clients', requireAdmin, async (_req, res) => {
  try {
    const [{ data: profiles, error: profilesError }, { data: applications, error: applicationsError }] = await Promise.all([
      supabaseAdmin.from('profiles').select('*').order('created_at', { ascending:false }),
      supabaseAdmin.from('applications').select('*').order('created_at', { ascending:false })
    ]);
    if (profilesError) throw profilesError;
    if (applicationsError) throw applicationsError;

    const latestByUser = new Map();
    for (const a of applications || []) if (!latestByUser.has(a.user_id)) latestByUser.set(a.user_id, a);

    const clients = (profiles || []).map(p => {
      const a = latestByUser.get(p.id) || null;
      return {
        user_id:p.id,
        full_name:p.full_name || '',
        email:p.email || '',
        phone:p.phone || '',
        gender:p.gender || '',
        country:p.country || '',
        currency:p.currency || 'EUR',
        balance:Number(p.balance || 0),
        account_status:p.account_status || 'active',
        application_id:a?.id || null,
        tracking_number:a?.tracking_number || null,
        amount_requested:a?.amount_requested ?? null,
        duration_months:a?.duration_months ?? null,
        application_status:a?.status || null,
        application_updated_at:a?.updated_at || a?.created_at || null
      };
    });
    res.json({ ok:true, clients });
  } catch (error) {
    console.error('Admin clients error:', error);
    res.status(500).json({ ok:false, error:'Impossible de charger les clients.' });
  }
});

app.get('/api/admin/clients/:userId/transactions', requireAdmin, async (req, res) => {
  const userId = req.params.userId;
  const { data, error } = await supabaseAdmin.from('wallet_transactions').select('*').eq('user_id', userId).order('created_at', { ascending:false }).limit(200);
  if (error) return res.status(500).json({ ok:false, error:'Impossible de charger les mouvements.' });
  res.json({ ok:true, transactions:data || [] });
});

// Modification réelle du profil/statut dans Supabase.
app.patch('/api/admin/clients/:userId', requireAdmin, async (req, res) => {
  try {
    const allowed = {};
    for (const key of ['full_name','phone','gender','country','account_status']) {
      if (req.body && Object.prototype.hasOwnProperty.call(req.body, key)) allowed[key] = clean(req.body[key], 200);
    }
    if (allowed.account_status && !['active','pending','suspended','blocked'].includes(allowed.account_status)) {
      return res.status(400).json({ ok:false, error:'Statut de compte invalide.' });
    }
    if (!Object.keys(allowed).length) return res.status(400).json({ ok:false, error:'Aucune modification fournie.' });
    const { data, error } = await supabaseAdmin.from('profiles').update(allowed).eq('id', req.params.userId).select('*').maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ ok:false, error:'Client introuvable.' });
    res.json({ ok:true, profile:data });
  } catch (error) {
    console.error('Admin client update error:', error);
    res.status(500).json({ ok:false, error:'Impossible de modifier le client.' });
  }
});

// Crédit/débit : on conserve les RPC existantes pour leur logique transactionnelle.
app.post('/api/admin/credit', requireAdmin, async (req, res) => {
  const amount = positiveAmount(req.body?.amount);
  if (!amount) return res.status(400).json({ ok:false, error:'Montant invalide.' });
  const { data, error } = await supabaseAdmin.rpc('admin_credit_account', {
    p_token:req.adminSession.token,
    p_user_id:req.body?.userId,
    p_amount:amount,
    p_note:clean(req.body?.note,200),
    p_reference:clean(req.body?.reference,100)
  });
  if (error) return res.status(400).json({ ok:false, error:error.message });
  res.json({ ok:true, balance:Number(data) });
});

app.post('/api/admin/debit', requireAdmin, async (req, res) => {
  const amount = positiveAmount(req.body?.amount);
  if (!amount) return res.status(400).json({ ok:false, error:'Montant invalide.' });
  const { data, error } = await supabaseAdmin.rpc('admin_debit_account', {
    p_token:req.adminSession.token,
    p_user_id:req.body?.userId,
    p_amount:amount,
    p_note:clean(req.body?.note,200),
    p_reference:clean(req.body?.reference,100)
  });
  if (error) return res.status(400).json({ ok:false, error:error.message });
  res.json({ ok:true, balance:Number(data) });
});

// ---------- ADMINISTRATION : paramètres ----------
app.get('/api/admin/settings', requireAdmin, async (req, res) => {
  res.json({ ok:true, username:req.adminSession.admin.username });
});

app.patch('/api/admin/settings', requireAdmin, async (req, res) => {
  try {
    const username = clean(req.body?.username, 80);
    const password = req.body?.password ? String(req.body.password) : '';
    if (!username) return res.status(400).json({ ok:false, error:'Nom d’utilisateur requis.' });

    const changes = { username };
    if (password) changes.password_hash = await bcrypt.hash(password, 12);

    const { data, error } = await supabaseAdmin.from('admin_users').update(changes).eq('id', req.adminSession.admin.id).select('id, username, active').maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ ok:false, error:'Compte administrateur introuvable.' });

    if (password) await supabaseAdmin.from('admin_sessions').delete().eq('admin_user_id', req.adminSession.admin.id);
    res.json({ ok:true, username:data.username, session_revoked:Boolean(password) });
  } catch (error) {
    console.error('Admin settings error:', error);
    res.status(500).json({ ok:false, error:'Impossible d’enregistrer les paramètres.' });
  }
});

// ---------- EMAIL CLIENT ----------
app.post('/api/emails/application-confirmation', async (req, res) => {
  try {
    const authorization = req.headers.authorization || '';
    if (!authorization.startsWith('Bearer ')) return res.status(401).json({ ok:false, error:'Authentication required' });
    const accessToken = authorization.slice(7).trim();
    const { data:userData, error:userError } = await supabaseAdmin.auth.getUser(accessToken);
    if (userError || !userData?.user) return res.status(401).json({ ok:false, error:'Authentication required' });

    const applicationId = req.body?.applicationId;
    if (!applicationId) return res.status(400).json({ ok:false, error:'applicationId is required' });
    const { data:application, error:applicationError } = await supabaseAdmin.from('applications').select('id,user_id,tracking_number,email,amount_requested,duration_months,monthly_payment,status').eq('id',applicationId).eq('user_id',userData.user.id).maybeSingle();
    if (applicationError) throw applicationError;
    if (!application) return res.status(404).json({ ok:false, error:'Application not found' });

    const { data:profile } = await supabaseAdmin.from('profiles').select('full_name,gender').eq('id',userData.user.id).maybeSingle();
    const salutation = `${profile?.gender === 'Mme' ? 'Mme' : 'M.'} ${profile?.full_name || userData.user.user_metadata?.full_name || 'Client'}`.trim();
    const recipient = application.email || userData.user.email;
    if (!recipient) return res.status(400).json({ ok:false, error:'No recipient email address' });
    const amount = Number(application.amount_requested || 0).toLocaleString('fr-FR',{minimumFractionDigits:2,maximumFractionDigits:2});
    const monthly = Number(application.monthly_payment || 0).toLocaleString('fr-FR',{minimumFractionDigits:2,maximumFractionDigits:2});
    const subject = `Confirmation de votre demande de crédit — ${application.tracking_number}`;
    const text = [`Bonjour ${salutation},`,'','Votre demande de crédit a bien été enregistrée.','',`Numéro de suivi : ${application.tracking_number}`,`Montant demandé : ${amount} €`,`Durée : ${application.duration_months} mois`,`Mensualité estimée : ${monthly} €`,`Statut : ${application.status || 'Application submitted'}`,'','Vous pouvez vous connecter à votre espace personnel pour suivre l’évolution de votre demande.','','Finvero Capital'].join('\n');
    const html = `<div style="font-family:Arial,sans-serif;line-height:1.6;color:#222"><h2>Finvero Capital</h2><p>Bonjour ${escapeHtml(salutation)},</p><p>Votre demande de crédit a bien été enregistrée.</p><p><strong>Numéro de suivi :</strong> ${escapeHtml(application.tracking_number || '')}<br><strong>Montant demandé :</strong> ${escapeHtml(amount)} €<br><strong>Durée :</strong> ${escapeHtml(String(application.duration_months || ''))} mois<br><strong>Mensualité estimée :</strong> ${escapeHtml(monthly)} €<br><strong>Statut :</strong> ${escapeHtml(application.status || 'Application submitted')}</p><p>Vous pouvez vous connecter à votre espace personnel pour suivre l’évolution de votre demande.</p><p><strong>Finvero Capital</strong></p></div>`;
    await transporter.sendMail({ from:process.env.MAIL_FROM, to:recipient, subject, text, html });
    res.json({ ok:true });
  } catch (error) {
    console.error('Email sending error:', error);
    res.status(500).json({ ok:false, error:'Unable to send email' });
  }
});

// ---------- FICHIERS DU SITE ----------
app.get('/', (_req,res) => res.sendFile(path.join(projectRoot,'index.html')));
app.use(express.static(projectRoot, { index:false, dotfiles:'ignore', maxAge:'1h' }));
app.use((req,res,next) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ ok:false, error:'API route not found' });
  res.sendFile(path.join(projectRoot,'index.html'), error => error && next(error));
});
app.use((error,_req,res,_next) => {
  console.error('Server error:', error);
  if (res.headersSent) return;
  res.status(500).json({ ok:false, error:'Internal server error' });
});

app.listen(port,'0.0.0.0',async()=>{
  console.log(`Finvero Capital server listening on port ${port}`);
  try { await transporter.verify(); console.log('SMTP connection verified successfully.'); }
  catch(error) { console.error('SMTP verification failed:',error.message); }
});
