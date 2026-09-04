import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import nodemailer from 'nodemailer';
import { createClient } from '@supabase/supabase-js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const required = ['SUPABASE_URL','SUPABASE_SERVICE_ROLE_KEY','SMTP_HOST','SMTP_PORT','SMTP_USER','SMTP_PASSWORD','MAIL_FROM'];
for (const key of required) {
  if (!process.env[key]) { console.error(`Missing environment variable: ${key}`); process.exit(1); }
}

const app = express();
const port = Number(process.env.PORT || 10000);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../..');

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ crossOriginEmbedderPolicy: false, contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));

const emailLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: String(process.env.SMTP_SECURE || 'true').toLowerCase() === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD }
});
const escapeHtml = (value = '') => String(value)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

async function getAuthenticatedUser(req) {
  const authorization = req.headers.authorization || '';
  if (!authorization.startsWith('Bearer ')) return null;
  const token = authorization.slice(7).trim();
  if (!token) return null;
  const { data, error } = await supabaseAdmin.auth.getUser(token);
  return error ? null : data?.user || null;
}

app.get('/health', (_req, res) => res.json({ ok: true, service: 'finverocapital' }));

app.post('/api/emails/application-confirmation', emailLimiter, async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);
    if (!user) return res.status(401).json({ error: 'Invalid user session.' });
    const applicationId = String(req.body?.applicationId || '').trim();
    if (!applicationId) return res.status(400).json({ error: 'applicationId is required.' });

    const { data: application, error: applicationError } = await supabaseAdmin
      .from('applications')
      .select('id,user_id,tracking_number,amount_requested,duration_months,monthly_payment,email')
      .eq('id', applicationId).eq('user_id', user.id).single();
    if (applicationError || !application) return res.status(404).json({ error: 'Application not found.' });

    const { data: profile } = await supabaseAdmin.from('profiles')
      .select('full_name,gender').eq('id', user.id).maybeSingle();
    const recipient = application.email || user.email;
    if (!recipient) return res.status(400).json({ error: 'Recipient email is missing.' });

    const gender = profile?.gender === 'Mme' ? 'Mme' : 'M.';
    const name = profile?.full_name || user.user_metadata?.full_name || 'Client';
    const tracking = application.tracking_number || application.id;
    const amount = Number(application.amount_requested).toLocaleString('fr-FR');
    const monthly = Number(application.monthly_payment).toLocaleString('fr-FR', { minimumFractionDigits: 2 });
    const subject = `Confirmation de votre demande Finvero Capital — ${tracking}`;
    const text = `Bonjour ${gender} ${name},\n\nVotre demande a bien été enregistrée sur Finvero Capital.\nNuméro de suivi : ${tracking}\nMontant demandé : ${amount} €\nDurée : ${application.duration_months} mois\nMensualité estimée : ${monthly} €\n\nVous pouvez vous connecter à votre compte sur https://finverocapital.de/ pour suivre son évolution.\n\nCordialement,\nFinvero Capital`;
    const html = `<!doctype html><html lang="fr"><body style="margin:0;background:#f4f6f8;font-family:Arial,sans-serif;color:#172033"><div style="max-width:620px;margin:30px auto;background:#fff;border-radius:14px;padding:28px"><h1>Finvero Capital</h1><p>Bonjour ${escapeHtml(gender)} ${escapeHtml(name)},</p><p>Votre demande a bien été enregistrée.</p><div style="background:#f4f6f8;border-radius:10px;padding:18px"><p><strong>Numéro de suivi :</strong> ${escapeHtml(tracking)}</p><p><strong>Montant demandé :</strong> ${amount} €</p><p><strong>Durée :</strong> ${escapeHtml(application.duration_months)} mois</p><p><strong>Mensualité :</strong> ${monthly} €</p></div><p>Connectez-vous à votre compte Finvero Capital pour suivre l’évolution de votre demande.</p><p><a href="https://finverocapital.de/">https://finverocapital.de/</a></p><p>Cordialement,<br>Finvero Capital</p></div></body></html>`;
    const info = await transporter.sendMail({ from: process.env.MAIL_FROM, to: recipient, subject, text, html });
    console.log(`Application email sent: ${recipient} (${info.messageId})`);
    return res.json({ ok: true, messageId: info.messageId });
  } catch (error) {
    console.error('Application email error:', error);
    return res.status(500).json({ error: 'Internal email service error.' });
  }
});

app.use((req, res, next) => {
  if (req.path.startsWith('/api/') || req.path === '/health') return next();
  res.sendFile(path.join(projectRoot, 'index.html'));
});

app.listen(port, '0.0.0.0', async () => {
  console.log(`Finvero Capital server listening on port ${port}`);
  try { await transporter.verify(); console.log('SMTP verification succeeded.'); }
  catch (error) { console.error('SMTP verification failed:', error.message); }
});
