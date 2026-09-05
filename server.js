import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import nodemailer from 'nodemailer';
import { createClient } from '@supabase/supabase-js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const required = [
  'SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY',
  'SMTP_HOST',
  'SMTP_PORT',
  'SMTP_USER',
  'SMTP_PASSWORD',
  'MAIL_FROM'
];

for (const name of required) {
  if (!process.env[name]) {
    throw new Error(`Missing environment variable: ${name}`);
  }
}

const app = express();
const port = Number(process.env.PORT || 10000);

const __filename = fileURLToPath(import.meta.url);
const projectRoot = path.dirname(__filename);

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: false
  })
);

app.use(express.json({ limit: '200kb' }));

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  }
);

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure:
    String(process.env.SMTP_SECURE || 'true').toLowerCase() === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD
  }
});

const emailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false
});

async function getAuthenticatedUser(req) {
  const authorization = req.headers.authorization || '';

  if (!authorization.startsWith('Bearer ')) {
    return null;
  }

  const token = authorization.slice(7).trim();

  if (!token) {
    return null;
  }

  const { data, error } =
    await supabaseAdmin.auth.getUser(token);

  if (error || !data?.user) {
    return null;
  }

  return data.user;
}

/* =========================
   HEALTH CHECK
========================= */

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'finverocapital'
  });
});

/* =========================
   EMAIL DE CONFIRMATION
========================= */

app.post(
  '/api/emails/application-confirmation',
  emailLimiter,
  async (req, res) => {
    try {
      const user = await getAuthenticatedUser(req);

      if (!user) {
        return res.status(401).json({
          ok: false,
          error: 'Authentication required'
        });
      }

      const { applicationId } = req.body || {};

      if (!applicationId) {
        return res.status(400).json({
          ok: false,
          error: 'applicationId is required'
        });
      }

      const { data: application, error: applicationError } =
        await supabaseAdmin
          .from('applications')
          .select(
            'id, user_id, tracking_number, email, amount_requested, duration_months, monthly_payment, status'
          )
          .eq('id', applicationId)
          .eq('user_id', user.id)
          .maybeSingle();

      if (applicationError) {
        console.error(
          'Application lookup error:',
          applicationError
        );

        return res.status(500).json({
          ok: false,
          error: 'Unable to retrieve application'
        });
      }

      if (!application) {
        return res.status(404).json({
          ok: false,
          error: 'Application not found'
        });
      }

      const { data: profile } =
        await supabaseAdmin
          .from('profiles')
          .select('full_name, gender')
          .eq('id', user.id)
          .maybeSingle();

      const userName =
        profile?.full_name ||
        user.user_metadata?.full_name ||
        'Client';

      const gender =
        profile?.gender === 'Mme'
          ? 'Mme'
          : 'Mr';

      const salutation =
        `${gender} ${userName}`.trim();

      const recipient =
        application.email || user.email;

      if (!recipient) {
        return res.status(400).json({
          ok: false,
          error: 'No recipient email address'
        });
      }

      const amount =
        Number(
          application.amount_requested || 0
        ).toLocaleString('fr-FR', {
          minimumFractionDigits: 2,
          maximumFractionDigits: 2
        });

      const monthly =
        Number(
          application.monthly_payment || 0
        ).toLocaleString('fr-FR', {
          minimumFractionDigits: 2,
          maximumFractionDigits: 2
        });

      const subject =
        `Confirmation de votre demande de crédit — ${application.tracking_number}`;

      const text = [
        `Bonjour ${salutation},`,
        '',
        'Votre demande de crédit a bien été enregistrée.',
        '',
        `Numéro de suivi : ${application.tracking_number}`,
        `Montant demandé : ${amount} €`,
        `Durée : ${application.duration_months} mois`,
        `Mensualité estimée : ${monthly} €`,
        `Statut : ${
          application.status ||
          'Application submitted'
        }`,
        '',
        'Vous pouvez vous connecter à votre espace personnel pour suivre l’évolution de votre demande.',
        '',
        'Finvero Capital'
      ].join('\n');

      const html = `
        <div style="font-family:Arial,sans-serif;line-height:1.6;color:#222">
          <h2>Finvero Capital</h2>

          <p>
            Bonjour ${escapeHtml(salutation)},
          </p>

          <p>
            Votre demande de crédit a bien été enregistrée.
          </p>

          <p>
            <strong>Numéro de suivi :</strong>
            ${escapeHtml(
              application.tracking_number || ''
            )}
            <br>

            <strong>Montant demandé :</strong>
            ${escapeHtml(amount)} €
            <br>

            <strong>Durée :</strong>
            ${escapeHtml(
              String(
                application.duration_months || ''
              )
            )}
            mois
            <br>

            <strong>Mensualité estimée :</strong>
            ${escapeHtml(monthly)} €
            <br>

            <strong>Statut :</strong>
            ${escapeHtml(
              application.status ||
              'Application submitted'
            )}
          </p>

          <p>
            Vous pouvez vous connecter à votre espace personnel pour suivre l’évolution de votre demande.
          </p>

          <p>
            <strong>Finvero Capital</strong>
          </p>
        </div>
      `;

      await transporter.sendMail({
        from: process.env.MAIL_FROM,
        to: recipient,
        subject,
        text,
        html
      });

      return res.json({
        ok: true
      });

    } catch (error) {

      console.error(
        'Email sending error:',
        error
      );

      return res.status(500).json({
        ok: false,
        error: 'Unable to send email'
      });
    }
  }
);

/* =========================
   PAGE PRINCIPALE
========================= */

app.get('/', (_req, res) => {
  res.sendFile(
    path.join(projectRoot, 'index.html')
  );
});

/* =========================
   FICHIERS FRONTEND
========================= */

const publicAssetPattern =
  /\.(?:jpg|jpeg|png|gif|webp|svg|ico|css|js|woff2?|ttf|otf)$/i;

app.get(
  publicAssetPattern,
  (req, res, next) => {

    const requested =
      path
        .normalize(req.path)
        .replace(
          /^(\.\.[/\\])+/, 
          ''
        );

    const filePath =
      path.join(
        projectRoot,
        requested
      );

    if (
      !filePath.startsWith(
        projectRoot + path.sep
      )
    ) {
      return res.status(403).end();
    }

    res.sendFile(
      filePath,
      error => {
        if (error) {
          next(error);
        }
      }
    );
  }
);

/* =========================
   ROUTES FRONTEND
========================= */

app.use((req, res, next) => {

  if (req.path.startsWith('/api/')) {
    return res.status(404).json({
      ok: false,
      error: 'API route not found'
    });
  }

  res.sendFile(
    path.join(
      projectRoot,
      'index.html'
    ),
    error => {
      if (error) {
        next(error);
      }
    }
  );
});

/* =========================
   GESTION DES ERREURS
========================= */

app.use(
  (error, _req, res, _next) => {

    console.error(
      'Server error:',
      error
    );

    if (res.headersSent) {
      return;
    }

    res.status(500).json({
      ok: false,
      error: 'Internal server error'
    });
  }
);

/* =========================
   DÉMARRAGE
========================= */

app.listen(
  port,
  '0.0.0.0',
  async () => {

    console.log(
      `Finvero Capital server listening on port ${port}`
    );

    try {

      await transporter.verify();

      console.log(
        'SMTP connection verified successfully.'
      );

    } catch (error) {

      console.error(
        'SMTP verification failed:',
        error.message
      );
    }
  }
);

/* =========================
   SÉCURITÉ HTML
========================= */

function escapeHtml(value) {

  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}