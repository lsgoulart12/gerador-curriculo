const crypto = require('node:crypto');

const PRODUCT_ID = 'rRsj5E0';
const JWT_EXPIRES_IN_SECONDS = 60 * 60 * 24 * 30;

function base64Url(value) {
    return Buffer.from(value).toString('base64url');
}

function timingSafeEqual(left, right) {
    const leftBuffer = Buffer.from(left || '');
    const rightBuffer = Buffer.from(right || '');

    return leftBuffer.length === rightBuffer.length
        && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function getHeader(request, name) {
    const value = request.headers?.[name]
        || request.headers?.[name.toLowerCase()]
        || request.headers?.[name.toUpperCase()];

    return Array.isArray(value) ? value[0] : value;
}

async function readRawBody(request) {
    if (Buffer.isBuffer(request.body)) {
        return request.body.toString('utf8');
    }

    if (typeof request.body === 'string') {
        return request.body;
    }

    if (request.body && typeof request.body === 'object') {
        return JSON.stringify(request.body);
    }

    const chunks = [];
    for await (const chunk of request) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }

    return Buffer.concat(chunks).toString('utf8');
}

// A assinatura deve ser calculada sobre o corpo bruto, antes do JSON.parse.
function getWebhookSignature(request) {
    const signature = getHeader(request, 'x-kiwify-signature')
        || getHeader(request, 'x-signature')
        || getHeader(request, 'signature');

    return String(signature || '').replace(/^sha256=/i, '').trim().toLowerCase();
}

function isApprovedPurchase(payload) {
    const status = String(
        payload.status
        || payload.payment_status
        || payload.order_status
        || payload.order?.status
        || payload.order?.payment_status
        || ''
    ).toLowerCase();

    const event = String(
        payload.event
        || payload.webhook_event
        || payload.type
        || ''
    ).toLowerCase();

    return [
        'paid',
        'approved',
        'completed',
        'payment_approved',
        'order_paid',
        'compra_aprovada'
    ].includes(status)
        || [
            'paid',
            'payment_approved',
            'order_paid',
            'compra_aprovada'
        ].includes(event);
}

function belongsToProduct(payload) {
    const productId = String(
        payload.product_id
        || payload.product?.id
        || payload.product?.product_id
        || payload.offer?.product_id
        || payload.order?.product_id
        || ''
    );

    return productId === PRODUCT_ID;
}

function getCustomerEmail(payload) {
    return String(
        payload.customer_email
        || payload.email
        || payload.customer?.email
        || payload.client?.email
        || payload.order?.customer?.email
        || ''
    ).trim().toLowerCase();
}

function getEventId(payload) {
    return String(
        payload.webhook_event_id
        || payload.event_id
        || payload.order_id
        || payload.id
        || ''
    ).trim();
}

function createJwt(email, eventId) {
    const secret = process.env.JWT_SECRET_KEY || process.env.KIWIFY_WEBHOOK_SECRET;
    if (!secret || secret.length < 32) {
        throw new Error('Configure JWT_SECRET_KEY ou KIWIFY_WEBHOOK_SECRET com pelo menos 32 caracteres.');
    }

    const now = Math.floor(Date.now() / 1000);
    const header = base64Url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const payload = base64Url(JSON.stringify({
        iss: 'curriculo-profissional-expresso',
        sub: crypto.createHash('sha256').update(email).digest('hex'),
        productId: PRODUCT_ID,
        eventId,
        iat: now,
        exp: now + JWT_EXPIRES_IN_SECONDS
    }));
    const unsignedToken = `${header}.${payload}`;
    const signature = crypto
        .createHmac('sha256', secret)
        .update(unsignedToken)
        .digest('base64url');

    return `${unsignedToken}.${signature}`;
}

function sendJson(response, statusCode, body) {
    return response.status(statusCode).json(body);
}

module.exports = async function webhook(request, response) {
    if (request.method !== 'POST') {
        response.setHeader('Allow', 'POST');
        return sendJson(response, 405, { error: 'Método não permitido.' });
    }

    try {
        const webhookSecret = process.env.KIWIFY_WEBHOOK_SECRET;
        if (!webhookSecret || webhookSecret.length < 32) {
            throw new Error('KIWIFY_WEBHOOK_SECRET não configurada corretamente.');
        }

        const rawBody = await readRawBody(request);
        const receivedSignature = getWebhookSignature(request);
        const expectedSignature = crypto
            .createHmac('sha256', webhookSecret)
            .update(rawBody)
            .digest('hex');

        // Comparação em tempo constante reduz risco de timing attack.
        if (!timingSafeEqual(receivedSignature, expectedSignature)) {
            return sendJson(response, 401, { error: 'Assinatura inválida.' });
        }

        const payload = JSON.parse(rawBody || '{}');
        if (!belongsToProduct(payload)) {
            return sendJson(response, 200, { received: true, ignored: true });
        }

        if (!isApprovedPurchase(payload)) {
            return sendJson(response, 200, { received: true, ignored: true });
        }

        const email = getCustomerEmail(payload);
        const eventId = getEventId(payload);
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !eventId) {
            return sendJson(response, 400, { error: 'Dados do comprador ou evento inválidos.' });
        }

        const token = createJwt(email, eventId);
        return sendJson(response, 200, {
            received: true,
            approved: true,
            productId: PRODUCT_ID,
            token,
            tokenType: 'Bearer',
            expiresIn: JWT_EXPIRES_IN_SECONDS
        });
    } catch (error) {
        console.error('Erro ao processar webhook Kiwify:', error);
        return sendJson(response, 400, { error: 'Webhook inválido.' });
    }
};

module.exports.config = {
    api: {
        bodyParser: false
    }
};
