import crypto from 'node:crypto';
import { neon } from '@neondatabase/serverless';

const ROLE = { Customer: 1, Admin: 2 };
const STATUS = { Pending: 1, Processing: 2, Shipped: 3, Completed: 4, Cancelled: 5 };
const STATUS_NAME = Object.fromEntries(Object.entries(STATUS).map(([key, value]) => [value, key]));
let initialized = false;

function sql() {
  const connectionString = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.POSTGRES_PRISMA_URL;
  if (!connectionString) throw new Error('DATABASE_URL is not configured.');
  return neon(normalizeConnectionString(connectionString));
}

function normalizeConnectionString(connectionString) {
  if (connectionString.startsWith('postgres://') || connectionString.startsWith('postgresql://')) {
    return connectionString;
  }
  const parts = Object.fromEntries(
    connectionString
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const index = part.indexOf('=');
        return [part.slice(0, index).trim().toLowerCase().replaceAll(' ', ''), part.slice(index + 1).trim()];
      })
  );
  const host = parts.host;
  const database = parts.database;
  const username = parts.username || parts.userid || parts.user;
  const password = parts.password;
  if (!host || !database || !username || !password) {
    throw new Error('DATABASE_URL is not configured correctly.');
  }
  return `postgresql://${encodeURIComponent(username)}:${encodeURIComponent(password)}@${host}/${encodeURIComponent(database)}?sslmode=require`;
}

function send(res, status, body) {
  if (body === undefined || body === null) return res.status(status).end();
  return res.status(status).json(body);
}

function b64(input) {
  return Buffer.from(input).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  return `${salt.toString('base64')}.${hash.toString('base64')}`;
}

function verifyPassword(password, storedHash) {
  const [saltText, hashText] = String(storedHash || '').split('.', 2);
  if (!saltText || !hashText) return false;
  const salt = Buffer.from(saltText, 'base64');
  const hash = Buffer.from(hashText, 'base64');
  const attempted = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  return hash.length === attempted.length && crypto.timingSafeEqual(hash, attempted);
}

function signToken(user) {
  const secret = process.env.JWT_SECRET || 'very-long-secret-key-for-jewelry-shop-api-2026';
  const header = b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64(JSON.stringify({ sub: String(user.id), role: user.role === ROLE.Admin ? 'Admin' : 'Customer', email: user.email, exp: Math.floor(Date.now() / 1000) + 604800 }));
  const signature = crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${signature}`;
}

function currentUser(req) {
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return null;
  const [header, payload, signature] = token.split('.');
  if (!header || !payload || !signature) return null;
  const secret = process.env.JWT_SECRET || 'very-long-secret-key-for-jewelry-shop-api-2026';
  const expected = crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
  if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  if (data.exp < Math.floor(Date.now() / 1000)) return null;
  return { id: Number(data.sub), role: data.role === 'Admin' ? ROLE.Admin : ROLE.Customer };
}

function requireUser(req, res) {
  const user = currentUser(req);
  if (!user?.id) send(res, 401, 'Unauthorized');
  return user;
}

function requireAdmin(req, res) {
  const user = requireUser(req, res);
  if (!user) return null;
  if (user.role !== ROLE.Admin) {
    send(res, 403, 'Forbidden');
    return null;
  }
  return user;
}

function product(row) {
  return { id: row.id, name: row.name, description: row.description, price: Number(row.price), stockQuantity: row.stock_quantity, imageUrl: row.image_url, categoryId: row.category_id, createdAt: row.created_at, category: row.category_id ? { id: row.category_id, name: row.category_name, description: row.category_description } : null };
}

async function init(db) {
  if (initialized) return;
  await db`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, full_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role INTEGER NOT NULL DEFAULT 1, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`;
  await db`CREATE TABLE IF NOT EXISTS categories (id SERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT)`;
  await db`CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, price NUMERIC(18,2) NOT NULL, stock_quantity INTEGER NOT NULL, image_url TEXT, category_id INTEGER NOT NULL REFERENCES categories(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`;
  await db`CREATE TABLE IF NOT EXISTS cart_items (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE, quantity INTEGER NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(user_id, product_id))`;
  await db`CREATE TABLE IF NOT EXISTS orders (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, total_amount NUMERIC(18,2) NOT NULL, status INTEGER NOT NULL DEFAULT 1, shipping_address TEXT NOT NULL DEFAULT '', phone_number TEXT NOT NULL DEFAULT '', payment_method TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`;
  await db`CREATE TABLE IF NOT EXISTS order_items (id SERIAL PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE, product_id INTEGER NOT NULL REFERENCES products(id), quantity INTEGER NOT NULL, unit_price NUMERIC(18,2) NOT NULL)`;
  await db`INSERT INTO users (full_name, email, password_hash, role) VALUES ('System Admin', 'admin@jewelryshop.com', ${hashPassword('Admin12345!')}, ${ROLE.Admin}) ON CONFLICT (email) DO NOTHING`;
  const cats = [['Rings','Elegant rings for weddings, engagements, and everyday style.'],['Necklaces','Beautiful necklaces crafted for modern and classic looks.'],['Bracelets','Luxury bracelets for casual and formal occasions.'],['Earrings','Stylish earrings designed with premium finishes.'],['Watches','Premium watches that complete a polished luxury look.']];
  for (const [name, desc] of cats) await db`INSERT INTO categories (name, description) VALUES (${name}, ${desc}) ON CONFLICT (name) DO NOTHING`;
  const rows = await db`SELECT id, name FROM categories`;
  const ids = Object.fromEntries(rows.map((r) => [r.name, r.id]));
  const items = [
    ['Diamond Engagement Ring','Premium diamond ring with a polished gold band.',1299.99,10,'https://images.unsplash.com/photo-1605100804763-247f67b3557e','Rings'],['Rose Gold Halo Ring','Rose gold ring with a sparkling halo setting.',749.99,12,'https://images.unsplash.com/photo-1589674781759-c21c37956a44','Rings'],['Sapphire Statement Ring','Bold sapphire ring designed for elegant evening wear.',980,7,'https://images.unsplash.com/photo-1603561591411-07134e71a2a9','Rings'],['Classic Gold Necklace','Elegant gold necklace suitable for special occasions.',899.5,15,'https://images.unsplash.com/photo-1599643478518-a784e5dc4c8f','Necklaces'],['Pearl Pendant Necklace','Timeless pearl pendant necklace with a delicate chain.',320,18,'https://images.unsplash.com/photo-1611085583191-a3b181a88401','Necklaces'],['Emerald Layered Necklace','Layered necklace with emerald-inspired luxury accents.',540.75,9,'https://images.unsplash.com/photo-1515562141207-7a88fb7ce338','Necklaces'],['Silver Charm Bracelet','Modern silver bracelet with a minimal charm design.',249.99,25,'https://images.unsplash.com/photo-1611591437281-460bfbe1220a','Bracelets'],['Gold Tennis Bracelet','Luxury tennis bracelet with brilliant polished stones.',670,8,'https://images.unsplash.com/photo-1602751584552-8ba73aad10e1','Bracelets'],['Leather Accent Bracelet','Modern leather and metal bracelet for everyday style.',120,20,'https://images.unsplash.com/photo-1611652022419-a9419f74343d','Bracelets'],['Pearl Drop Earrings','Classic pearl earrings with a luxury finish.',179.99,30,'https://images.unsplash.com/photo-1535632066927-ab7c9ab60908','Earrings'],['Diamond Stud Earrings','Brilliant diamond stud earrings for timeless elegance.',499.99,16,'https://images.unsplash.com/photo-1600721391776-b5cd0e0048f9','Earrings'],['Gold Hoop Earrings','Polished gold hoops with a clean modern silhouette.',210,22,'https://images.unsplash.com/photo-1630019852942-f89202989a59','Earrings'],['Classic Gold Watch','Premium gold watch with a refined jewelry-inspired finish.',1190,6,'https://images.unsplash.com/photo-1523170335258-f5ed11844a49','Watches'],['Silver Minimal Watch','Minimal silver watch designed for daily luxury.',430,14,'https://images.unsplash.com/photo-1524592094714-0f0654e20314','Watches'],['Black Luxury Watch','Bold black luxury watch with premium detailing.',860,5,'https://images.unsplash.com/photo-1542496658-e33a6d0d50f6','Watches']
  ];
  for (const [name, desc, price, stock, image, cat] of items) {
    const exists = await db`SELECT id FROM products WHERE name=${name}`;
    if (!exists.length) await db`INSERT INTO products (name, description, price, stock_quantity, image_url, category_id) VALUES (${name}, ${desc}, ${price}, ${stock}, ${image}, ${ids[cat]})`;
  }
  initialized = true;
}

async function orderItems(db, ids) {
  if (!ids.length) return {};
  const rows = await db`SELECT oi.*, p.*, c.name AS category_name, c.description AS category_description FROM order_items oi LEFT JOIN products p ON p.id=oi.product_id LEFT JOIN categories c ON c.id=p.category_id WHERE oi.order_id = ANY(${ids}) ORDER BY oi.id`;
  return rows.reduce((a, r) => { (a[r.order_id] ||= []).push({ id: r.id, orderId: r.order_id, productId: r.product_id, quantity: r.quantity, unitPrice: Number(r.unit_price), product: product(r) }); return a; }, {});
}

export default async function handler(req, res) {
  try {
    const db = sql();
    await init(db);
    const path = (Array.isArray(req.query.path) ? req.query.path : [req.query.path]).filter(Boolean);
    const [root, a, b] = path;
    const id = Number(a);
    if (root === 'auth' && req.method === 'POST') {
      const body = req.body || {};
      if (a === 'register') {
        const email = String(body.email || '').trim().toLowerCase();
        const fullName = String(body.fullName || '').trim();
        const exists = await db`SELECT id FROM users WHERE email=${email}`;
        if (exists.length) return send(res, 409, 'Email is already registered.');
        const rows = await db`INSERT INTO users (full_name, email, password_hash, role) VALUES (${fullName}, ${email}, ${hashPassword(String(body.password || ''))}, ${ROLE.Customer}) RETURNING id, full_name, email, role`;
        const u = { id: rows[0].id, fullName: rows[0].full_name, email: rows[0].email, role: rows[0].role };
        return send(res, 200, { userId: u.id, fullName: u.fullName, email: u.email, role: u.role, token: signToken(u) });
      }
      if (a === 'login') {
        const email = String(body.email || '').trim().toLowerCase();
        const rows = await db`SELECT * FROM users WHERE email=${email}`;
        if (!rows.length || !verifyPassword(String(body.password || ''), rows[0].password_hash)) return send(res, 401, 'Invalid email or password.');
        const u = { id: rows[0].id, fullName: rows[0].full_name, email: rows[0].email, role: rows[0].role };
        return send(res, 200, { userId: u.id, fullName: u.fullName, email: u.email, role: u.role, token: signToken(u) });
      }
    }
    if (root === 'categories') {
      if (req.method === 'GET') return send(res, 200, await db`SELECT id, name, description FROM categories ORDER BY name`);
      if (req.method === 'POST') { if (!requireAdmin(req, res)) return; const r = await db`INSERT INTO categories (name, description) VALUES (${req.body.name}, ${req.body.description || null}) RETURNING id, name, description`; return send(res, 201, r[0]); }
      if (req.method === 'DELETE') { if (!requireAdmin(req, res)) return; await db`DELETE FROM categories WHERE id=${id}`; return send(res, 204); }
    }
    if (root === 'products') {
      if (req.method === 'GET') {
        const rows = await db`SELECT p.*, c.name AS category_name, c.description AS category_description FROM products p LEFT JOIN categories c ON c.id=p.category_id ${id ? db`WHERE p.id=${id}` : db``} ORDER BY p.name`;
        return rows.length ? send(res, 200, id ? product(rows[0]) : rows.map(product)) : send(res, 404, 'Not found');
      }
      if (b === 'image') return send(res, 501, 'Image upload needs Cloudinary setup in serverless mode.');
      if (!requireAdmin(req, res)) return;
      const body = req.body || {};
      if (req.method === 'POST') { const r = await db`INSERT INTO products (name, description, price, stock_quantity, image_url, category_id) VALUES (${body.name}, ${body.description}, ${Number(body.price)}, ${Number(body.stockQuantity)}, ${body.imageUrl || null}, ${Number(body.categoryId)}) RETURNING *`; return send(res, 201, product({ ...r[0], category_name: null, category_description: null })); }
      if (req.method === 'PUT') { await db`UPDATE products SET name=${body.name}, description=${body.description}, price=${Number(body.price)}, stock_quantity=${Number(body.stockQuantity)}, image_url=${body.imageUrl || null}, category_id=${Number(body.categoryId)} WHERE id=${id}`; return send(res, 204); }
      if (req.method === 'DELETE') { await db`DELETE FROM products WHERE id=${id}`; return send(res, 204); }
    }
    if (root === 'cart') {
      const u = requireUser(req, res); if (!u) return;
      if (req.method === 'GET') { const rows = await db`SELECT ci.id, ci.user_id, ci.product_id, ci.quantity, ci.created_at, p.*, c.name AS category_name, c.description AS category_description FROM cart_items ci LEFT JOIN products p ON p.id=ci.product_id LEFT JOIN categories c ON c.id=p.category_id WHERE ci.user_id=${u.id} ORDER BY ci.created_at`; return send(res, 200, rows.map((r) => ({ id: r.id, userId: r.user_id, productId: r.product_id, quantity: r.quantity, createdAt: r.created_at, product: product(r) }))); }
      if (req.method === 'POST') { const q = Number(req.body.quantity || 1), pid = Number(req.body.productId); const r = await db`INSERT INTO cart_items (user_id, product_id, quantity) VALUES (${u.id}, ${pid}, ${q}) ON CONFLICT (user_id, product_id) DO UPDATE SET quantity=cart_items.quantity+EXCLUDED.quantity RETURNING *`; return send(res, 200, r[0]); }
      if (req.method === 'PUT') { await db`UPDATE cart_items SET quantity=${Number(req.body.quantity)} WHERE id=${id} AND user_id=${u.id}`; return send(res, 204); }
      if (req.method === 'DELETE') { await db`DELETE FROM cart_items WHERE id=${id} AND user_id=${u.id}`; return send(res, 204); }
    }
    if (root === 'orders') {
      const u = requireUser(req, res); if (!u) return;
      if (a === 'admin') { if (u.role !== ROLE.Admin) return send(res, 403, 'Forbidden'); const rows = await db`SELECT o.*, u.full_name AS user_full_name, u.email AS user_email, u.role AS user_role FROM orders o LEFT JOIN users u ON u.id=o.user_id ORDER BY o.created_at DESC`; const items = await orderItems(db, rows.map((r) => r.id)); return send(res, 200, rows.map((r) => ({ id: r.id, userId: r.user_id, user: { id: r.user_id, fullName: r.user_full_name, email: r.user_email, role: r.user_role }, totalAmount: Number(r.total_amount), status: STATUS_NAME[r.status], shippingAddress: r.shipping_address, phoneNumber: r.phone_number, paymentMethod: r.payment_method, createdAt: r.created_at, items: items[r.id] || [] }))); }
      if (b === 'status') { if (u.role !== ROLE.Admin) return send(res, 403, 'Forbidden'); await db`UPDATE orders SET status=${STATUS[req.body.status] || Number(req.body.status)} WHERE id=${id}`; return send(res, 204); }
      if (a === 'checkout') { const cart = await db`SELECT ci.*, p.price, p.stock_quantity FROM cart_items ci LEFT JOIN products p ON p.id=ci.product_id WHERE ci.user_id=${u.id}`; if (!cart.length) return send(res, 400, 'Cart is empty.'); const total = cart.reduce((s, i) => s + Number(i.price) * i.quantity, 0); const o = await db`INSERT INTO orders (user_id,total_amount,status,shipping_address,phone_number,payment_method) VALUES (${u.id},${total},1,${req.body.shippingAddress},${req.body.phoneNumber},${req.body.paymentMethod}) RETURNING *`; for (const i of cart) { await db`INSERT INTO order_items (order_id,product_id,quantity,unit_price) VALUES (${o[0].id},${i.product_id},${i.quantity},${i.price})`; await db`UPDATE products SET stock_quantity=stock_quantity-${i.quantity} WHERE id=${i.product_id}`; } await db`DELETE FROM cart_items WHERE user_id=${u.id}`; return send(res, 201, o[0]); }
      if (req.method === 'GET') { const rows = await db`SELECT * FROM orders WHERE user_id=${u.id} ORDER BY created_at DESC`; const items = await orderItems(db, rows.map((r) => r.id)); return send(res, 200, rows.map((r) => ({ id: r.id, userId: r.user_id, totalAmount: Number(r.total_amount), status: STATUS_NAME[r.status], shippingAddress: r.shipping_address, phoneNumber: r.phone_number, paymentMethod: r.payment_method, createdAt: r.created_at, items: items[r.id] || [] }))); }
    }
    if (root === 'admin' && a === 'dashboard') {
      if (!requireAdmin(req, res)) return;
      const c = (await db`SELECT (SELECT COUNT(*)::int FROM users) total_users,(SELECT COUNT(*)::int FROM users WHERE role=1) total_customers,(SELECT COUNT(*)::int FROM users WHERE role=2) total_admins,(SELECT COUNT(*)::int FROM categories) total_categories,(SELECT COUNT(*)::int FROM products) total_products,(SELECT COUNT(*)::int FROM orders) total_orders,(SELECT COUNT(*)::int FROM orders WHERE status=1) pending_orders,(SELECT COUNT(*)::int FROM orders WHERE status=4) completed_orders,COALESCE((SELECT SUM(total_amount) FROM orders WHERE status=4),0) total_revenue,(SELECT COUNT(*)::int FROM products WHERE stock_quantity<=5) low_stock_products`)[0];
      return send(res, 200, { totalUsers: c.total_users, totalCustomers: c.total_customers, totalAdmins: c.total_admins, totalCategories: c.total_categories, totalProducts: c.total_products, totalOrders: c.total_orders, pendingOrders: c.pending_orders, completedOrders: c.completed_orders, totalRevenue: Number(c.total_revenue), lowStockProducts: c.low_stock_products, recentOrders: [], lowStockItems: [], bestSellers: [], statusBreakdown: [] });
    }
    return send(res, 404, 'Not found');
  } catch (error) {
    return send(res, 500, error.message || 'Server error');
  }
}
