// server.js - Unified Express + SQLite backend (fixed and extended)
// Run with: node server.js
// Requires: npm i express sqlite3 body-parser express-session bcrypt cors multer

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
  }
}));

// ---------- Static assets
const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(__dirname));          // serve root (in case html is kept alongside)
app.use(express.static(PUBLIC_DIR));
app.use('/public', express.static(PUBLIC_DIR));

// Ensure uploads dir exists (fix for Multer ENOENT)
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// ---------- DB setup
const db = new sqlite3.Database(path.join(__dirname, 'dashboard.db'), (err) => {
  if (err) {
    console.error('Error opening dashboard database:', err.message);
  } else {
    console.log('Connected to the dashboard SQLite database.');
    initializeDatabase();
  }
});

// Multer storage for product photos
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '_'));
  }
});
const upload = multer({ storage });

// ---------- Schema & seed
function initializeDatabase() {
  db.serialize(() => {
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        phone TEXT,
        password TEXT,
        role TEXT,
        two_factor_enabled INTEGER DEFAULT 0,
        notification_email INTEGER DEFAULT 1,
        notification_sms INTEGER DEFAULT 0,
        notification_push INTEGER DEFAULT 0,
        digest_frequency TEXT DEFAULT 'Daily'
      )`);

    db.run(`
      CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT,
        barcode TEXT,
        stock INTEGER NOT NULL,
        rental_period TEXT,
        pricelist TEXT,
        price_per_day REAL NOT NULL,
        extra_hour REAL,
        extra_day REAL,
        brand TEXT,
        base_price REAL,
        tax_percent REAL,
        status TEXT DEFAULT 'Active',
        location TEXT,
        photos TEXT,
        image_url TEXT
      )`);

    db.run(`
      CREATE TABLE IF NOT EXISTS stock_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER,
        adjust INTEGER,
        reason TEXT,
        date TEXT,
        FOREIGN KEY (product_id) REFERENCES products(id)
      )`);

    db.run(`
      CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL
      )`);

    db.run(`
      CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER,
        customer_id INTEGER,
        quantity INTEGER DEFAULT 1,
        revenue REAL,
        date TEXT,
        is_quotation INTEGER DEFAULT 0,
        is_rental INTEGER DEFAULT 0,
        status TEXT DEFAULT 'active',
        FOREIGN KEY (product_id) REFERENCES products(id),
        FOREIGN KEY (customer_id) REFERENCES customers(id)
      )`);

    db.run(`
      CREATE TABLE IF NOT EXISTS support_tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER,
        date TEXT,
        FOREIGN KEY (customer_id) REFERENCES customers(id)
      )`);

    db.run(`
      CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT,
        time TEXT
      )`);

    db.run(`
      CREATE TABLE IF NOT EXISTS returns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        return_number TEXT,
        customer TEXT,
        schedule_date DATE,
        responsible TEXT,
        transfer_type TEXT,
        total REAL,
        status TEXT,
        product TEXT
      )`);

    db.run(`
      CREATE TABLE IF NOT EXISTS rental_orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reference TEXT,
        customer_name TEXT,
        invoice_address TEXT,
        delivery_address TEXT,
        rental_template TEXT,
        expiration_date DATE,
        order_date DATE,
        pricelist TEXT,
        rental_period_days INTEGER,
        rental_duration_weeks INTEGER,
        notes TEXT,
        rental_status TEXT DEFAULT 'Draft',
        invoice_status TEXT DEFAULT 'Nothing to invoice',
        tax REAL DEFAULT 0,
        total REAL DEFAULT 0,
        created_by INTEGER,
        FOREIGN KEY (created_by) REFERENCES users(id)
      )`);

    db.run(`
      CREATE TABLE IF NOT EXISTS wishlists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        UNIQUE(user_id, product_id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (product_id) REFERENCES products(id)
      )`);

    db.run(`
      CREATE TABLE IF NOT EXISTS carts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER DEFAULT 1,
        from_date DATE NOT NULL,
        to_date DATE NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (product_id) REFERENCES products(id)
      )`);

    db.run(`
      CREATE TABLE IF NOT EXISTS shop_orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        total REAL NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        delivery_address TEXT,
        invoice_address TEXT,
        delivery_method TEXT,
        delivery_charge REAL DEFAULT 0,
        discount REAL DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )`);

    db.run(`
      CREATE TABLE IF NOT EXISTS shop_order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        from_date DATE NOT NULL,
        to_date DATE NOT NULL,
        price REAL NOT NULL,
        FOREIGN KEY (order_id) REFERENCES shop_orders(id),
        FOREIGN KEY (product_id) REFERENCES products(id)
      )`);

    db.run(`
      CREATE TABLE IF NOT EXISTS coupons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        discount REAL NOT NULL,
        expires_at DATE
      )`);

    // Seed if products empty
    db.get('SELECT COUNT(*) as c FROM products', (e, row) => {
      if (!e && row.c === 0) seed();
    });
  });
}

function seed() {
  db.serialize(() => {
    const products = [
      ["Wheelchairs", "Rental - Service", "Standard wheelchair", "WC001", 20, "Daily", "Standard", 303.2, 50, 200, "MedEquip", 303.2, 10, "Active", "Warehouse A", "", ""],
      ["Tables", "Rental - Service", "Folding table", "TB001", 15, "Daily", "Standard", 201.6, 30, 100, "EventFurn", 201.6, 10, "Active", "Warehouse B", "", ""],
      ["Chairs", "Rental - Service", "Stackable chair", "CH001", 50, "Daily", "Standard", 752, 20, 80, "StackPro", 752, 10, "Active", "Warehouse C", "", ""],
      ["Other", "Rental - Service", "Miscellaneous", "OT001", 30, "Daily", "Standard", 58.213, 10, 40, "MiscBrand", 58.213, 10, "Active", "Warehouse D", "", ""],
      ["Professional Camera Kit", "Rental - Service",
        "4K camera kit with 24–70mm lens, extras.",
        null, 5, "Daily", "Standard", 1500, null, null, "ProCam", 1500, 10, "Active", "Studio", "", "https://example.com/camera.jpg"]
    ];

    const pStmt = db.prepare(`INSERT INTO products
      (name, category, description, barcode, stock, rental_period, pricelist, price_per_day, extra_hour, extra_day, brand, base_price, tax_percent, status, location, photos, image_url)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    products.forEach(p => pStmt.run(p));
    pStmt.finalize();

    ['Customer 1','Customer 2','Customer 3','Customer 4'].forEach(n => {
      db.run('INSERT INTO customers (name) VALUES (?)', [n]);
    });

    // Sample user
    bcrypt.hash('password', 10).then(hash => {
      db.run(`INSERT OR IGNORE INTO users (username, email, phone, password, role) VALUES (?, ?, ?, ?, ?)`,
        ['adam', 'adam@example.com', '0000000000', hash, 'admin']);
      db.run(`INSERT OR IGNORE INTO users (username, email, phone, password, role) VALUES (?, ?, ?, ?, ?)`,
        ['priya', 'user@example.com', '1111111111', hash, 'user']);
    });

    // Coupon
    db.run(`INSERT OR IGNORE INTO coupons (code, discount, expires_at) VALUES (?,?,?)`, ['DISCOUNT10', 10, '2025-12-31']);
  });
}

// ---------- Auth helpers
const isAuthenticated = (req, res, next) => {
  if (req.session.user) return next();
  return res.redirect('/user_login.html'); // default to login page
};

const isAdmin = (req, res, next) => {
  if (req.session.user && req.session.user.role === 'admin') return next();
  return res.status(403).send('Access denied');
};

// ---------- Page routes
app.get('/register', (req, res) => {
  // compatibility: serve registration.html if present; otherwise any matching file
  const file = fs.existsSync(path.join(PUBLIC_DIR, 'registration.html'))
    ? 'registration.html'
    : 'register.html';
  res.sendFile(path.join(PUBLIC_DIR, file));
});

app.get('/login', (req, res) => {
  const file = fs.existsSync(path.join(PUBLIC_DIR, 'user_login.html'))
    ? 'user_login.html'
    : 'login.html';
  res.sendFile(path.join(PUBLIC_DIR, file));
});

// Example dashboards (protect)
app.get('/user_dashboard.html', isAuthenticated, (req, res) => {
  if (req.session.user.role !== 'admin') {
    return res.sendFile(path.join(PUBLIC_DIR, 'user_dashboard.html'));
  }
  return res.redirect('/admin_dashboard.html');
});

app.get('/admin_dashboard.html', isAuthenticated, isAdmin, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'admin_dashboard.html'));
});

// Wishlist & Orders pages (the “remaining 2 pages”)
app.get('/shop_wishlist.html', isAuthenticated, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'shop_wishlist.html'));
});
app.get('/shop_orders.html', isAuthenticated, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'shop_orders.html'));
});

// ---------- Auth APIs (fixed role normalization & matching frontend)
function normalizeRole(role) {
  if (!role) return 'user';
  const r = String(role).trim().toLowerCase();
  return (r === 'admin') ? 'admin' : 'user';
}

// Register
app.post('/register', async (req, res) => {
  const { username, name, email, phone, password, confirm, role } = req.body;
  if (!email || !password || !confirm) return res.status(400).send('Missing fields');
  if (password !== confirm) return res.status(400).send('Passwords do not match');

  const uname = username || name || email.split('@')[0];
  const normRole = normalizeRole(role);

  try {
    const hashed = await bcrypt.hash(password, 10);
    db.run(`INSERT INTO users (username, email, phone, password, role) VALUES (?,?,?,?,?)`,
      [uname, email, phone || '', hashed, normRole],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE')) return res.status(400).send('Email or username already exists');
          return res.status(500).send('Error registering user');
        }
        // auto login
        req.session.user = { id: this.lastID, role: normRole, username: uname };
        return res.redirect(normRole === 'admin' ? '/admin_dashboard.html' : '/user_dashboard.html');
      });
  } catch (e) {
    return res.status(500).send('Server error');
  }
});

// Login
app.post('/login', (req, res) => {
  const { email, password, role } = req.body;
  const normRole = normalizeRole(role);

  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) return res.status(400).send('Invalid email or password');
    if (normalizeRole(user.role) !== normRole) return res.status(400).send('Role mismatch');

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).send('Invalid email or password');

    req.session.user = { id: user.id, role: normRole, username: user.username };
    return res.redirect(normRole === 'admin' ? '/admin_dashboard.html' : '/user_dashboard.html');
  });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ---------- Products (admin)
app.get('/api/products', isAuthenticated, isAdmin, (req, res) => {
  db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => {
    if (err) return res.status(500).send('Error fetching products');
    res.json(rows);
  });
});

app.post('/api/products', isAuthenticated, isAdmin, upload.array('photos', 10), (req, res) => {
  const { name, category, description, barcode, stock, rental_period, pricelist, price_per_day, extra_hour, extra_day, brand, base_price, tax_percent, status, location } = req.body;
  const photos = (req.files || []).map(f => f.filename).join(',');

  db.run(`INSERT INTO products (name, category, description, barcode, stock, rental_period, pricelist, price_per_day, extra_hour, extra_day, brand, base_price, tax_percent, status, location, photos)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [name, category, description, barcode, +stock || 0, rental_period, pricelist, +price_per_day || 0, +extra_hour || null, +extra_day || null, brand, +base_price || null, +tax_percent || null, status || 'Active', location, photos],
    function (err) {
      if (err) return res.status(500).send('Error creating product');
      res.json({ id: this.lastID });
    });
});

app.patch('/api/products/:id/stock', isAuthenticated, isAdmin, (req, res) => {
  const { adjust = 0, location, reason } = req.body;
  const date = new Date().toISOString().slice(0,10);

  db.run(`UPDATE products SET stock = stock + ?, location = COALESCE(?, location) WHERE id = ?`,
    [Number(adjust), location || null, req.params.id],
    function (err) {
      if (err) return res.status(500).send('Error updating stock');
      db.run(`INSERT INTO stock_history (product_id, adjust, reason, date) VALUES (?,?,?,?)`,
        [req.params.id, Number(adjust), reason || '', date],
        function (e2) {
          if (e2) return res.status(500).send('Error logging stock history');
          res.send('Stock updated');
        });
    });
});

// ---------- Profile & Settings
app.get('/api/profile', isAuthenticated, (req, res) => {
  db.get(`SELECT id, username, email, phone, role, two_factor_enabled, notification_email, notification_sms, notification_push, digest_frequency FROM users WHERE id = ?`,
    [req.session.user.id], (err, row) => {
      if (err || !row) return res.status(500).send('Error fetching profile');
      res.json(row);
    });
});

// ---------- Dashboard KPIs (examples)
app.get('/api/kpis', isAuthenticated, (req, res) => {
  const now = new Date();
  const d30 = new Date(now.getTime() - 30*24*60*60*1000).toISOString().slice(0,10);
  const d60 = new Date(now.getTime() - 60*24*60*60*1000).toISOString().slice(0,10);
  const today = new Date().toISOString().slice(0,10);
  const d7 = new Date(now.getTime() - 7*24*60*60*1000).toISOString().slice(0,10);

  const queries = {
    revenue: `SELECT SUM(revenue) AS total FROM orders WHERE date >= ? AND is_quotation = 0 AND status='active'`,
    prev_revenue: `SELECT SUM(revenue) AS total FROM orders WHERE date >= ? AND date < ? AND is_quotation = 0 AND status='active'`,
    orders: `SELECT COUNT(*) AS count FROM orders WHERE date >= ? AND is_quotation = 0`,
    new_today: `SELECT COUNT(*) AS count FROM orders WHERE date = ? AND is_quotation = 0 AND status='active'`,
    quotations: `SELECT COUNT(*) AS count FROM orders WHERE date >= ? AND is_quotation = 1`,
    awaiting: `SELECT COUNT(*) AS count FROM orders WHERE date >= ? AND is_quotation = 1 AND status='awaiting'`,
    top_product: `SELECT p.name
                  FROM products p JOIN orders o ON o.product_id = p.id
                  WHERE o.date >= ? AND o.is_quotation = 0 AND o.status='active'
                  GROUP BY p.id ORDER BY SUM(o.revenue) DESC LIMIT 1`
  };

  Promise.all([
    new Promise((resolve,reject)=>db.get(queries.revenue,[d30],(e,row)=>e?reject(e):resolve(row.total||0))),
    new Promise((resolve,reject)=>db.get(queries.prev_revenue,[d60,d30],(e,row)=>e?reject(e):resolve(row.total||0))),
    new Promise((resolve,reject)=>db.get(queries.orders,[d30],(e,row)=>e?reject(e):resolve(row.count||0))),
    new Promise((resolve,reject)=>db.get(queries.new_today,[today],(e,row)=>e?reject(e):resolve(row.count||0))),
    new Promise((resolve,reject)=>db.get(queries.quotations,[d30],(e,row)=>e?reject(e):resolve(row.count||0))),
    new Promise((resolve,reject)=>db.get(queries.awaiting,[d30],(e,row)=>e?reject(e):resolve(row.count||0))),
    new Promise((resolve,reject)=>db.get(queries.top_product,[d7],(e,row)=>e?reject(e):resolve(row?row.name:'N/A'))),
  ]).then(([revenue, prev_revenue, orders, new_today, quotations, awaiting, top_product]) => {
    const revenue_percentage = prev_revenue>0 ? Number(((revenue-prev_revenue)/prev_revenue*100).toFixed(1)) : 0;
    res.json({ revenue, revenue_percentage, orders, new_today, quotations, awaiting, top_product });
  }).catch(e => res.status(500).json({ error: e.message }));
});

// ---------- Product public
app.get('/products/:id', (req, res) => {
  db.get(`SELECT * FROM products WHERE id = ?`, [req.params.id], (err, product) => {
    if (err || !product) return res.status(404).json({ error: 'Product not found' });
    res.json(product);
  });
});

// ---------- Wishlist (Page 1 backend)
app.get('/wishlist', isAuthenticated, (req, res) => {
  db.all(`SELECT p.* FROM products p JOIN wishlists w ON p.id = w.product_id WHERE w.user_id = ?`,
    [req.session.user.id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Server error' });
      res.json(rows);
    });
});

app.post('/wishlist', isAuthenticated, (req, res) => {
  const { product_id } = req.body;
  if (!product_id) return res.status(400).json({ error: 'product_id required' });
  db.run(`INSERT OR IGNORE INTO wishlists (user_id, product_id) VALUES (?,?)`,
    [req.session.user.id, product_id],
    function (err) {
      if (err) return res.status(500).json({ error: 'Server error' });
      res.status(201).json({ id: this.lastID });
    });
});

app.delete('/wishlist/:product_id', isAuthenticated, (req, res) => {
  db.run(`DELETE FROM wishlists WHERE user_id = ? AND product_id = ?`,
    [req.session.user.id, req.params.product_id],
    function (err) {
      if (err) return res.status(500).json({ error: 'Server error' });
      res.json({ removed: this.changes > 0 });
    });
});

// ---------- Orders (Page 2 backend)
app.get('/shop_orders', isAuthenticated, (req, res) => {
  db.all(`SELECT id, total, status, created_at, delivery_method, delivery_charge, discount FROM shop_orders WHERE user_id = ? ORDER BY id DESC`,
    [req.session.user.id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Server error' });
      res.json(rows);
    });
});

app.get('/shop_orders/:id/items', isAuthenticated, (req, res) => {
  db.all(`SELECT i.*, p.name FROM shop_order_items i JOIN products p ON p.id = i.product_id WHERE i.order_id = ?`,
    [req.params.id], (err, items) => {
      if (err) return res.status(500).json({ error: 'Server error' });
      res.json(items);
    });
});

// Simple endpoint to change order status (e.g., after payment webhook)
app.post('/shop_orders/:id/status', isAuthenticated, (req, res) => {
  const { status } = req.body;
  const allowed = new Set(['pending','paid','shipped','delivered','cancelled']);
  if (!allowed.has(status)) return res.status(400).json({ error: 'Invalid status' });
  db.run(`UPDATE shop_orders SET status = ? WHERE id = ? AND user_id = ?`,
    [status, req.params.id, req.session.user.id],
    function (err) {
      if (err) return res.status(500).json({ error: 'Server error' });
      res.json({ updated: this.changes > 0 });
    });
});

// ---------- Cart / Checkout helpers
app.post('/cart', isAuthenticated, (req, res) => {
  const { product_id, quantity = 1, from_date, to_date } = req.body;
  if (!product_id || !from_date || !to_date) return res.status(400).json({ error: 'Missing fields' });
  db.run(`INSERT INTO carts (user_id, product_id, quantity, from_date, to_date) VALUES (?,?,?,?,?)`,
    [req.session.user.id, product_id, quantity, from_date, to_date],
    function (err) {
      if (err) return res.status(500).json({ error: 'Server error' });
      res.status(201).json({ id: this.lastID });
    });
});

app.get('/cart/summary', isAuthenticated, (req, res) => {
  db.all(`SELECT p.*, c.quantity, c.from_date, c.to_date FROM products p JOIN carts c ON p.id = c.product_id WHERE c.user_id = ?`,
    [req.session.user.id], (err, items) => {
      if (err) return res.status(500).json({ error: 'Server error' });
      let subtotal = 0;
      items.forEach(item => {
        const days = Math.ceil((new Date(item.to_date) - new Date(item.from_date)) / 86400000) || 1;
        subtotal += (item.price_per_day || 0) * days * (item.quantity || 1);
      });
      const tax = +(subtotal * 0.18).toFixed(2);
      const total = +(subtotal + tax).toFixed(2);
      res.json({ items, subtotal, tax, total });
    });
});

app.get('/delivery-methods', (_req, res) => {
  res.json([
    { name: 'Store pickup', charge: 0 },
    { name: 'Standard courier', charge: 120 },
    { name: 'Express same-day', charge: 350 },
    { name: 'Outstation freight', charge: 600 }
  ]);
});

app.post('/checkout/delivery', isAuthenticated, (req, res) => {
  const { delivery_address, invoice_address, delivery_method, coupon_code } = req.body;
  const methods = new Map([['Store pickup',0],['Standard courier',120],['Express same-day',350],['Outstation freight',600]]);
  if (!methods.has(delivery_method)) return res.status(400).json({ error: 'Invalid delivery method' });

  const delivery_charge = methods.get(delivery_method);
  db.all(`SELECT p.*, c.quantity, c.from_date, c.to_date
          FROM products p JOIN carts c ON p.id = c.product_id
          WHERE c.user_id = ?`, [req.session.user.id], (err, items) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (items.length === 0) return res.status(400).json({ error: 'Cart is empty' });

    let subtotal = 0;
    items.forEach(item => {
      const days = Math.ceil((new Date(item.to_date) - new Date(item.from_date)) / 86400000) || 1;
      subtotal += (item.price_per_day || 0) * days * (item.quantity || 1);
    });

    const applyCoupon = (next) => {
      if (!coupon_code) return next(0);
      db.get(`SELECT discount FROM coupons WHERE code = ? AND (expires_at IS NULL OR expires_at >= DATE('now'))`,
        [coupon_code], (e, c) => {
          if (e || !c) return next(0);
          next(c.discount || 0);
        });
    };

    applyCoupon((discountPct) => {
      const discounted = subtotal - (subtotal * discountPct / 100);
      const tax = +(discounted * 0.18).toFixed(2);
      const total = +(discounted + tax + delivery_charge).toFixed(2);

      db.run(`INSERT INTO shop_orders (user_id, total, delivery_address, invoice_address, delivery_method, delivery_charge, discount)
              VALUES (?,?,?,?,?,?,?)`,
        [req.session.user.id, total, delivery_address, invoice_address, delivery_method, delivery_charge, discountPct],
        function (e2) {
          if (e2) return res.status(500).json({ error: 'Error creating order' });
          const orderId = this.lastID;

          const stmt = db.prepare(`INSERT INTO shop_order_items (order_id, product_id, quantity, from_date, to_date, price)
                                   VALUES (?,?,?,?,?,?)`);
          items.forEach(item => {
            const days = Math.ceil((new Date(item.to_date) - new Date(item.from_date)) / 86400000) || 1;
            const price = (item.price_per_day || 0) * days * (item.quantity || 1);
            stmt.run(orderId, item.id, item.quantity, item.from_date, item.to_date, price);
          });
          stmt.finalize();

          db.run(`DELETE FROM carts WHERE user_id = ?`, [req.session.user.id]);
          res.json({ orderId, total, status: 'pending' });
        });
    });
  });
});

app.post('/payment', isAuthenticated, (req, res) => {
  const { order_id } = req.body;
  db.run(`UPDATE shop_orders SET status = 'paid' WHERE id = ? AND user_id = ?`,
    [order_id, req.session.user.id], function (err) {
      if (err) return res.status(500).json({ error: 'Error processing payment' });
      res.json({ success: this.changes > 0 });
    });
});

// ---------- Rental orders (admin examples)
app.get('/api/rental_orders', isAuthenticated, isAdmin, (req, res) => {
  const { rental_status, invoice_status } = req.query;
  let q = `SELECT ro.*, u.username as created_by_name FROM rental_orders ro
           JOIN users u ON u.id = ro.created_by WHERE 1=1`;
  const p = [];
  if (rental_status) { q += ` AND rental_status = ?`; p.push(rental_status); }
  if (invoice_status) { q += ` AND invoice_status = ?`; p.push(invoice_status); }
  db.all(q, p, (err, rows) => {
    if (err) return res.status(500).send('Error fetching rental orders');
    res.json(rows);
  });
});

app.post('/api/rental_orders', isAuthenticated, isAdmin, (req, res) => {
  const {
    customer_name, invoice_address, delivery_address, rental_template,
    expiration_date, order_date, pricelist, rental_period_days,
    rental_duration_weeks, notes, rental_status, invoice_status, tax, total
  } = req.body;
  const created_by = req.session.user.id;

  db.run(`INSERT INTO rental_orders
    (customer_name, invoice_address, delivery_address, rental_template, expiration_date, order_date, pricelist,
     rental_period_days, rental_duration_weeks, notes, rental_status, invoice_status, tax, total, created_by)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [customer_name, invoice_address, delivery_address, rental_template, expiration_date, order_date, pricelist,
     rental_period_days, rental_duration_weeks, notes, rental_status || 'Draft', invoice_status || 'Nothing to invoice',
     tax || 0, total || 0, created_by],
    function (err) {
      if (err) return res.status(500).send('Error creating rental order');
      const id = this.lastID;
      const reference = `R${String(id).padStart(4,'0')}`;
      db.run(`UPDATE rental_orders SET reference = ? WHERE id = ?`, [reference, id], (e2) => {
        if (e2) return res.status(500).send('Error setting reference');
        res.json({ id, reference });
      });
    });
});

// ---------- Default
app.get('/', (_req, res) => res.redirect('/register'));

// ---------- Shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down...');
  db.close();
  process.exit(0);
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
