# RentalShop — Node.js + Express + SQLite (Fully Functional Backend)

A simple rental/e‑commerce style web app with a working **Node.js + Express** backend and **SQLite** database.
This repo includes authentication, products, inventory, wishlist, cart/checkout, orders, KPIs for dashboards, and rental orders for admins.

> ✅ This backend is **plug-and-play** with static HTML pages in `public/`. It auto‑creates the database (`dashboard.db`) and seeds sample data on first run.

---

## ✨ Features

- **Auth & Sessions**: Register, Login, Logout (role‑based: `user` or `admin`)
- **Dashboards**: Protected routes for User and Admin dashboards
- **Products & Stock**: Create products (with photos), adjust stock with history
- **Wishlist**: Add/remove/list user wishlist items
- **Cart & Checkout**: Date‑based cart, price calculation, coupon, delivery methods, tax, order creation
- **Orders**: View previous orders, items, and update order status
- **KPIs API**: Revenue, orders, quotations, top product (for dashboard cards)
- **Rental Orders (Admin)**: Create/list rental orders with references (e.g., `R0001`)
- **File Uploads**: Product image uploads via Multer to `/uploads`
- **CORS Enabled** for local dev with separate front‑end
- **Zero external DB setup** — uses a local SQLite file

---

## 🧱 Tech Stack

- **Backend**: Node.js, Express
- **Database**: SQLite3 (file: `dashboard.db`)
- **Auth**: `express-session` + `bcrypt`
- **Uploads**: Multer
- **Front‑end**: Static HTML/CSS/JS (use your pages in `public/` — Tailwind via CDN works fine)

---

## 📁 Project Structure

```
rentalshop-project/
├─ server.js               # Express server (this is the file you run)
├─ public/                 # Your HTML/CSS/JS lives here
│  ├─ registration.html
│  ├─ user_login.html
│  ├─ user_dashboard.html
│  ├─ admin_dashboard.html
│  ├─ shop_wishlist.html
│  └─ shop_orders.html
├─ uploads/                # Auto-created for product photos
├─ dashboard.db            # Auto-created SQLite database
└─ package.json            # Your npm scripts (optional)
```

> If your page names differ, adjust links or duplicate them to match these routes.

---

## 🚀 Getting Started

### 1) Install dependencies
```bash
npm i express sqlite3 body-parser express-session bcrypt cors multer
```

### 2) Run the server
```bash
node server.js
# or (optional)
# npx nodemon server.js
```

### 3) Open the app
Go to: **http://localhost:3000**  
You’ll land on **Register**, then **Login**, and be redirected to the appropriate dashboard based on role.

---

## 🔐 Auth & Roles

- Roles are normalized (`user`, `admin`) even if your form sends `User`/`Admin`.
- After registration/login, the server redirects to:
  - **User** → `/user_dashboard.html`
  - **Admin** → `/admin_dashboard.html`

### Seeded test accounts
The DB seeds on first run:

- **Admin** — Email: `adam@example.com` • Password: `password`
- **User** — Email: `user@example.com` • Password: `password`

> ⚠️ Your login form should include/select the correct role to match the account.

---

## 🌐 Pages (served by Express)

- `/register` → serves `public/registration.html` (fallback `register.html`)
- `/login` → serves `public/user_login.html` (fallback `login.html`)
- `/user_dashboard.html` → **protected**
- `/admin_dashboard.html` → **admin only**
- `/shop_wishlist.html` → **protected**
- `/shop_orders.html` → **protected**

Place your static pages in `public/` with those filenames (or update the server to match yours).

---

## 🔌 REST API

### Auth
- `POST /register` — body: `{ username|name, email, phone?, password, confirm, role }`
- `POST /login` — body: `{ email, password, role }`
- `POST /logout`

### Profile & KPIs
- `GET /api/profile` — current user profile
- `GET /api/kpis` — metrics for dashboard widgets

### Products (admin)
- `GET /api/products` — list products
- `POST /api/products` — **multipart/form-data**, fields:
  - text: `name, category, description?, barcode?, stock, rental_period?, pricelist?, price_per_day, extra_hour?, extra_day?, brand?, base_price?, tax_percent?, status?, location?`
  - files: `photos[]` (up to 10)
- `PATCH /api/products/:id/stock` — body: `{ adjust, reason?, location? }`

### Product (public)
- `GET /products/:id` — get product by id

### Wishlist (user)
- `GET /wishlist`
- `POST /wishlist` — body: `{ product_id }`
- `DELETE /wishlist/:product_id`

### Cart & Checkout (user)
- `POST /cart` — body: `{ product_id, quantity, from_date, to_date }`
- `GET /cart/summary` — returns items + subtotal/tax/total
- `GET /delivery-methods` — list of delivery options
- `POST /checkout/delivery` — body: `{ delivery_address, invoice_address, delivery_method, coupon_code? }`
- `POST /payment` — body: `{ order_id }` (marks order as paid)

### Shop Orders (user)
- `GET /shop_orders` — list own orders
- `GET /shop_orders/:id/items` — items for a given order
- `POST /shop_orders/:id/status` — body: `{ status }` (`pending|paid|shipped|delivered|cancelled`)

### Rental Orders (admin)
- `GET /api/rental_orders` — (filters: `?rental_status=&invoice_status=`)
- `POST /api/rental_orders` — body:
  ```json
  {
    "customer_name": "Acme Ltd",
    "invoice_address": "123 Street",
    "delivery_address": "Warehouse A",
    "rental_template": "Default",
    "expiration_date": "2025-08-31",
    "order_date": "2025-08-12",
    "pricelist": "Standard",
    "rental_period_days": 7,
    "rental_duration_weeks": 1,
    "notes": "N/A",
    "rental_status": "Draft",
    "invoice_status": "Nothing to invoice",
    "tax": 0,
    "total": 0
  }
  ```

---

## 🧪 Quick Manual Test

1. Register a **User** → login → visit `/shop_wishlist.html`
2. Add a product to wishlist: `POST /wishlist { product_id: 1 }` → `GET /wishlist`
3. Add to cart: `POST /cart { product_id: 1, quantity: 2, from_date: "2025-08-12", to_date: "2025-08-14" }`
4. Get summary: `GET /cart/summary`
5. Checkout: `POST /checkout/delivery { delivery_address, invoice_address, delivery_method: "Standard courier" }`
6. View orders: `GET /shop_orders` and `GET /shop_orders/:id/items`

---

## ⚙️ Configuration

Environment variables (optional):

- `PORT` — default `3000`
- `SESSION_SECRET` — default `"change-me-please"`

> The app creates `/uploads` automatically. To reset your DB, stop the server and delete `dashboard.db`.

---

## 🧩 Front‑End Integration Tips

- Post your auth forms to `/register` and `/login`.
- After login/registration, the server redirects to the correct dashboard.
- Serve your static assets from `public/` (server already mounted).
- For product creation with images, submit **multipart/form-data** and field names exactly as listed above.

---

## 🛠️ Troubleshooting

- **Port in use**: change `PORT` or free the port.
- **Cannot upload**: ensure requests are `multipart/form-data`. The server autogenerates `uploads/`.
- **Role mismatch**: make sure you select the same role that the account was created with.
- **Reset seed**: delete `dashboard.db` to reseed on next start.

---

## 📜 License

Add your preferred license (MIT recommended).

---

## 🙌 Acknowledgements

- Express, SQLite, Multer, bcrypt, Tailwind (if used in your HTML).

---

## 🧭 Roadmap (optional)

- JWT-based API (optional mobile app)
- Stripe/Razorpay integration
- Pagination & search on products
- Email/SMS notifications on order status
- Admin UI for coupons & delivery methods

---

## ✍️ Changelog

- **v1.0.0**
  - Fixed `server.js` role normalization and session redirects
  - Added fully working backends for **Wishlist** and **Orders** pages
  - Added auto‑created `uploads/` and improved static serving
  - Completed cart → checkout → order create → payment flow

## Demo - Video:
  - https://drive.google.com/file/d/1KBZJGqUln6kGkx4W7BVtXv5BYkF69cPr/view?usp=sharing

