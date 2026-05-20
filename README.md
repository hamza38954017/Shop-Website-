# Dr. Dev Shop — E-Commerce Platform
**Author: Dr. Hamza 2026 | © Dr. Dev | All Rights Reserved**

---

## 📁 File Structure
```
drdev-shop/
├── app.py              ← Flask backend (all API routes)
├── requirements.txt    ← Python dependencies
├── templates/
│   ├── shop.html       ← E-commerce frontend SPA
│   └── admin.html      ← Admin panel
└── README.md
```

---

## 🚀 Deploy on Render (Free)

### Step 1 — Firebase Setup
1. Go to **https://console.firebase.google.com**
2. Create a new project → **Realtime Database** → Start in **test mode**
3. Copy your database URL (e.g. `https://myproject-default-rtdb.firebaseio.com`)

### Step 2 — Render Deploy
1. Push this project to a **GitHub repo**
2. Go to **https://render.com** → New → **Web Service**
3. Connect your GitHub repo
4. Set these:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2`
   - **Environment:** Python 3

### Step 3 — Environment Variables (on Render)
Set these in your Render service **Environment** tab:

| Variable | Value |
|---|---|
| `FIREBASE_URL` | `https://yourproject-default-rtdb.firebaseio.com` |
| `SECRET_KEY` | Any random long string |
| `JWT_SECRET` | Any random long string |
| `ADMIN_USER` | `admin` (or change it) |
| `ADMIN_PASS` | `admin123` (change this!) |

---

## 🌐 Access

| URL | Description |
|---|---|
| `https://yourapp.onrender.com/` | Shop Website |
| `https://yourapp.onrender.com/admin` | Admin Panel |

### Admin Credentials
- **Username:** `admin`
- **Password:** `admin123`

> ⚠️ Change admin credentials via environment variables before deploying!

---

## ✅ Features

### 🛒 Shop (Frontend)
- User Registration & Login (email/mobile + password)
- Categories & Products with pagination
- Product detail page with reviews
- Shopping cart with quantity management
- Checkout with custom product fields
- UTR payment submission
- Wallet payment option
- Order history & tracking
- Wallet (balance, deposit, withdraw)
- Refer & Earn (10% commission, configurable)
- Profile page
- Search products
- Mobile responsive with bottom navigation
- Referral URL auto-fill on registration
- Notification broadcasts (shown on load)

### 🔐 Security
- JWT authentication (7-day expiry)
- bcrypt password hashing
- Rate limiting (Flask-Limiter)
- WAF — blocks XSS, SQLi, SSRF, command injection
- Security headers (CSP, XSS, Clickjacking protection)
- Input sanitization on all fields
- Visitor logging (IP, browser, screen, URL, timestamp)
- Email format validation
- Mobile number validation (10-digit Indian)
- Password minimum length enforcement

### ⚙️ Admin Panel
- Dashboard with live stats & revenue chart
- User management (edit wallet, suspend)
- Category management (add/edit/delete, icons, colors, sort order)
- Product management with **custom fields builder**
  - Field types: text, number, email, tel, select, textarea
  - Per-field: label, placeholder, required toggle, validation, hint
  - Select fields: comma-separated options
- Order management with date/status filters
- Deposit management (approve/reject)
- Withdrawal management (approve/reject with note, auto-refund on reject)
- Review moderation (delete)
- Broadcast notifications to all users
- Visitor logs (last 200)
- Full settings editor:
  - Site title, tagline, color, copyright
  - UPI ID & QR code for payments
  - Refer commission % (changeable)
  - Minimum withdrawal amount
  - WhatsApp & email support links
  - Announcement bar
  - Rules/policy page content
  - Maintenance mode toggle

---

## 🔥 Firebase Database Structure
```
/users/{id}         — User profiles, wallet, cart
/categories/{id}    — Product categories
/products/{id}      — Products with custom fields
/orders/{id}        — Purchase orders
/referrals/{id}     — Referral tracking
/deposits/{id}      — Wallet deposit requests
/withdrawals/{id}   — Withdrawal requests
/reviews/{id}       — Product reviews
/notifications/{id} — Broadcast messages
/settings           — Site-wide settings
/visitor_logs/{id}  — Security visitor logs
```

---

## 🛠️ Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export FIREBASE_URL="https://yourproject-default-rtdb.firebaseio.com"
export SECRET_KEY="local-dev-secret"
export JWT_SECRET="local-jwt-secret"

# Run
python app.py
# Open http://localhost:5000
# Admin: http://localhost:5000/admin
```

---

*© Dr. Hamza 2026 | Dr. Dev | All Rights Reserved*
