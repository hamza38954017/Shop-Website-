#!/usr/bin/env python3
"""
Dr. Dev Shop — Full E-Commerce Platform
Author: Dr. Hamza 2026  |  © Dr. Dev | All Rights Reserved
"""

import os, re, json, time, string, secrets, hashlib, logging, uuid
from datetime import datetime, timezone, timedelta
from functools import wraps

import jwt, bcrypt, requests
from flask import Flask, render_template, request, jsonify, make_response, abort, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

# ─── App Setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", "drdev-shop-super-secret-2026-xK9p")
CORS(app, supports_credentials=True, origins="*")

FIREBASE_BASE = os.environ.get("FIREBASE_URL", "https://YOUR-PROJECT-default-rtdb.firebaseio.com")
JWT_SECRET    = os.environ.get("JWT_SECRET", "drdev-jwt-2026-secret-mQwP")
JWT_EXP_DAYS  = 7
ADMIN_USER    = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS    = os.environ.get("ADMIN_PASS", "admin123")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("drdev")

limiter = Limiter(
    app=app, key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["600/day", "120/hour"]
)

# ─── Firebase REST Helper ───────────────────────────────────────────────────────
def fb(path: str, method="GET", data=None, params=None):
    url = f"{FIREBASE_BASE}/{path}.json"
    p   = params or {}
    try:
        kw = dict(params=p, timeout=12)
        if   method == "GET":    r = requests.get(url, **kw)
        elif method == "PUT":    r = requests.put(url, json=data, **kw)
        elif method == "POST":   r = requests.post(url, json=data, **kw)
        elif method == "PATCH":  r = requests.patch(url, json=data, **kw)
        elif method == "DELETE": r = requests.delete(url, **kw)
        else: return None
        return r.json() if r.content else None
    except Exception as e:
        log.error(f"FB {method} {path}: {e}")
        return None

def fb_list(path: str, params=None):
    data = fb(path, params=params)
    if not data or not isinstance(data, dict):
        return []
    return [{"id": k, **v} for k, v in data.items() if isinstance(v, dict)]

def ts() -> str:
    return datetime.now(timezone.utc).isoformat()

def uid() -> str:
    return uuid.uuid4().hex[:20]

# ─── Auth Helpers ───────────────────────────────────────────────────────────────
def hash_pw(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(12)).decode()

def check_pw(pw: str, h: str) -> bool:
    try:    return bcrypt.checkpw(pw.encode(), h.encode())
    except: return False

def make_token(user_id: str, is_admin=False) -> str:
    return jwt.encode({
        "sub": user_id, "adm": is_admin,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=JWT_EXP_DAYS)
    }, JWT_SECRET, algorithm="HS256")

def decode_token(token: str):
    try:    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except: return None

def get_token() -> str:
    auth = request.headers.get("Authorization", "")
    return auth[7:] if auth.startswith("Bearer ") else request.cookies.get("token", "")

def require_auth(f):
    @wraps(f)
    def dec(*args, **kwargs):
        p = decode_token(get_token())
        if not p: return jsonify(error="Unauthorized"), 401
        request.user_id  = p["sub"]
        request.is_admin = p.get("adm", False)
        return f(*args, **kwargs)
    return dec

def require_admin(f):
    @wraps(f)
    def dec(*args, **kwargs):
        p = decode_token(get_token())
        if not p or not p.get("adm"): return jsonify(error="Forbidden"), 403
        request.user_id = p["sub"]
        return f(*args, **kwargs)
    return dec

def gen_refer_code(n=8) -> str:
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(n))

# ─── Validators ─────────────────────────────────────────────────────────────────
def valid_email(e):   return bool(re.match(r'^[\w+\-.]+@[\w\-.]+\.[a-z]{2,}$', e, re.I))
def valid_mobile(m):  return bool(re.match(r'^\d{10}$', str(m)))
def valid_name(n):    return bool(re.match(r'^[A-Za-z ]{2,60}$', n.strip()))
def sanitize(s, n=500): return re.sub(r'[<>"\'%;]', '', str(s))[:n]

# ─── Security Middleware ─────────────────────────────────────────────────────────
INJECT_PATTERNS = [
    "<script", "javascript:", "onload=", "onerror=", "onclick=",
    "union select", "drop table", "insert into", "delete from",
    "../etc/passwd", "cmd=", "exec(", "eval(", "__import__",
    "ssrf://", "gopher://", "file://", "${", "#{",
]

@app.before_request
def waf():
    if request.path.startswith("/static"): return
    # Log visitor
    _log_visitor()
    # WAF: check query params, form fields, JSON body
    all_vals = list(request.args.values()) + list(request.form.values())
    try:
        body = request.get_json(silent=True)
        if body: all_vals += _extract_strings(body)
    except: pass
    for val in all_vals:
        v = str(val).lower()
        if any(p in v for p in INJECT_PATTERNS):
            return jsonify(error="Request blocked by security filter"), 400

def _extract_strings(obj, depth=0):
    if depth > 5: return []
    if isinstance(obj, str): return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _extract_strings(v, depth+1)]
    if isinstance(obj, list):
        return [s for i in obj for s in _extract_strings(i, depth+1)]
    return [str(obj)]

def _log_visitor():
    try:
        fb("visitor_logs", "POST", {
            "ip":        request.remote_addr,
            "ua":        request.headers.get("User-Agent","")[:200],
            "screen":    request.headers.get("X-Screen",""),
            "url":       request.path,
            "method":    request.method,
            "referer":   request.headers.get("Referer","")[:200],
            "timestamp": ts()
        })
    except: pass

@app.after_request
def sec_headers(resp):
    resp.headers.update({
        "X-Content-Type-Options":  "nosniff",
        "X-Frame-Options":         "DENY",
        "X-XSS-Protection":        "1; mode=block",
        "Referrer-Policy":         "strict-origin-when-cross-origin",
        "Permissions-Policy":      "geolocation=(), microphone=()",
        "Content-Security-Policy": (
            "default-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "https://cdn.jsdelivr.net https://cdnjs.cloudflare.com "
            "https://fonts.googleapis.com https://fonts.gstatic.com; "
            "img-src * data: blob:; connect-src *;"
        ),
    })
    return resp

# ══════════════════════════════════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("8/hour")
def register():
    d        = request.get_json(silent=True) or {}
    name     = sanitize(d.get("name","")).strip()
    raw_mob  = str(d.get("mobile","")).strip().replace("+91","").strip()
    email    = d.get("email","").strip().lower()
    password = d.get("password","")
    ref_code = d.get("refer_code","").strip().upper()

    errs = []
    if not valid_name(name):    errs.append("Name must be letters only (2–60 chars)")
    if not valid_mobile(raw_mob): errs.append("Mobile must be exactly 10 digits")
    if not valid_email(email):  errs.append("Invalid email format")
    if len(password) < 6:       errs.append("Password must be at least 6 characters")
    if errs: return jsonify(error="; ".join(errs)), 400

    users = fb_list("users")
    for u in users:
        if u.get("email")  == email:   return jsonify(error="Email already registered"), 409
        if u.get("mobile") == raw_mob: return jsonify(error="Mobile already registered"), 409

    referrer_id = None
    if ref_code:
        match = [u for u in users if u.get("refer_code") == ref_code]
        if not match:              return jsonify(error="Invalid refer code"), 400
        referrer_id = match[0]["id"]

    user_id = uid()
    my_code = gen_refer_code()
    fb(f"users/{user_id}", "PUT", {
        "name": name, "mobile": raw_mob, "email": email,
        "password_hash": hash_pw(password),
        "refer_code": my_code, "referred_by": referrer_id or "",
        "wallet": 0, "total_earned": 0, "total_spent": 0,
        "cart": {}, "is_active": True,
        "created_at": ts(), "last_seen": ts()
    })

    if referrer_id:
        fb("referrals", "POST", {
            "referrer_id": referrer_id, "referred_id": user_id,
            "status": "pending", "amount": 0, "created_at": ts()
        })

    token = make_token(user_id)
    return jsonify(success=True, token=token, user={
        "id": user_id, "name": name, "email": email,
        "mobile": raw_mob, "wallet": 0, "refer_code": my_code
    })

@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("15/hour")
def login():
    d          = request.get_json(silent=True) or {}
    identifier = d.get("identifier","").strip().lower().replace("+91","")
    password   = d.get("password","")

    users = fb_list("users")
    found = next((u for u in users
                  if u.get("email") == identifier or u.get("mobile") == identifier), None)
    if not found or not check_pw(password, found.get("password_hash","")):
        return jsonify(error="Invalid credentials"), 401
    if not found.get("is_active", True):
        return jsonify(error="Account suspended. Contact support."), 403

    uid_ = found["id"]
    fb(f"users/{uid_}/last_seen", "PUT", ts())
    return jsonify(success=True, token=make_token(uid_), user={
        "id": uid_, "name": found["name"], "email": found["email"],
        "mobile": found["mobile"], "wallet": found.get("wallet",0),
        "refer_code": found.get("refer_code","")
    })

@app.route("/api/auth/me")
@require_auth
def me():
    u = fb(f"users/{request.user_id}")
    if not u: return jsonify(error="Not found"), 404
    u.pop("password_hash", None)
    return jsonify(user=u, id=request.user_id)

# ══════════════════════════════════════════════════════════════════════════════
#  SETTINGS (public)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/settings")
def get_settings():
    s = fb("settings") or {}
    return jsonify({
        "site_title":      s.get("site_title",      "Dr. Dev Shop"),
        "site_tagline":    s.get("site_tagline",     "Your One-Stop Digital Store"),
        "site_color":      s.get("site_color",       "#7c3aed"),
        "copyright":       s.get("copyright",        "© Dr. Hamza 2026 | Dr. Dev | All Rights Reserved"),
        "whatsapp":        s.get("whatsapp",         ""),
        "support_email":   s.get("support_email",    ""),
        "upi_id":          s.get("upi_id",           ""),
        "upi_qr":          s.get("upi_qr",           ""),
        "refer_commission":s.get("refer_commission",  10),
        "maintenance":     s.get("maintenance",       False),
        "announcement":    s.get("announcement",      ""),
        "min_withdraw":    s.get("min_withdraw",      10),
        "rules":           s.get("rules",             ""),
    })

# ══════════════════════════════════════════════════════════════════════════════
#  CATEGORIES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/categories")
def get_categories():
    cats = [c for c in fb_list("categories") if c.get("active", True)]
    cats.sort(key=lambda x: x.get("order", 99))
    return jsonify(categories=cats)

# ══════════════════════════════════════════════════════════════════════════════
#  PRODUCTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/products")
def get_products():
    cat_id = request.args.get("category","")
    page   = max(1, int(request.args.get("page",1)))
    limit  = min(24, int(request.args.get("limit",12)))
    search = request.args.get("q","").lower()

    prods = [p for p in fb_list("products") if p.get("active", True)]
    if cat_id: prods = [p for p in prods if p.get("category_id") == cat_id]
    if search: prods = [p for p in prods
                        if search in p.get("name","").lower()
                        or search in p.get("description","").lower()]
    prods.sort(key=lambda x: x.get("created_at",""), reverse=True)

    total       = len(prods)
    start       = (page - 1) * limit
    page_prods  = prods[start : start + limit]
    pages       = max(1, (total + limit - 1) // limit)

    # Increment views async (fire-and-forget)
    for p in page_prods:
        fb(f"products/{p['id']}/views", "PUT", p.get("views",0) + 1)

    return jsonify(products=page_prods, total=total, page=page, pages=pages)

@app.route("/api/products/<pid>")
def get_product(pid):
    p = fb(f"products/{pid}")
    if not p: return jsonify(error="Product not found"), 404
    fb(f"products/{pid}/views", "PUT", p.get("views",0) + 1)
    reviews = [r for r in fb_list("reviews") if r.get("product_id") == pid]
    reviews.sort(key=lambda x: x.get("created_at",""), reverse=True)
    avg = round(sum(r.get("rating",5) for r in reviews)/len(reviews),1) if reviews else 0
    return jsonify(product={**p,"id":pid}, reviews=reviews,
                   avg_rating=avg, review_count=len(reviews))

# ══════════════════════════════════════════════════════════════════════════════
#  CART
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/cart")
@require_auth
def get_cart():
    cart  = fb(f"users/{request.user_id}/cart") or {}
    items, total = [], 0
    for pid, qty in cart.items():
        p = fb(f"products/{pid}")
        if p:
            line = p.get("price",0) * qty
            total += line
            items.append({"product_id":pid,"quantity":qty,"line_total":line,**p})
    return jsonify(items=items, total=total, count=len(items))

@app.route("/api/cart/add", methods=["POST"])
@require_auth
def add_to_cart():
    d   = request.get_json(silent=True) or {}
    pid = d.get("product_id")
    qty = max(1, int(d.get("quantity",1)))
    if not pid: return jsonify(error="product_id required"), 400
    p = fb(f"products/{pid}")
    if not p or not p.get("active",True): return jsonify(error="Product not available"), 404
    cart = fb(f"users/{request.user_id}/cart") or {}
    cart[pid] = cart.get(pid,0) + qty
    fb(f"users/{request.user_id}/cart", "PUT", cart)
    return jsonify(success=True, cart=cart, count=len(cart))

@app.route("/api/cart/update", methods=["POST"])
@require_auth
def update_cart():
    d   = request.get_json(silent=True) or {}
    pid = d.get("product_id"); qty = int(d.get("quantity",1))
    cart = fb(f"users/{request.user_id}/cart") or {}
    if qty <= 0: cart.pop(pid,None)
    else:        cart[pid] = qty
    fb(f"users/{request.user_id}/cart", "PUT", cart)
    return jsonify(success=True, cart=cart, count=len(cart))

@app.route("/api/cart/remove", methods=["POST"])
@require_auth
def remove_from_cart():
    d   = request.get_json(silent=True) or {}
    cart = fb(f"users/{request.user_id}/cart") or {}
    cart.pop(d.get("product_id",""), None)
    fb(f"users/{request.user_id}/cart", "PUT", cart)
    return jsonify(success=True, count=len(cart))

@app.route("/api/cart/clear", methods=["POST"])
@require_auth
def clear_cart():
    fb(f"users/{request.user_id}/cart", "PUT", {})
    return jsonify(success=True)

# ══════════════════════════════════════════════════════════════════════════════
#  ORDERS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/orders", methods=["POST"])
@require_auth
@limiter.limit("30/hour")
def create_order():
    d          = request.get_json(silent=True) or {}
    items_in   = d.get("items",[])
    pay_method = d.get("payment_method","utr")
    delivery   = {k: sanitize(v) for k,v in d.get("delivery",{}).items()}

    if not items_in: return jsonify(error="No items in order"), 400

    user = fb(f"users/{request.user_id}")
    if not user: return jsonify(error="User not found"), 404

    order_items, total = [], 0
    for item in items_in:
        pid  = item.get("product_id")
        qty  = max(1, int(item.get("quantity",1)))
        flds = {k: sanitize(v) for k,v in item.get("fields",{}).items()}
        p    = fb(f"products/{pid}")
        if not p: return jsonify(error=f"Product not found: {pid}"), 404
        line = p.get("price",0) * qty
        total += line
        order_items.append({
            "product_id":pid,"name":p.get("name"),"category_id":p.get("category_id"),
            "price":p.get("price",0),"quantity":qty,"line_total":line,"fields":flds
        })

    order_id = uid()
    order = {
        "user_id":request.user_id,"user_name":user.get("name"),
        "user_email":user.get("email"),"user_mobile":user.get("mobile"),
        "items":order_items,"total":total,
        "payment_method":pay_method,"payment_status":"pending",
        "order_status":"pending","utr_number":"",
        "delivery":delivery,"note":"",
        "created_at":ts(),"updated_at":ts()
    }

    if pay_method == "wallet":
        bal = user.get("wallet",0)
        if bal < total: return jsonify(error=f"Insufficient balance. Need ₹{total}, have ₹{bal}"), 400
        fb(f"users/{request.user_id}/wallet", "PUT", round(bal - total, 2))
        fb(f"users/{request.user_id}/total_spent","PUT", round(user.get("total_spent",0)+total,2))
        order.update({"payment_status":"paid","order_status":"processing"})
        _credit_referral(request.user_id, total)

    fb(f"orders/{order_id}", "PUT", order)
    fb(f"users/{request.user_id}/cart", "PUT", {})
    return jsonify(success=True, order_id=order_id, total=total,
                   payment_status=order["payment_status"])

@app.route("/api/orders/<oid>/utr", methods=["POST"])
@require_auth
def submit_utr(oid):
    d   = request.get_json(silent=True) or {}
    utr = sanitize(d.get("utr","")).strip()
    if len(utr) < 6: return jsonify(error="UTR must be at least 6 characters"), 400
    order = fb(f"orders/{oid}")
    if not order:                              return jsonify(error="Order not found"), 404
    if order.get("user_id") != request.user_id: return jsonify(error="Forbidden"), 403
    if order.get("payment_status") == "paid":  return jsonify(error="Already paid"), 400
    fb(f"orders/{oid}", "PATCH", {"utr_number":utr,"payment_status":"verifying","updated_at":ts()})
    return jsonify(success=True, message="UTR submitted. Verification in progress ⏳")

@app.route("/api/orders/history")
@require_auth
def order_history():
    orders = [o for o in fb_list("orders") if o.get("user_id") == request.user_id]
    orders.sort(key=lambda x: x.get("created_at",""), reverse=True)
    return jsonify(orders=orders)

@app.route("/api/orders/<oid>")
@require_auth
def get_order(oid):
    o = fb(f"orders/{oid}")
    if not o: return jsonify(error="Not found"), 404
    if o.get("user_id") != request.user_id and not request.is_admin:
        return jsonify(error="Forbidden"), 403
    return jsonify(order={**o,"id":oid})

# ══════════════════════════════════════════════════════════════════════════════
#  WALLET
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/wallet")
@require_auth
def get_wallet():
    u = fb(f"users/{request.user_id}")
    if not u: return jsonify(error="Not found"), 404
    deps = [d for d in fb_list("deposits")    if d.get("user_id")==request.user_id]
    wds  = [w for w in fb_list("withdrawals") if w.get("user_id")==request.user_id]
    deps.sort(key=lambda x:x.get("created_at",""), reverse=True)
    wds.sort( key=lambda x:x.get("created_at",""), reverse=True)
    return jsonify(
        wallet=u.get("wallet",0), total_earned=u.get("total_earned",0),
        total_spent=u.get("total_spent",0),
        deposits=deps, withdrawals=wds
    )

@app.route("/api/wallet/deposit", methods=["POST"])
@require_auth
@limiter.limit("12/hour")
def deposit():
    d   = request.get_json(silent=True) or {}
    amt = float(d.get("amount",0))
    utr = sanitize(d.get("utr","")).strip()
    if amt <= 0:       return jsonify(error="Invalid amount"), 400
    if len(utr) < 6:   return jsonify(error="UTR must be at least 6 chars"), 400
    dep_id = uid()
    fb(f"deposits/{dep_id}", "PUT", {
        "user_id":request.user_id,"user_name":fb(f"users/{request.user_id}/name"),
        "amount":amt,"utr":utr,"status":"pending","created_at":ts()
    })
    return jsonify(success=True, message="Deposit request submitted ✅")

@app.route("/api/wallet/withdraw", methods=["POST"])
@require_auth
@limiter.limit("5/hour")
def withdraw():
    d   = request.get_json(silent=True) or {}
    amt = float(d.get("amount",0))
    upi = sanitize(d.get("upi_id","")).strip()
    s   = fb("settings") or {}
    min_w = s.get("min_withdraw", 10)
    if amt < min_w: return jsonify(error=f"Minimum withdrawal ₹{min_w}"), 400
    u = fb(f"users/{request.user_id}")
    if u.get("wallet",0) < amt: return jsonify(error="Insufficient balance"), 400
    fb(f"users/{request.user_id}/wallet", "PUT", round(u["wallet"]-amt, 2))
    wid = uid()
    fb(f"withdrawals/{wid}", "PUT", {
        "user_id":request.user_id,"user_name":u.get("name"),
        "amount":amt,"upi_id":upi,"status":"pending",
        "note":"","created_at":ts(),"processed_at":""
    })
    return jsonify(success=True, message="Withdrawal request submitted ✅")

# ══════════════════════════════════════════════════════════════════════════════
#  REFER
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/refer")
@require_auth
def refer_stats():
    u    = fb(f"users/{request.user_id}")
    refs = fb_list("referrals")
    mine = [r for r in refs if r.get("referrer_id")==request.user_id]
    pct  = (fb("settings") or {}).get("refer_commission", 10)
    base = request.host_url.rstrip("/")
    return jsonify(
        refer_code=u.get("refer_code",""),
        refer_url =f"{base}/?ref={u.get('refer_code','')}",
        commission=pct,
        total_referred =len(mine),
        pending_count  =len([r for r in mine if r.get("status")=="pending"]),
        credited_count =len([r for r in mine if r.get("status")=="credited"]),
        total_earned   =u.get("total_earned",0)
    )

def _credit_referral(user_id: str, order_total: float):
    u = fb(f"users/{user_id}")
    if not u: return
    rid = u.get("referred_by")
    if not rid: return
    pct = (fb("settings") or {}).get("refer_commission", 10)
    amt = round(order_total * pct / 100, 2)
    ref = fb(f"users/{rid}")
    if ref:
        fb(f"users/{rid}/wallet",       "PUT", round(ref.get("wallet",0)+amt, 2))
        fb(f"users/{rid}/total_earned", "PUT", round(ref.get("total_earned",0)+amt, 2))
    for r in fb_list("referrals"):
        if r.get("referrer_id")==rid and r.get("referred_id")==user_id:
            fb(f"referrals/{r['id']}", "PATCH", {"status":"credited","amount":amt})
            break

# ══════════════════════════════════════════════════════════════════════════════
#  REVIEWS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/reviews", methods=["POST"])
@require_auth
@limiter.limit("15/hour")
def add_review():
    d      = request.get_json(silent=True) or {}
    pid    = d.get("product_id","")
    rating = max(1, min(5, int(d.get("rating",5))))
    text   = sanitize(d.get("text","")).strip()
    if not pid or len(text) < 5:
        return jsonify(error="product_id and review text (min 5 chars) required"), 400
    u = fb(f"users/{request.user_id}")
    bought = any(
        any(i.get("product_id")==pid for i in o.get("items",[]))
        for o in fb_list("orders")
        if o.get("user_id")==request.user_id and o.get("payment_status")=="paid"
    )
    fb("reviews","POST",{
        "product_id":pid,"user_id":request.user_id,
        "user_name":u.get("name","Anonymous"),
        "rating":rating,"text":text,
        "verified_purchase":bought,"created_at":ts()
    })
    return jsonify(success=True)

@app.route("/api/reviews/<pid>")
def get_reviews(pid):
    rs = [r for r in fb_list("reviews") if r.get("product_id")==pid]
    rs.sort(key=lambda x:x.get("created_at",""), reverse=True)
    avg = round(sum(r.get("rating",5) for r in rs)/len(rs),1) if rs else 0
    return jsonify(reviews=rs, average=avg, count=len(rs))

# ══════════════════════════════════════════════════════════════════════════════
#  NOTIFICATIONS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/notifications")
def notifications():
    ns = fb_list("notifications")
    ns.sort(key=lambda x:x.get("created_at",""), reverse=True)
    return jsonify(notifications=ns[:10])

# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN — AUTH
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/login", methods=["POST"])
@limiter.limit("10/hour")
def admin_login():
    d = request.get_json(silent=True) or {}
    if d.get("username")==ADMIN_USER and d.get("password")==ADMIN_PASS:
        return jsonify(success=True, token=make_token("admin", is_admin=True))
    time.sleep(1)
    return jsonify(error="Invalid admin credentials"), 401

# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN — STATS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/stats")
@require_admin
def admin_stats():
    users    = fb_list("users")
    orders   = fb_list("orders")
    prods    = fb_list("products")
    cats     = fb_list("categories")
    refs     = fb_list("referrals")
    wds      = fb_list("withdrawals")
    deps     = fb_list("deposits")

    today  = datetime.now(timezone.utc).date().isoformat()
    paid   = [o for o in orders if o.get("payment_status")=="paid"]
    pend   = [o for o in orders if o.get("payment_status") in ["pending","verifying"]]
    failed = [o for o in orders if o.get("payment_status")=="failed"]

    # Revenue by day (last 7)
    rev_by_day = {}
    for o in paid:
        day = o.get("created_at","")[:10]
        rev_by_day[day] = rev_by_day.get(day,0) + o.get("total",0)

    top_wallets = sorted(users, key=lambda x:x.get("wallet",0), reverse=True)[:10]
    ref_counts  = {}
    for r in refs:
        k = r.get("referrer_id","")
        ref_counts[k] = ref_counts.get(k,0)+1
    top_refs = sorted(ref_counts.items(), key=lambda x:x[1], reverse=True)[:10]

    return jsonify(
        total_users=len(users),
        today_users=len([u for u in users if u.get("created_at","")[:10]==today]),
        total_orders=len(orders),
        today_orders=len([o for o in orders if o.get("created_at","")[:10]==today]),
        paid_orders=len(paid), pending_orders=len(pend), failed_orders=len(failed),
        total_revenue=round(sum(o.get("total",0) for o in paid),2),
        today_revenue=round(sum(o.get("total",0) for o in paid if o.get("created_at","")[:10]==today),2),
        total_products=len(prods), total_categories=len(cats),
        total_referrals=len(refs),
        total_wallet=round(sum(u.get("wallet",0) for u in users),2),
        total_earned=round(sum(u.get("total_earned",0) for u in users),2),
        pending_withdrawals=len([w for w in wds if w.get("status")=="pending"]),
        pending_deposits=len([d for d in deps if d.get("status")=="pending"]),
        revenue_chart=rev_by_day,
        top_wallets=[{"name":u.get("name"),"wallet":u.get("wallet",0),"id":u.get("id")} for u in top_wallets],
        top_referrers=[{"id":r[0],"count":r[1]} for r in top_refs],
        total_product_views=sum(p.get("views",0) for p in prods),
        top_products=sorted(prods, key=lambda x:x.get("views",0), reverse=True)[:5],
    )

# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN — USERS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/users")
@require_admin
def admin_users():
    us = fb_list("users")
    for u in us: u.pop("password_hash",None)
    us.sort(key=lambda x:x.get("created_at",""), reverse=True)
    return jsonify(users=us)

@app.route("/api/admin/users/<uid_>", methods=["PATCH","DELETE"])
@require_admin
def admin_user(uid_):
    if request.method=="DELETE":
        fb(f"users/{uid_}","DELETE")
        return jsonify(success=True)
    d = request.get_json(silent=True) or {}
    ok = {k:v for k,v in d.items() if k in ["wallet","is_active","name","note"]}
    if not ok: return jsonify(error="Nothing to update"),400
    fb(f"users/{uid_}","PATCH",ok)
    return jsonify(success=True)

# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN — CATEGORIES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/categories", methods=["GET","POST"])
@require_admin
def admin_cats():
    if request.method=="GET":
        return jsonify(categories=fb_list("categories"))
    d = request.get_json(silent=True) or {}
    if not d.get("name"): return jsonify(error="name required"),400
    cid = uid()
    fb(f"categories/{cid}","PUT",{
        "name":sanitize(d["name"]), "icon":sanitize(d.get("icon","📦")),
        "color":sanitize(d.get("color","#7c3aed")), "order":int(d.get("order",99)),
        "active":True, "created_at":ts()
    })
    return jsonify(success=True, id=cid)

@app.route("/api/admin/categories/<cid>", methods=["PATCH","DELETE"])
@require_admin
def admin_cat(cid):
    if request.method=="DELETE":
        fb(f"categories/{cid}","DELETE"); return jsonify(success=True)
    d = request.get_json(silent=True) or {}
    for k in ["name","icon","color"]:
        if k in d: d[k]=sanitize(d[k])
    fb(f"categories/{cid}","PATCH",d)
    return jsonify(success=True)

# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN — PRODUCTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/products", methods=["GET","POST"])
@require_admin
def admin_prods():
    if request.method=="GET":
        ps = fb_list("products")
        ps.sort(key=lambda x:x.get("created_at",""), reverse=True)
        return jsonify(products=ps)
    d = request.get_json(silent=True) or {}
    for r in ["name","category_id","price"]:
        if r not in d: return jsonify(error=f"{r} required"),400
    pid = uid()
    fb(f"products/{pid}","PUT",{
        "name":sanitize(d["name"]), "category_id":d["category_id"],
        "price":float(d["price"]),
        "original_price":float(d.get("original_price",d["price"])),
        "description":sanitize(d.get("description",""),2000),
        "image":sanitize(d.get("image","")),
        "stock":int(d.get("stock",-1)),
        "views":0, "active":True,
        "fields":d.get("fields",[]),
        "created_at":ts()
    })
    return jsonify(success=True, id=pid)

@app.route("/api/admin/products/<pid>", methods=["PATCH","DELETE"])
@require_admin
def admin_prod(pid):
    if request.method=="DELETE":
        fb(f"products/{pid}","DELETE"); return jsonify(success=True)
    d = request.get_json(silent=True) or {}
    for k in ["name","description","image"]:
        if k in d: d[k]=sanitize(d[k])
    if "price" in d:          d["price"]=float(d["price"])
    if "original_price" in d: d["original_price"]=float(d["original_price"])
    fb(f"products/{pid}","PATCH",d)
    return jsonify(success=True)

# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN — ORDERS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/orders")
@require_admin
def admin_orders():
    s = request.args.get("start",""); e = request.args.get("end","")
    status = request.args.get("status","")
    os_ = fb_list("orders")
    if s:      os_ = [o for o in os_ if o.get("created_at","")[:10]>=s]
    if e:      os_ = [o for o in os_ if o.get("created_at","")[:10]<=e]
    if status: os_ = [o for o in os_ if o.get("payment_status")==status]
    os_.sort(key=lambda x:x.get("created_at",""), reverse=True)
    return jsonify(orders=os_)

@app.route("/api/admin/orders/<oid>", methods=["PATCH"])
@require_admin
def admin_order(oid):
    d = request.get_json(silent=True) or {}
    order = fb(f"orders/{oid}")
    if not order: return jsonify(error="Not found"),404
    update = {k:v for k,v in d.items() if k in ["payment_status","order_status","note"]}
    update["updated_at"] = ts()
    if d.get("payment_status")=="paid" and order.get("payment_status")!="paid":
        uid_ = order.get("user_id"); tot = order.get("total",0)
        u    = fb(f"users/{uid_}")
        if u:
            fb(f"users/{uid_}/total_spent","PUT",round(u.get("total_spent",0)+tot,2))
        _credit_referral(uid_, tot)
    if d.get("payment_status")=="failed": update["order_status"]="failed"
    fb(f"orders/{oid}","PATCH",update)
    return jsonify(success=True)

# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN — DEPOSITS & WITHDRAWALS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/deposits")
@require_admin
def admin_deposits():
    ds = fb_list("deposits")
    ds.sort(key=lambda x:x.get("created_at",""), reverse=True)
    return jsonify(deposits=ds)

@app.route("/api/admin/deposits/<did>", methods=["PATCH"])
@require_admin
def admin_deposit(did):
    d   = request.get_json(silent=True) or {}
    dep = fb(f"deposits/{did}")
    if not dep: return jsonify(error="Not found"),404
    if d.get("status")=="approved" and dep.get("status")!="approved":
        u = fb(f"users/{dep['user_id']}")
        if u:
            fb(f"users/{dep['user_id']}/wallet","PUT",round(u.get("wallet",0)+dep.get("amount",0),2))
    fb(f"deposits/{did}","PATCH",{"status":d.get("status"),"updated_at":ts()})
    return jsonify(success=True)

@app.route("/api/admin/withdrawals")
@require_admin
def admin_wds():
    ws = fb_list("withdrawals")
    ws.sort(key=lambda x:x.get("created_at",""), reverse=True)
    return jsonify(withdrawals=ws)

@app.route("/api/admin/withdrawals/<wid>", methods=["PATCH"])
@require_admin
def admin_wd(wid):
    d  = request.get_json(silent=True) or {}
    wd = fb(f"withdrawals/{wid}")
    if not wd: return jsonify(error="Not found"),404
    if d.get("status")=="failed" and wd.get("status")=="pending":
        u = fb(f"users/{wd['user_id']}")
        if u:
            fb(f"users/{wd['user_id']}/wallet","PUT",round(u.get("wallet",0)+wd.get("amount",0),2))
    fb(f"withdrawals/{wid}","PATCH",{"status":d.get("status"),"note":d.get("note",""),"processed_at":ts()})
    return jsonify(success=True)

# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN — SETTINGS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/settings", methods=["GET","PATCH"])
@require_admin
def admin_settings():
    if request.method=="GET":
        return jsonify(settings=fb("settings") or {})
    d = request.get_json(silent=True) or {}
    fb("settings","PATCH",d)
    return jsonify(success=True)

# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN — BROADCAST
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/broadcast", methods=["POST"])
@require_admin
def broadcast():
    d = request.get_json(silent=True) or {}
    nid = uid()
    fb(f"notifications/{nid}","PUT",{
        "title":  sanitize(d.get("title","")),
        "message":sanitize(d.get("message",""),2000),
        "image":  sanitize(d.get("image","")),
        "created_at":ts()
    })
    return jsonify(success=True, id=nid)

# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN — REVIEWS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/reviews")
@require_admin
def admin_reviews():
    rs = fb_list("reviews")
    rs.sort(key=lambda x:x.get("created_at",""), reverse=True)
    return jsonify(reviews=rs)

@app.route("/api/admin/reviews/<rid>", methods=["DELETE"])
@require_admin
def admin_del_review(rid):
    fb(f"reviews/{rid}","DELETE")
    return jsonify(success=True)

# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN — VISITOR LOGS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/logs")
@require_admin
def admin_logs():
    logs = fb_list("visitor_logs")
    logs.sort(key=lambda x:x.get("timestamp",""), reverse=True)
    return jsonify(logs=logs[:200])

# ══════════════════════════════════════════════════════════════════════════════
#  PAGE ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
@app.route("/<path:p>")
def shop(p=""):
    if p.startswith("admin"): return render_template("admin.html")
    return render_template("shop.html")

# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
