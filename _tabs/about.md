---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

<section style="line-height: 1.8; max-width: 760px; margin: auto; font-family: sans-serif; padding: 2rem 1rem;">

  <div style="text-align: center; margin-bottom: 2rem;" class="fade-in">
    <img src="/assets/img/avatar.jpg" alt="avatar" style="border-radius: 50%; width: 120px; box-shadow: 0 0 10px rgba(0,0,0,0.15);">
    <h1 style="margin-top: 1rem;">Vu Trong Nghia (VuxNx)</h1>
    <p style="color: var(--text-secondary); font-size: 1rem;">
      Student at HCMUT · Member of BKISC<br>
      Focus: Web exploitation · Security research · CTFs
    </p>
  </div>

<hr style="border: none; border-top: 1px solid #ccc;">

<h2>About Me</h2>

<p class="fade-in">
  I’m a cybersecurity enthusiast currently studying at Ho Chi Minh City University of Technology (HCMUT), and a member of BKISC.
  My main area of interest is web exploitation and real-world vulnerability research. I enjoy breaking, analyzing, and understanding the internals of modern applications, and writing about them.
</p>

<hr style="border: none; border-top: 1px solid #ccc;">

<h2>Focus Areas</h2>

<ul class="fade-in">
  <li>Web vulnerabilities: XSS, SQLi, IDOR, SSTI, logic bugs</li>
  <li>Analyzing obfuscated or malicious JavaScript/PHP</li>
  <li>Studying CVEs and developing PoCs</li>
  <li>Occasionally explore binary exploitation and malware behavior</li>
</ul>

<hr style="border: none; border-top: 1px solid #ccc;">

<h2>CTF Achievements</h2>

<ul class="fade-in">
  <li><strong>Integirty CTF</strong> – 2nd place (BKISC team)</li>
  <li><strong>Hacktheon Sejong (Qualifiers)</strong> – Top 14 (Chicken Hunter team)</li>
  <li><strong>Hacktheon Sejong (Final Round)</strong> – Finalist in Sejong, Korea (Chicken Hunter team)</li>
</ul>

<hr style="border: none; border-top: 1px solid #ccc;">

<h2>Tech Stack</h2>

<ul class="fade-in">
  <li><strong>Languages:</strong> Python, JavaScript, Bash, C/C++, Java</li>
  <li><strong>Web pentest tools:</strong> Burp Suite, Postman, mitmproxy, ffuf, sqlmap, feroxbuster</li>
  <li><strong>Reversing/analysis tools:</strong> Ghidra, IDA, Wireshark</li>
  <li><strong>Other:</strong> Docker, Git, Linux, tmux</li>
</ul>

<hr style="border: none; border-top: 1px solid #ccc;">

<h2>Timeline</h2>

<div class="timeline fade-in">
  <div class="event">
    <div class="year">2023</div>
    <div class="desc">Started CTFs and learning security foundations</div>
  </div>
  <div class="event">
    <div class="year">2024</div>
    <div class="desc">Wrote technical writeups and joined CTF teams</div>
  </div>
  <div class="event">
    <div class="year">2025</div>
    <div class="desc">Focused on vulnerability research and deep dives</div>
  </div>
</div>

<hr style="border: none; border-top: 1px solid #ccc;">

<h2>Contact</h2>

<ul class="fade-in">
  <li>Email: <a href="mailto:trongnghiavu649@gmail.com">trongnghiavu649@gmail.com</a></li>
  <li>GitHub: <a href="https://github.com/VuxNx" target="_blank">github.com/VuxNx</a></li>
</ul>

<p style="margin-top: 3rem; font-style: italic; color: var(--text-secondary); text-align: center;" class="fade-in">
  “The hacker mindset doesn't actually see what happens on the other side, to the victim.” <br>- Kevin Mitnick
</p>

</section>

<style>
:root {
  --text-secondary: #555;
}

@media (prefers-color-scheme: dark) {
  :root {
    --text-secondary: #aaa;
  }
}

.timeline {
  border-left: 3px solid #38bdf8;
  margin: 1.5rem 0;
  padding-left: 1.2rem;
}
.event {
  margin-bottom: 1rem;
}
.event .year {
  font-weight: bold;
  color: #38bdf8;
}
.event .desc {
  margin-left: 0.5rem;
}

hr {
  border: none;
  border-top: 1px solid rgba(128,128,128,0.3);
  margin: 2rem 0;
}

.fade-in {
  opacity: 0;
  transform: translateY(10px);
  transition: opacity 0.6s ease-out, transform 0.6s ease-out;
}
.fade-in.visible {
  opacity: 1;
  transform: none;
}
</style>

<script>
document.addEventListener("DOMContentLoaded", function () {
  const faders = document.querySelectorAll('.fade-in');
  const appearOptions = {
    threshold: 0.1,
    rootMargin: "0px 0px -50px 0px"
  };

  const appearOnScroll = new IntersectionObserver(function(entries, observer) {
    entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add("visible");
      observer.unobserve(entry.target);
    });
  }, appearOptions);

  faders.forEach(fader => appearOnScroll.observe(fader));
});
</script>
