# About

<section style="line-height: 1.8; max-width: 760px; margin: auto; font-family: sans-serif; padding: 2rem 1rem;">

  <div style="text-align: center; margin-bottom: 2rem;" class="fade-in">
    <h1 style="margin-top: 1rem;">Vu Trong Nghia (VuxNx)</h1>
    <p style="color: var(--text-secondary); font-size: 1rem;">
      Student at HCMUT · Member of BKISC<br>
      Focus: Web exploitation · Security research · Red Team · CTFs
    </p>
  </div>

---

<h2>About Me</h2>

<p class="fade-in">
  I’m a cybersecurity enthusiast currently studying at Ho Chi Minh City University of Technology (HCMUT), and a member of BKISC.
  My main area of interest is red team, web exploitation and real-world vulnerability research. I enjoy breaking, analyzing, and understanding the internals of modern applications, and writing about them.
</p>

---

<h2>Focus Areas</h2>

<ul class="fade-in">
  <li>Web vulnerabilities: XSS, SQLi, IDOR, SSTI, logic bugs</li>
  <li>Analyzing obfuscated or malicious JavaScript/PHP</li>
  <li>Studying CVEs and developing PoCs</li>
  <li>Occasionally explore binary exploitation and malware behavior</li>
</ul>

---

<h2>CTF Achievements</h2>

<div class="ctf-grid fade-in">
  <div class="ctf-card">
    <span class="ctf-icon">🥈</span>
    <div>
      <strong>Intigriti CTF</strong><br>
      2nd Place – BKISC Team
    </div>
  </div>
  <div class="ctf-card">
    <span class="ctf-icon">🏅</span>
    <div>
      <strong>Hacktheon Sejong – Qualifiers</strong><br>
      Top 14 – Chicken Hunter Team
    </div>
  </div>
  <div class="ctf-card">
    <span class="ctf-icon">🏅</span>
    <div>
      <strong>GPN CTF 2025</strong><br>
      Top 7 out of 1,064 teams – BKISC Team
    </div>
  </div>
  <div class="ctf-card">
    <span class="ctf-icon">🏅</span>
    <div>
      <strong>Hacktheon Sejong – Final Round</strong><br>
      Finalist – Sejong, Korea (Chicken Hunter Team)
    </div>
  </div>
  <div class="ctf-card">
    <span class="ctf-icon">🏅</span>
    <div>
      <strong>HCMUS-CTF Finals</strong><br>
      Top 7 (Jitenshas Team)
    </div>
  </div>
  <div class="ctf-card">
    <span class="ctf-icon">🥈</span>
    <div>
      <strong>HDBank Hackathon CyberSecurity Track Finals</strong><br>
      Top 2 (0v3rc1ock Team)
    </div>
  </div>
  <div class="ctf-card">
    <span class="ctf-icon">🥈</span>
    <div>
      <strong>International Standoff 16 Cyberbattle Finals</strong><br>
      Top 10 (BKISC Team)
    </div>
  </div>
</div>

---

<h2>Tech Stack</h2>

<ul class="fade-in">
  <li><strong>Languages:</strong> Python, JavaScript, Bash, C/C++, Java</li>
  <li><strong>Web pentest tools:</strong> Burp Suite, Postman, mitmproxy, ffuf, sqlmap, feroxbuster</li>
  <li><strong>Reversing/analysis tools:</strong> Ghidra, IDA, Wireshark</li>
  <li><strong>Other:</strong> Docker, Git, Linux, tmux</li>
</ul>

---

<h2>Timeline</h2>

<div class="timeline fade-in">
<div class="event">
    <div class="year">2025</div>
    <div class="desc">Focused on vulnerability research and deep dives</div>
  </div>
  <div class="event">
    <div class="year">2024</div>
    <div class="desc">Wrote technical writeups and joined CTF teams</div>
  </div>
  <div class="event">
    <div class="year">2023</div>
    <div class="desc">Started CTFs and learning security foundations</div>
  </div>
  
</div>

---

<h2>Contact</h2>

<ul class="fade-in">
  <li>Email: <a href="mailto:trongnghiavu649@gmail.com">trongnghiavu649@gmail.com</a></li>
  <li>GitHub: <a href="https://github.com/VuxNx" target="_blank">github.com/VuxNx</a></li>
</ul>

---

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

.ctf-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 1.2rem;
  margin-top: 1rem;
}

.ctf-card {
  display: flex;
  align-items: flex-start;
  background: rgba(0, 0, 0, 0.02);
  padding: 1rem 1.2rem;
  border-radius: 12px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.05);
  transition: 0.3s ease;
  gap: 0.75rem;
}

.ctf-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

.ctf-icon {
  font-size: 1.4rem;
  margin-top: 0.1rem;
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
