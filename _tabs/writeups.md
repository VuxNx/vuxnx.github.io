---
title: Writeups
icon: fas fa-flag
order: 4
---

<div class="writeups-list">

  {% for post in site.categories.writeups %}
    <article class="writeup-entry">
      <h3><a href="{{ post.url }}">{{ post.title }}</a></h3>
      <p class="meta">
        🗓️ {{ post.date | date: "%B %d, %Y" }} &nbsp;|&nbsp; 🏷️ 
        {% for tag in post.tags %}
          <span class="tag">{{ tag }}</span>{% unless forloop.last %}, {% endunless %}
        {% endfor %}
      </p>
      <p>{{ post.excerpt | strip_html | truncatewords: 30 }}</p>
    </article>
    <hr>
  {% endfor %}

</div>
