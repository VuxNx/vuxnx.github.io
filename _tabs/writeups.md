---
title: Writeups
icon: fas fa-flag
order: 5
---
<ul>
  {% for post in site.categories.writeups %}
    <li><a href="{{ post.url }}">{{ post.title }}</a></li>
  {% endfor %}
</ul>
