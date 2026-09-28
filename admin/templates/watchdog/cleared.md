<!-- stow-watchdog:clear -->
**incident cleared — {{ now }} UTC**

{% if !actions.is_empty() -%}
Actions applied:
{% for action in actions -%}
- {{ action }}
{% endfor %}
{% endif -%}
