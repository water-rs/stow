<!-- stow-watchdog:incident -->
## stow watchdog — {{ now }} UTC{% if dry_run %} (dry run){% endif %}

Breaching signals, observed against threshold:

| signal | window | observed | threshold | effect |
| --- | --- | --- | --- | --- |
{% for breach in breaches -%}
| `{{ breach.id }}` — {{ breach.label }} | {{ breach.window }} | {{ breach.observed }} | {{ breach.threshold }} | {{ breach.effect }} |
{% endfor %}
{% for breach in breaches -%}
{% if !breach.evidence.is_empty() %}
- `{{ breach.id }}`:
  {% for line in breach.evidence -%}
  - {{ line }}
  {% endfor %}
{% endif -%}
{% endfor %}

{% if !actions.is_empty() %}
Breaker actions this run:
{% for action in actions -%}
- {{ action }}
{% endfor %}
{% else %}
No breaker action (alert-only signals breach, or nothing was applicable).
{% endif %}

{% if !failures.is_empty() %}
Watchdog partial failures:
{% for failure in failures -%}
- {{ failure }}
{% endfor %}
{% endif %}

The watchdog does not un-trip on its own — recovery is manual:
`stow-admin watchdog clear`.
