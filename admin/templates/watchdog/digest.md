<!-- stow-watchdog:update -->
**still breaching — {{ now }} UTC**

| signal | window | observed | threshold | effect |
| --- | --- | --- | --- | --- |
{% for breach in breaches -%}
| `{{ breach.id }}` | {{ breach.window }} | {{ breach.observed }} | {{ breach.threshold }} | {{ breach.effect }} |
{% endfor %}

{% if !actions.is_empty() -%}
Actions so far: {{ actions|join("; ") }}
{% endif -%}
{% if !failures.is_empty() -%}
Watchdog failures: {{ failures|join("; ") }}
{% endif %}
