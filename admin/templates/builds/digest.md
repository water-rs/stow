<!-- stow-builds-digest -->
**{{ total }} failed `build-crate.yml` run(s)** — {{ since }} → {{ until }} UTC

| class | runs |
| --- | --- |
{% for row in class_counts -%}
| {{ row.name }} | {{ row.runs }} |
{% endfor %}

| target | runs |
| --- | --- |
{% for row in target_counts -%}
| `{{ row.name }}` | {{ row.runs }} |
{% endfor %}
{% for group in groups %}
## {{ group.label }} — {{ group.runs }} run(s)

{% for krate in group.crates -%}
- **{{ krate.crate_name }} {{ krate.version }}**
{% for failure in krate.failures %}
  - `{{ failure.target }}`{% if failure.host_side %} (host side){% endif %} — `{{ failure.job }}`{% if let Some(step) = failure.step %} / `{{ step }}`{% endif %} — [run]({{ failure.run_url }})
    {%- if let Some(line) = failure.error_line %}
    first error: `{{ line }}`
    {%- endif %}
{% endfor -%}
{% endfor -%}
{% endfor %}
