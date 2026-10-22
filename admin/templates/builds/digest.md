<!-- stow-builds-digest -->
**{{ failed_legs }} failed leg(s) across {{ failed_runs }} failed `build-batch.yml` run(s)** — {{ since }} → {{ until }} UTC

| class | legs |
| --- | --- |
{% for row in class_counts -%}
| {{ row.name }} | {{ row.legs }} |
{% endfor %}

| target | legs |
| --- | --- |
{% for row in target_counts -%}
| `{{ row.name }}` | {{ row.legs }} |
{% endfor %}
{% for group in groups %}
## {{ group.label }} — {{ group.legs }} leg(s)

{% for krate in group.crates -%}
- **{{ krate.crate_name }} {{ krate.version }}**
{% for failure in krate.failures %}
  - `{{ failure.target }}` — `{{ failure.job }}`{% if let Some(step) = failure.step %} / `{{ step }}`{% endif %} — [run]({{ failure.run_url }})
    {%- if let Some(line) = failure.error_line %}
    first error: `{{ line }}`
    {%- endif %}
{% endfor -%}
{% endfor -%}
{% endfor %}
