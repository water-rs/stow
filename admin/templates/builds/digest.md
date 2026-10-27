<!-- stow-builds-digest -->
**{{ failed_tasks }} failed task(s) across {{ failed_runs }} failed `build-crate.yml` run(s)** — {{ since }} → {{ until }} UTC

| class | tasks |
| --- | --- |
{% for row in class_counts -%}
| {{ row.name }} | {{ row.tasks }} |
{% endfor %}

| target | tasks |
| --- | --- |
{% for row in target_counts -%}
| `{{ row.name }}` | {{ row.tasks }} |
{% endfor %}
{% for group in groups %}
## {{ group.label }} — {{ group.tasks }} task(s)

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
