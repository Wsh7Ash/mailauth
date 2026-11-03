"""Contract checker for a single-file, master-prompt-shaped cybersecurity skill.

The package ships one thing of substance (``SKILL.md`` at the repository root) and
the machinery that proves the file meets the written contract:

* flat YAML frontmatter with sixteen required machine-readable keys,
* sixteen body sections ``A``..``P`` in order, each above a word floor,
* hygiene rules for placeholders, code fences, references and authorization text.

Nothing here contacts the network, sends mail, or resolves DNS. It reads a file.
"""

from .contract import (  # noqa: F401
    AUTHORITATIVE_HOSTS,
    REQUIRED_FRONTMATTER,
    SECTIONS,
    Finding,
    Report,
    analyse,
    render_text,
    split_frontmatter,
)

__all__ = [
    "AUTHORITATIVE_HOSTS",
    "REQUIRED_FRONTMATTER",
    "SECTIONS",
    "Finding",
    "Report",
    "analyse",
    "render_text",
    "split_frontmatter",
]

__version__ = "1.0.0"
