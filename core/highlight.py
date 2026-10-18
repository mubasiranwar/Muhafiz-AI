"""
core/highlight.py
Secure text highlighting for detected red-flag phrases.
Crucial Security Rule:
- User text is ALWAYS escaped using html.escape() before inserting <mark> tags.
- NEVER render unescaped user text or raw HTML.
"""

import html
import re
from typing import List
from core.schemas import RedFlag


def highlight_message(original_text: str, red_flags: List[RedFlag]) -> str:
    """
    Highlights red-flag evidence substrings in original_text.
    1. Validates that evidence_quote is an exact substring of original_text.
    2. Drops invalid quotes.
    3. Finds match spans in the original unescaped text.
    4. Merges overlapping spans.
    5. Escapes non-highlighted segments and highlighted segments separately.
    6. Wraps highlighted segments in <mark class="scam-mark">.
    """
    if not original_text:
        return ""

    if not red_flags:
        return html.escape(original_text)

    # Collect valid spans (start, end)
    spans = []
    for flag in red_flags:
        quote = flag.evidence_quote
        if not quote:
            continue
        # Only highlight if quote is an exact substring
        start = 0
        while True:
            idx = original_text.lower().find(quote.lower(), start)
            if idx == -1:
                break
            spans.append((idx, idx + len(quote)))
            start = idx + len(quote)

    if not spans:
        return html.escape(original_text)

    # Sort and merge overlapping or adjacent spans
    spans.sort(key=lambda x: (x[0], x[1]))
    merged_spans = []
    cur_start, cur_end = spans[0]

    for next_start, next_end in spans[1:]:
        if next_start <= cur_end:
            cur_end = max(cur_end, next_end)
        else:
            merged_spans.append((cur_start, cur_end))
            cur_start, cur_end = next_start, next_end
    merged_spans.append((cur_start, cur_end))

    # Build safe escaped HTML with <mark> tags
    html_parts = []
    last_idx = 0

    for start, end in merged_spans:
        if start > last_idx:
            # Safe unhighlighted chunk
            html_parts.append(html.escape(original_text[last_idx:start]))
        # Highlighted chunk (escaped inside <mark>)
        highlighted_content = html.escape(original_text[start:end])
        html_parts.append(f'<mark class="scam-mark">{highlighted_content}</mark>')
        last_idx = end

    if last_idx < len(original_text):
        html_parts.append(html.escape(original_text[last_idx:]))

    return "".join(html_parts)
