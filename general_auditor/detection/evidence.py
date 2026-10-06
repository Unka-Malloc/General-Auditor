"""Exact evidence assembled only from the bytes selected by the local scanner."""
from bisect import bisect_right


def source_evidence(text, *, start=None, end=None, line=None, line_starts=None):
    starts = line_starts if line_starts is not None else [0] + [i + 1 for i, c in enumerate(text) if c == '\n']
    literal = start is not None and end is not None
    index = bisect_right(starts, start) - 1 if literal else max(0, min((line or 1) - 1, len(starts) - 1))
    last = bisect_right(starts, max(start, end - 1)) - 1 if literal else index
    first_line, last_line = max(0, index - 2), min(len(starts) - 1, last + 2)
    stop = starts[last_line + 1] if last_line + 1 < len(starts) else len(text)
    result = {'kind': 'literal_match' if literal else 'derived',
              'context': {'text': text[starts[first_line]:stop], 'start_line': first_line + 1, 'end_line': last_line + 1}}
    if literal:
        result.update(matched_text=text[start:end], span={'start': start, 'end': end, 'unit': 'unicode_codepoint'})
    return result
