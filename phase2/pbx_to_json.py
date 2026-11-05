#!/usr/bin/env python3
"""Convert a classic `key = value;` plist .pbxproj into a JSON-plist pbxproj (for Xcode 26)."""
import json, sys

def tokenize(s):
    """Return list of (kind, value). For arr/dict, value is a nested token list."""
    i, n = 0, len(s)
    toks = []
    while i < n:
        c = s[i]
        if c == '/' and i+1 < n and s[i+1] == '*':
            j = s.index('*/', i+2); i = j+2; continue
        if c in ' \t\r\n,;':
            i += 1; continue
        if c == '(':
            depth, j, buf = 1, i+1, []
            while depth and j < n:
                if s[j] == '(': depth += 1
                elif s[j] == ')': depth -= 1
                if depth: buf.append(s[j])
                j += 1
            toks.append(('arr', tokenize(''.join(buf))))
            i = j; continue
        if c == '{':
            depth, j, buf = 1, i+1, []
            while depth and j < n:
                if s[j] == '{': depth += 1
                elif s[j] == '}': depth -= 1
                if depth: buf.append(s[j])
                j += 1
            toks.append(('dict', tokenize(''.join(buf))))
            i = j; continue
        if c == '"':
            j = i+1
            while j < n and s[j] != '"': j += 1
            toks.append(('str', s[i+1:j])); i = j+1; continue
        if c.isalpha() or c == '<':
            j = i
            while j < n and s[j] not in ' \t\r\n,;(){}"': j += 1
            toks.append(('id', s[i:j])); i = j; continue
        j = i
        while j < n and s[j] not in ' \t\r\n,;(){}"': j += 1
        toks.append(('num', s[i:j])); i = j; continue
    return toks

def parse_val(toks):
    if not toks: return []
    kind, val = toks[0]
    if kind == 'arr':
        return [parse_val([tok]) for tok in val]
    if kind == 'dict':
        out = {}
        pairs = [t for t in val]
        for i in range(0, len(pairs)-1, 2):
            k = pairs[i][1]
            out[k] = parse_val([pairs[i+1]])
        return out
    return val  # str/id/num

with open(sys.argv[1]) as f:
    txt = f.read()
tokens = tokenize(txt)
# The classic root is an unwrapped `key = value;` pair sequence (no braces).
if tokens and tokens[0][0] in ('id', 'str') and len(tokens) >= 2 and tokens[1][0] in ('num', 'str', 'id'):
    data = {}
    for i in range(0, len(tokens)-1, 2):
        data[tokens[i][1]] = parse_val([tokens[i+1]])
else:
    data = parse_val(tokens)
with open(sys.argv[2], 'w') as f:
    json.dump(data, f, indent=2, sort_keys=True)
print("converted ->", sys.argv[2], "objects:", len(data.get('objects', {})))
