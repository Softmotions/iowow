# Heap out-of-bounds read in `_jbl_ptr_pool()` for a JSON-pointer token that is a lone `~` (CWE-125)

## Summary

`_jbl_ptr_pool()` (`src/json/iwjson.c`), the JSON-pointer parser behind the
public `jbl_ptr_alloc()` / `jbl_ptr_alloc_pool()` API, reads one byte past the
end of its heap buffer when a path token is a **lone `~`** (a `~` immediately
followed by the NUL terminator).

In the RFC 6901 `~0`/`~1` decoder the index was advanced unconditionally:

```c
if (path[i] == '~') {
  if (path[i + 1] == '0')      { *(jp->n[cnt] + k) = '~'; }
  else if (path[i + 1] == '1') { *(jp->n[cnt] + k) = '/'; }
  ++i;                         /* <-- advanced even when neither escape matched */
}
```

For a trailing `~`, `path[i + 1]` is `'\0'`, neither branch matches, but `++i`
still runs. The index now points at the NUL; the loop header's `++i` then
advances it one byte **past** the NUL, and the next bounds test `!path[i]`
reads outside the allocation.

- **Sanitizer**: AddressSanitizer reports a 1-byte `heap-buffer-overflow`
  (`READ of size 1`, `0 bytes to the right` of the allocation).
- **CWE**: CWE-125 (Out-of-bounds Read).

## Reproduction

Minimal, using the public iowow API (a 2-byte path):

```c
struct jbl_ptr *p = NULL;
jbl_ptr_alloc("/~", &p);   /* ASan: heap-buffer-overflow READ in _jbl_ptr_pool */
```

```
READ of size 1 at 0x6040000000b2
0x6040000000b2 is located 0 bytes to the right of 34-byte region [...]
    #0 _jbl_ptr_pool    src/json/iwjson.c
    #1 jbl_ptr_alloc    src/json/iwjson.c:1141
```

## Impact

Reachable from the public JSON-pointer API and from EJDB2 JQL `order by`
clauses whose path value ends in `~` (the JQL layer builds `"/" + value` and
calls `jbl_ptr_alloc_pool()`). A 10-byte JQL query `/a |asc /~` on an
untrusted collection reproduces it through `jql_create2()`:

```
READ of size 1
    #0 _jbl_ptr_pool   iowow src/json/iwjson.c:1116
    #1 _jqp_finish     ejdb  src/jql/inc/jqpx.c:961
    #2 yy_6_QUERY      ejdb  src/jql/jqp.leg:86
```

## Fix

Advance the index only when the two-character escape was actually consumed;
otherwise copy the `~` literally:

```c
if (path[i] == '~') {
  if (path[i + 1] == '0')      { *(jp->n[cnt] + k) = '~'; ++i; }
  else if (path[i + 1] == '1') { *(jp->n[cnt] + k) = '/'; ++i; }
  else                         { *(jp->n[cnt] + k) = '~'; }
}
```

The `jbl_test1` suite gained regression cases for `/~`, `/foo~`, and `/foo/~`.
