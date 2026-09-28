# Feed Authority artifact format

This document describes every byte-level format this repository reads or writes, the
canonical text encoding used for identity and integrity, and the bounds that apply to
each. It is the normative description; the implementation in `src/detail/` follows it.

## 1. Canonical text encoding

Canonical text is ASCII, line oriented, and unambiguous. It is used for policy and
input fingerprints, for the payload of a stored generation, and for the scenario
reader's line syntax.

* One record per line, terminated by a single `\n` (0x0A). No carriage return, no
  trailing whitespace, no empty lines, no comments.
* A record is a lowercase token type followed by zero or more fields, separated by
  single spaces: `type key=value key=value`.
* Keys are lowercase tokens: `[a-z0-9_]{1,64}`. A record's fields appear in a fixed
  documented order; the reader consumes them positionally and refuses a wrong key, a
  missing field, an extra field or a duplicated key.
* Values have exactly one of these forms:
  * unsigned decimal: digits only, no sign, no leading zero unless the value is
    exactly `0`, at most 20 characters;
  * signed decimal: optional `-`, digits only, no leading zero, at most 20
    characters;
  * boolean: `true` or `false`;
  * token: `[a-z0-9_]{1,64}`;
  * text: double quoted, with `\\` and `\"` as the only escapes, all other
    characters in the printable ASCII range 0x20..0x7E, at most `Limits::max_text_length`
    characters;
  * digest: exactly 64 lowercase hexadecimal characters.
* Every collection is emitted sorted by identity, every observation list sorted by
  evidence-source identity, and every optional value as an explicit sentinel
  (empty text, `0`, or the token `none`). Two logically equal values therefore
  always encode to identical bytes, whatever order their parts were supplied in.
* The reader enforces `Limits::max_payload_line_bytes` per line, a bounded record
  count and a bounded total payload.

## 2. Store layout

```
<root>/
  authority.lock          cross-process advisory lock file, never written to
  head.marker              the committed head (fixed 176 bytes)
  generations/             verified generations, oldest first, bounded retention
    gen-<19 digits>.fas
  staging/                 staging files; never authoritative, always removable
```

The root is validated before use: path components must not be `..`, must not end in
a space or a dot, must not be a reserved device name, must be printable and valid
Unicode, and the root must be a directory. A root that is a symbolic link, junction or
other reparse point is refused unless the caller sets `OpenOptions::allow_reparse_root`.

## 3. Generation file

Fixed little-endian framing with a SHA-256 integrity digest.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | magic `FEEDAUTH` |
| 8 | 4 | format version (u32 little-endian, currently 1) |
| 12 | 4 | header size (u32 little-endian, 72) |
| 16 | 8 | payload size (u64 little-endian) |
| 24 | 32 | SHA-256 of the payload bytes |
| 56 | 16 | reserved, all zero |
| 72 | payload size | canonical payload (section 4) |
| 72 + payload size | 8 | trailer magic `FAEND001` |
| 80 + payload size | 8 | payload size repeated (u64 little-endian) |

A file is accepted only when the magic, the version, the header size, the declared
payload size, the total file size, the trailer magic, the repeated size and the
payload digest all agree. A version field of `0x01000000` is reported as an
endianness mismatch rather than as an unsupported version. The declared payload size
is bounded by `Limits::max_generation_bytes` before anything is allocated.

## 4. Generation payload

The payload is canonical text (section 1) with this record sequence:

```
state v=1
counters seq epoch decision lease grant_seq emergency_seq event_seq sections grants emergencies attempts events
sections: for h = 0..sections-1
  section_begin h
  <input generation records, section 5>
  section_end h
<grants records, section 6>
<emergency authorization records, section 7>
<attempt records, section 8>
<event records, section 9>
```

Section 0 is the current adopted input generation; higher ordinals are retained
history, oldest first. The decoder decodes the whole payload, re-encodes what it
decoded, and refuses the artifact unless the two byte sequences are identical: the
payload must therefore be exactly the canonical form, not merely parseable.
Cross-record consistency is checked as well: grant identities may not exceed the grant
sequence, event sequences may not exceed the event counter, no record may carry an
epoch newer than the state epoch, and attempts may not be recorded after the state
sequence.

## 5. Input generation records

```
generation topology policy control evidence
feed id source role domain protected obs_n
obs_feed feed decl value at max_age src
load id class protected
link feed load role domain obs_n
obs_link load feed decl value at max_age src
maint feed window obs_n
obs_maint feed window decl value at max_age src
obs_state decl value at max_age src
option ranking emergency
rank_role ordinal value
rule id prec rank effect path reason fresh overridable note feed load source class role cond_n expo_n dom_n
rule_cond id value
rule_expo id value
rule_dom id value
obligation id class protected_loads capability domains overridable reason note loads_n roles_n sources_n
obligation_load id value
obligation_role id value
obligation_source id value
```

Observation records carry `decl` (`known`, `unknown`, `unsupported`,
`unavailable`), an optional `value` token, the observation instant `at` in
nanoseconds since the Unix epoch, the validity window `max_age` in nanoseconds, and
the evidence source `src`. An observation that is not `known` must carry
`value=unknown`, `at=0` and `max_age=0`; a `known` observation must carry a
non-zero window. Freshness is never stored: it is derived at an explicit instant.

## 6. Grant records

```
grant id load feed path epoch topo pol ctrl ev dgen dfp issued expires revoked rev_at rev_by rev_reason reval r_epoch r_topo r_pol r_ctrl r_ev r_dgen r_at attempt
```

A revoked grant must carry a revoker and a reason; a grant must expire after it was
issued.

## 7. Emergency authorization records

```
emergency id authorizer justification epoch topo pol ctrl ev dgen issued expires revoked rev_at rev_by rev_reason attempt classes_n loads_n feeds_n
emergency_class id value
emergency_load id value
emergency_feed id value
```

An authorization must name at least one class and one load, must carry a non-empty
justification and an identified authorizer, and must expire after it was issued. Safety
interlocks can never appear in `emergency_class`.

## 8. Attempt records

```
attempt id kind fp grant emergency at
```

`grant` and `emergency` are `0` when the attempt produced none. Attempts are
stored oldest first; the record is the idempotency window described in the README.

## 9. Event records

```
event seq kind at epoch detail grant emergency decision
```

`grant`, `emergency` and `decision` are `0` when the event does not reference
one. Events are stored oldest first and are bounded by `Limits::max_events`.

## 10. Head marker

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | magic `FAHEAD01` |
| 8 | 4 | format version (u32 little-endian, 1) |
| 12 | 4 | header size (u32 little-endian, 24) |
| 16 | 8 | body size (u64 little-endian, 152) |
| 24 | 8 | committed store sequence |
| 32 | 8 | authority epoch |
| 40 | 8 | commit instant (nanoseconds since the Unix epoch, signed) |
| 48 | 32 | generation file name, ASCII, NUL padded |
| 80 | 32 | SHA-256 of the whole generation file |
| 112 | 32 | SHA-256 of the previous head marker file (zero for the first) |
| 144 | 32 | SHA-256 of bytes 0..144 of this file |

The head marker is accepted only when its size, magic, version, header size, body size
and self digest all agree, and when the generation file name is terminated with NUL and
padded with zeros to the full 32 bytes.

## 11. Publication protocol

A mutation is planned in memory, validated, encoded, and published:

1. the new store sequence is reserved (the committed head sequence plus one);
2. the generation is written to `staging/gen-<19 digits>.fas.tmp` and flushed to
   stable storage;
3. the staging file is read back, its framing and digest are verified, and the payload
   is decoded and re-encoded to prove it is canonical;
4. the generation is published by renaming the staging file to
   `generations/gen-<19 digits>.fas`. A file already occupying that name can only be
   the residue of an interrupted publication, and it is retired first;
5. the new head marker is written to `staging/head.marker.tmp`, flushed, read back and
   verified;
6. **the commit point** is the atomic replacement of `head.marker` (on Windows
   `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING` and `MOVEFILE_WRITE_THROUGH`; on
   POSIX `rename`). Before it, the previous head is the whole state. After it, this
   generation is;
7. staging residue is removed and generations beyond `Limits::generation_retention`
   are retired.

Fault injection (section 12) makes each step observable from a crash test.

## 12. Fault injection

`OpenOptions::fault_point` names one stage of the protocol and
`OpenOptions::on_fault` is invoked when that stage is reached. The callback runs with
the writer lock held and no other internal resource acquired, so a callback that
terminates the process leaves exactly the durable artifacts of that stage behind.
`OpenOptions::fault_skip_publications` lets a harness let the session-opening
publication through and fault the mutation under test instead. Fault injection is inert
unless it is configured explicitly, and the command line tool never enables it.

## 13. Scenario text

Scenarios are the human-readable form of one input generation, read by
`parse_scenario` and by the tool's `--scenario` option.

```
# a comment line
name <token or quoted text>            informational only
revisions topology=<n> policy=<n> control=<n> evidence=<n>     required exactly once
option ranking=on|off
option emergency=on|off
option roles=primary,secondary,standby,spare
feed <id> source=<class> role=<role> [domain=<id>] [protected=yes|no]
load <id> class=<class> [protected=yes|no]
link <feed> <load> role=<role> [domain=<id>]
obs feed <feed> <decl> source=<src> | condition=<cond> at=<time> max_age=<duration> source=<src>
obs link <feed> <load> <decl> source=<src> | present=yes|no at=<time> max_age=<duration> source=<src>
obs state <decl> source=<src> | condition=<cond> at=<time> max_age=<duration> source=<src>
obs maintenance <feed> [window=<id>] <decl> source=<src> | exposure=<exposure> at=<time> max_age=<duration> source=<src>
rule <id> effect=permit|deny [precedence=<class>] [rank=ordinary|elevated|emergency] [reason=<code>]
          [path=<id>] [feed=<id>] [load=<id>] [source_class=<class>] [load_class=<class>]
          [role=<role>] [domains=<id>,...] [conditions=<cond>,...] [exposures=<exposure>,...]
          [fresh=yes|no] [overridable=yes|no] [note="<text>"]
obligation <id> [loads=<id>,...] [class=<class>] [protected_loads=yes|no]
          [roles=<role>,...] [source_classes=<class>,...] [capability=yes|no]
          [min_domains=<n>] [overridable=yes|no] [reason=<code>] [note="<text>"]
```

* `<decl>` is `known`, `unknown`, `unsupported` or `unavailable`. A bare
  declaration token is shorthand for `decl=<token>`; the `known` form may be left
  out entirely when a value field is present.
* `<time>` is an ISO-8601 UTC timestamp ending in `Z` or whole Unix seconds.
* `<duration>` is an integer followed by `ns`, `ms`, `s`, `m` or `h`.
* Booleans accept `yes`/`no`, `true`/`false` and `on`/`off`.
* Record order does not matter: records are collected and canonicalized. Observations
  may appear before or after the subject they describe.
* Unknown record types, unknown keys, duplicated keys, malformed values, out-of-range
  numbers, lists above their bound and references to subjects the scenario does not
  declare are all errors with a `<source>:<line>` prefix.
