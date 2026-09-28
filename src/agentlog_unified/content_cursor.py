"""Bounded resumable rule pages; no source values leave this module."""
from __future__ import annotations
import ipaddress
from agentlog_unified import content_types as ct

# Maximum named regex width: two chars per escaped token *4096 +129 prefix/quotes.
CORE = 65536
RIGHT = 9216
LEFT = 600
SPECS = [('token', ct._TOKEN), ('jwt', ct._JWT), ('bearer', ct._BEARER),
         ('email', ct._EMAIL), ('userinfo', ct._USERINFO), ('ipv4', ct._IPV4)]
SPECS += [('pem:' + kind, None) for kind in ct._PEM_KINDS]
SPECS += [('named', ct._NAMED)]


def rows_for(kind, match, buffer):
    """Reuse product semantic helpers; bounded regex candidate already selected."""
    start, end = match.span()
    if kind == 'named':
        # Run exactly the raw match, then recover original buffer context for
        # example status. Raw match contains no earlier non-overlap candidate.
        for row in ct._named_candidates(match[0]):
            row['start'] += start; row['end'] += start
            if ct._example(buffer, row['start'], row['end']):
                row.update(value_status='placeholder_or_example', candidate_status='placeholder_or_example')
            yield row
        return
    if kind == 'ipv4':
        try: ipaddress.IPv4Address(match[0])
        except ValueError: return
    if kind == 'email' and any(m.start() < start < m.end() < end for m in ct._USERINFO.finditer(buffer, max(0,start-550),end)):
        return
    category, subtype, rule = {
        'jwt': ('AUTH','access_token','compact_jwt_shape'),
        'bearer': ('AUTH','authorization_header','bearer_scheme_shape'),
        'email': ('PII','email','email_shape'),
        'userinfo': ('AUTH','credential_bundle','url_userinfo_shape'),
        'ipv4': ('QID','network_identifier','ipv4_shape'),
    }.get(kind, ('AUTH', 'api_key' if match[0].startswith('sk-') else 'credential_bundle' if match[0].startswith('AKIA') else 'access_token', 'credential_prefix_shape'))
    basis,status,value_status='literal_shape','literal_candidate','unverified'
    if kind=='bearer' and ct._REFERENCE.fullmatch(match[0].split(None,1)[1]):
        basis,status,value_status='identifier_or_unquoted_value','identifier_reference','opaque'
    yield ct._record(buffer,start,end,category,subtype,rule,basis,status,value_status)


def page(text, state, *, core=CORE, max_rows=1000):
    """Return one bounded page and source-position cursor; no original value."""
    state=dict(state); output=[]; gaps=[]
    index,cursor=state.get('rule_index',0),state.get('search_offset',0)
    if index==len(SPECS): return output,state,gaps
    kind,regex=SPECS[index]
    stop=min(len(text),cursor+core)
    if kind.startswith('pem:'):
        name=kind[4:]; opening=f'-----BEGIN {name}-----'; closing=f'-----END {name}-----'
        pending=state.get('pending_open')
        if pending is None:
            found=text.find(opening,cursor,min(len(text),stop+len(opening)))
            if found>=0 and found<stop:
                state.update(pending_open=found,search_offset=found+len(opening),example=False)
                return output,state,gaps
        else:
            found=text.find(closing,cursor,min(len(text),stop+len(closing)))
            end=found+len(closing) if found>=0 and found<stop else stop
            probe_start=max(pending,cursor-64)
            # A page boundary is not EOF: peek past it before accepting a word
            # with an end anchor. Own keyword starts, not the optional consumed
            # leading delimiter, so keywords starting exactly at cursor survive.
            probe=text[probe_start:min(len(text),end+64)]
            for marker in ct._EXAMPLE_WORD.finditer(probe):
                word_start=probe_start+marker.start()+int(not marker[0][0].isalpha())
                if cursor<=word_start<end:
                    state['example']=True
            if found>=0 and found<stop:
                local=text[max(0,pending-LEFT):pending+len(opening)]
                row=ct._record(local,pending-max(0,pending-LEFT),len(local),'AUTH','private_key','private_key_envelope_shape','literal_shape','literal_candidate')
                row.update(start=pending,end=end)
                if state['example']: row.update(value_status='placeholder_or_example',candidate_status='placeholder_or_example')
                output.append(row); state={'rule_index':index,'search_offset':end}
                return output,state,gaps
        state['search_offset']=stop
        if stop==len(text):
            if pending is not None: gaps.append({'reason':'unclosed_private_key_envelope','start':pending,'end':len(text)})
            state={'rule_index':index+1,'search_offset':0}
        return output,state,gaps
    low=max(0,cursor-LEFT); high=min(len(text),stop+RIGHT)
    buffer=text[low:high]
    position=cursor-low
    while (match:=regex.search(buffer,position)) is not None and match.start()+low<stop:
        candidates=list(rows_for(kind,match,buffer))
        # A raw key can have several labels. Emit them atomically; threshold may
        # overshoot by at most len(RULES)-1 (37), never lose sibling labels.
        for row in candidates:
            row['start']+=low;row['end']+=low;output.append(row)
        position=match.end(); state['search_offset']=position+low
        if len(output)>=max_rows: return output,state,gaps
    state['search_offset']=max(stop,state.get('search_offset',0))
    if state['search_offset']>=len(text): state={'rule_index':index+1,'search_offset':0}
    return output,state,gaps


