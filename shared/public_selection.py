"""Compile resolver negotiation from the actual ordered native action rules."""
import hashlib
import json


def compile_rules(groups,site_header):
    if site_header not in ('X-HVH-Site','X-WV-Site'):
        raise ValueError('Unknown native site boundary')
    result=[]
    for rules,identities in groups.items():
        digest=hashlib.sha256(rules.encode('utf-8')).hexdigest()
        condition=' || '.join('req.http.'+site_header+' == '+json.dumps(identity) for identity in identities)
        result.append('if ('+condition+') {\n'
            'set req.http.X-SCP-Selection-Native-Policy = "'+digest+'";\n'
            'if (req.http.X-SCP-Selection-Operation == "begin" || req.http.X-SCP-Selection-Operation == "cold-begin") {\n'
            'set req.http.X-SCP-Selection-State = cookie_handoff.selection_begin(req.http.X-SCP-Site,"'+digest+'",{"'+rules+'"},req.http.X-SCP-Selection-Operation == "cold-begin");\n'
            '} else if (req.http.X-SCP-Selection-Operation == "actions") {\n'
            'set req.http.X-SCP-Selection-Actions = cookie_handoff.selection_actions({"'+rules+'"},req.http.X-SCP-Selection-Names);\n}\n}')
    return '\n'.join(result)
