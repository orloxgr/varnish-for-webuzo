"""Compile resolver negotiation from the actual ordered native action rules."""
import hashlib
import json


def compile_rules(groups,site_header,credentials=None):
    if site_header not in ('X-HVH-Site','X-WV-Site'):
        raise ValueError('Unknown native site boundary')
    result=[]
    credentials=credentials or {}
    for rules,identities in groups.items():
        digest=hashlib.sha256(rules.encode('utf-8')).hexdigest()
        condition=' || '.join('req.http.'+site_header+' == '+json.dumps(identity) for identity in identities)
        support=''.join('if (req.http.'+site_header+' == '+json.dumps(identity)+') { set req.http.X-SCP-Warm-Projection-Supported = "1"; }\n'
            for identity in identities if identity in credentials)
        warm=''.join('if (req.http.'+site_header+' == '+json.dumps(identity)+') {\n'
            'if (!cookie_handoff.guest_warm_parent(req.http.X-SCP-Site,"'+digest+'",'+json.dumps(credentials[identity])+')) {\n'
            'return (synth(403,"Invalid Warm projection"));\n}\n}\n'
            for identity in identities if identity in credentials)
        result.append('if ('+condition+') {\n'
            +support+
            'set req.http.X-SCP-Selection-Native-Policy = "'+digest+'";\n'
            'if (req.http.X-SCP-Selection-Operation == "begin" || req.http.X-SCP-Selection-Operation == "cold-begin" || req.http.X-SCP-Selection-Operation == "reselect") {\n'
            +warm+
            'cookie_handoff.guest_select(req.http.X-SCP-Site,"'+digest+'",{"'+rules+'"});\n'
            'set req.http.X-SCP-Selection-State = cookie_handoff.selection_begin(req.http.X-SCP-Site,"'+digest+'",{"'+rules+'"},req.http.X-SCP-Selection-Operation == "cold-begin",req.http.X-SCP-Selection-Operation == "reselect");\n'
            '} else if (req.http.X-SCP-Selection-Operation == "actions") {\n'
            'set req.http.X-SCP-Selection-Actions = cookie_handoff.selection_actions({"'+rules+'"},req.http.X-SCP-Selection-Names);\n}\n}')
    return '\n'.join(result)
