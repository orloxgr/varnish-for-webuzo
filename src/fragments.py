"""Parse the supported site-local VCL language; never splice arbitrary VCL."""
import re


class FragmentError(ValueError):
    pass


TOKEN = re.compile(r'''(?P<space>\s+)|(?P<comment>\#[^\n]*|//[^\n]*)|
    (?P<string>"(?:[^"\\\r\n]|\\[^\r\n])*")|
    (?P<duration>\d+(?:\.\d+)?(?:ms|s|m|h|d|w)\b)|
    (?P<number>\d+(?:\.\d+)?)|(?P<name>[A-Za-z_][A-Za-z0-9_.-]*)|
    (?P<operator>==|!=|!~|<=|>=|&&|\|\||[{}();,=~!<>+])''', re.X)


class Parser:
    def __init__(self, source, stage):
        if stage not in ('recv', 'backend_response'):
            raise FragmentError('Unknown VCL editing section')
        if not isinstance(source, str):
            raise FragmentError('A VCL section must be text')
        self.tokens = []
        self.stage = stage
        position = 0
        while position < len(source):
            match = TOKEN.match(source, position)
            if not match:
                raise FragmentError('Unsupported VCL character or literal')
            if match.lastgroup not in ('space', 'comment'):
                self.tokens.append((match.lastgroup, match.group()))
            position = match.end()
        self.index = 0

    def peek(self):
        return self.tokens[self.index][1] if self.index < len(self.tokens) else None

    def take(self, expected=None):
        if self.peek() is None or (expected is not None and self.peek() != expected):
            raise FragmentError('Invalid VCL syntax')
        token = self.tokens[self.index]
        self.index += 1
        return token

    def block(self, depth=0, nested=False):
        # An explicit parser stack avoids Python recursion limits. The native
        # compiler still validates VCL types, regexes and complete grammar.
        braces = 0
        while self.peek() is not None:
            word = self.take()[1]
            if word == 'if':
                self.take('('); self.expression(')'); self.take(')')
                self.take('{'); braces += 1
            elif word == 'else':
                if self.peek() == 'if':
                    continue
                self.take('{'); braces += 1
            elif word == '}':
                if not braces:
                    raise FragmentError('A VCL section cannot close its containing scope')
                braces -= 1
            elif word in ('set', 'unset'):
                target = self.take()[1]
                if not self.writable(target):
                    raise FragmentError('This field is outside the site-local editing scope')
                if word == 'set':
                    self.take('='); self.expression(';')
                elif '.http.' not in target:
                    raise FragmentError('Only custom headers can be unset')
                self.take(';')
            elif word == 'return' and self.stage == 'recv':
                self.take('('); self.take('pass'); self.take(')'); self.take(';')
            else:
                raise FragmentError('Unsupported VCL statement')
        if braces:
            raise FragmentError('Unclosed VCL block')

    def writable(self, name):
        prefix = 'req' if self.stage == 'recv' else 'beresp'
        if re.fullmatch(prefix + r'\.http\.X-User-[A-Za-z0-9_-]+', name, re.I):
            return True
        return self.stage == 'backend_response' and name in ('beresp.ttl', 'beresp.grace', 'beresp.keep')

    def readable(self, name):
        request = 'req' if self.stage == 'recv' else 'bereq'
        if name in (request + '.url', request + '.method'):
            return True
        match = re.fullmatch(request + r'\.http\.([A-Za-z0-9_-]+)', name)
        if match and not match[1].lower().startswith(('x-wv-', 'x-webuzo-varnish-', 'x-hvh-', 'x-esi-', 'x-ultracache-')):
            return True
        if self.stage == 'backend_response':
            return name in ('beresp.status', 'beresp.ttl', 'beresp.grace', 'beresp.keep',
                            'beresp.http.Content-Type', 'beresp.http.Cache-Control')
        return False

    def expression(self, terminator):
        parentheses = 0
        consumed = False
        while self.peek() is not None:
            value = self.peek()
            if value == terminator and not parentheses:
                if not consumed:
                    raise FragmentError('Empty VCL expression')
                return
            kind, value = self.take()
            consumed = True
            if value == '(':
                parentheses += 1
            elif value == ')':
                if not parentheses:
                    raise FragmentError('Unbalanced VCL expression')
                parentheses -= 1
            elif value in ('regsub', 'regsuball'):
                self.take('('); parentheses += 1
            elif kind in ('string', 'duration', 'number') or value in ('true', 'false'):
                pass
            elif value in ('==', '!=', '~', '!~', '<', '>', '<=', '>=', '&&', '||', '+', '!', ','):
                pass
            elif not self.readable(value):
                raise FragmentError('Unsupported VCL expression or field')
        raise FragmentError('Unterminated VCL expression')


def validate(source, stage, mark_pass=False):
    parser = Parser(source, stage)
    parser.block()
    # Re-render only parsed tokens. Comments and unrecognized syntax never reach
    # the native compiler, while Varnish remains the authority on types/regexes.
    return ' '.join('set req.http.X-WV-Mode = "PASS"; return' if mark_pass and stage=='recv' and kind=='name' and value=='return' else value
                    for kind,value in parser.tokens)
