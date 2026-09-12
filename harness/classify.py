#!/usr/bin/env python3
"""classify.py — HackerDummy's standalone vulnerability taxonomy.

Maps a free-text finding title (whatever an AI/agent calls a vuln) to a
canonical class key, so findings from ANY tool — Claude, GPT/Codex, Cursor,
a local LLM, a custom plugin — can be scored against the labs' answer keys
without forcing the tool to know our class names.

Self-contained (pure stdlib) with no dependency on any pentest tool. The class
keys here ARE the benchmark's contract; the per-lab ``gabarito.json`` files use
the same keys.

Usage::

    from classify import classify, classify_detail

    classify("SQL Injection (auth bypass)")   # -> "sqli"
    classify("Exposed Redis without auth")    # -> "exposed-service"
    classify_detail("Stored XSS in profile")  # -> Match(key='stored-xss', ...)

Command line::

    python3 classify.py "SQL Injection" "Exposed Redis"   # one per argument
    cat titles.txt | python3 classify.py -                # one per input line
    python3 classify.py --json -                          # JSONL output
    python3 classify.py --list-classes                    # dump the contract

Order matters: more specific patterns come first so they win over generic ones
(e.g. ``actuator`` before ``rce``; ``default-creds`` before ``creds``;
``stored-xss`` before ``xss``; ``no-rate-limit`` before ``graphql``).

Patterns cover English and Portuguese wording, with or without accents
(``inje[cç][aã]o``), because agents report findings in either language. When
the two collide the English precedence wins, so "Injecao de cabecalho Host na
redefinicao de senha" lands on ``auth`` exactly as its English counterpart does.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, NamedTuple, Sequence

__all__ = [
    "CLASS_KEYS",
    "DEFAULT_CLASS",
    "Match",
    "Rule",
    "RULES",
    "TAXONOMY",
    "classify",
    "classify_all",
    "classify_detail",
    "main",
]

#: Key returned when no rule matches.
DEFAULT_CLASS = "other"

#: Cache size for :func:`classify`; benchmark runs repeat titles a lot.
_CACHE_SIZE = 4096


@dataclass(frozen=True, slots=True)
class Rule:
    """One taxonomy rule: a compiled pattern and the class key it yields."""

    key: str
    pattern: re.Pattern[str]
    note: str = ""

    def search(self, text: str) -> re.Match[str] | None:
        return self.pattern.search(text)


class Match(NamedTuple):
    """Result of a classification, with the evidence that produced it."""

    key: str
    matched_text: str | None = None
    pattern: str | None = None

    @property
    def is_default(self) -> bool:
        return self.key == DEFAULT_CLASS


# (regex, canonical_class_key) — first match wins. Kept as a plain list of
# tuples so the taxonomy stays diffable and copy-pasteable across tools.
TAXONOMY: list[tuple[str, str]] = [
    (r"nosql.?inj|no-?sql inj|mongo.*inject|inject.*mongo|operator injection|nosql.*operator|inje[cç][aãa]o.*nosql|nosql.*inje[cç]|nosql.*operador|operador.*nosql|mongo.*inje[cç]", "nosqli"),
    (r"ldap inject|ldap.?injection|inje[cç].*ldap", "ldap-injection"),
    (r"xpath inject|xpath.?injection|inje[cç].*xpath", "xpath-injection"),
    (r"\bssi\b\s*(injection|inject)|server.?side include|\.shtml|edge.?side include", "ssi-injection"),
    (r"csv inject|formula inject|csv.*formula|formula.*csv|spreadsheet inject|inje[cç][aã]o de f[oó]rmula|f[oó]rmula.*csv|csv.*f[oó]rmula|planilha.*f[oó]rmula", "csv-injection"),
    (r"sql.?inj|\bsqli\b|union.?based|boolean.?based|error.?based|inje[cç].*sql", "sqli"),
    (r"\bactuator\b|spring boot actuator|jolokia|h2[\s-]?console|heapdump|jmx[\s-]?(http|over|console|exposed)|console h2", "actuator"),
    # upload before rce: an unrestricted-upload finding is class 'upload' even when the
    # title states the RCE impact ("File Upload -> RCE / webshell"). Pure command-injection
    # RCE has no upload words and falls through to 'rce'.
    (r"file.?upload|unrestricted upload|arbitrary file|webshell|polyglot|upload.*(shell|arbitr|malicios|webshell|rce|remote code|execu)|envio de arquivo|upload de arquivo|arquivo.*sem valida[cç][aã]o|extens[aã]o.*(n[aã]o validad|sem valida)", "upload"),
    (r"\bxxe\b|xml external entit|external general entit|external.*entity injection|entidade externa", "xxe"),
    (r"deserializ|desserializ|insecure.*deserial|unsafe.*(pickle|unpickle|unserialize|marshal)|pickle.*load|object injection|__reduce__|unmarshal|desserializa[cç][aã]o insegura", "deserialization"),
    (r"\bssti\b|server.?side template inject|template injection|expression language inject|inje[cç][aã]o de template|template.*lado do servidor|c[oó]digo.*via template|template.*inje[cç]", "ssti"),
    (r"\bimds\b|imdsv\d|instance metadata|metadata.*credential|credential.*(theft|exfil)|169\.254\.169\.254|security-credentials|instance.?role.*(credential|token)|steal.*(instance|iam|role).*(credential|token)", "creds"),
    (r"\bssrf\b|server.?side request|falsifica[cç][aã]o de requisi[cç][aã]o.*servidor|requisi[cç][aã]o forjada.*servidor|requisi[cç][aã]o.*lado do servidor", "ssrf"),
    (r"\blfi\b|local file incl|path traversal|directory traversal|file inclusion|travessia de (diret[oó]rio|caminho)|inclus[aã]o de arquivo", "lfi"),
    (r"stored xss|persistent xss|xss armazenad|xss persistente", "stored-xss"),
    (r"reflect.*xss|xss reflet|cross.?site script|reflected.*script|dom.?based.?xss|dom.?xss", "xss"),
    (r"prototype pollut|proto.?pollut|__proto__|object\.prototype|constructor.*pollut|polui[cç][aã]o de prot[oó]tipo", "prototype-pollution"),
    (r"\bidor\b|insecure direct object|broken object level|\bbola\b|refer[eê]ncia direta|controle de acesso quebrado|falta de autentica[cç][aã]o|autentica[cç][aã]o ausente|autoriza[cç][aã]o ausente|acesso n[aã]o autenticado", "idor"),
    (r"\bbfla\b|broken function.?level|function.?level authoriz|missing function.?level|n[ií]vel de fun[cç][aã]o", "bfla"),
    (r"excessive data exposure|excessive.*data exposur|oversharing|overshar.*(field|data)|exposi[cç][aã]o excessiva de dados|dados em excesso", "excessive-data"),
    (r"\bjwt\b|json web token|alg[\s:=\"']*none|none algorithm|jwt.*(secret|signature|forge|alg)|weak.*(signing|hmac).*secret", "jwt"),
    (r"\b2fa\b|\bmfa\b|\botp\b|one.?time.?password|two.?factor|second factor|multi.?factor|segundo fator|dois fatores|m[uú]ltiplos fatores|senha de uso [uú]nico", "2fa-bypass"),
    (r"user(name)? enumeration|account enumeration|enumera[çc][aã]o de usu|user.*enumerat|enumera[cç][aã]o de contas", "user-enum"),
    (r"rate.?limit|brute.?force|for[çc]a bruta|no lockout|account lockout|excessive.*(attempts|requests)|throttl|limite de tentativas|limita[cç][aã]o de taxa|bloqueio de conta|tentativas excessivas", "no-rate-limit"),
    (r"mass.?assignment|mass-assign|auto.?bind|over.?post|autobinding|atribui[cç][aã]o em massa", "mass-assignment"),
    (r"race.?cond|\btoctou\b|time.?of.?check|check.?then.?act|double.?spend|concurren\w*.*(redeem|withdraw|transfer|purchase|spend|double|limit|bypass)|parallel.*request.*(double|race|bypass)|condi[cç][aã]o de corrida", "race-condition"),
    # ── Mobile storage/crypto classes — before weak-crypto; backup-allowed before
    # insecure-storage so an "allowBackup -> extract prefs/db" finding stays backup-allowed ──
    (r"android:allowbackup|allow.?backup|\ballowbackup\b|adb backup|backup.*(enabled|allowed|permitted)|backup flag|c[oó]pia de seguran[cç]a.*(permitid|habilitad|ativad)|backup.*(permitid|habilitad|ativad)", "backup-allowed"),
    (r"shared.?pref\w*.*(world.?readable|plaintext|cleartext|mode_world|unencrypt|sensitive|token|password|secret|pii|pan)|mode_world_readable|world.?(readable|writable).*(pref|file|storage|db)|plaintext.*(sqlite|database|\.db\b|shared.?pref|prefs)|(sqlite|database|\.db\b).*(plaintext|unencrypt|cleartext|sensitive|pii|no.?encrypt|sqlcipher)|insecure (local )?(data )?storage|sensitive data.*(stored|saved|at rest).*(plaintext|cleartext|unencrypt)|stores?.*(token|password|\bpin\b|pii|card|pan|credential).*(plaintext|cleartext|unencrypt|shared.?pref|sqlite|external storage)|external storage.*(secret|token|sensitive|password|pii|credential)|armazenamento inseguro de dados|armazenamento local inseguro|armazenamento inseguro no dispositivo|dados sens[ií]veis.*(texto claro|texto plano|sem criptografia|n[aã]o criptografad)|armazenad[oa]s?.*(em )?texto (claro|plano)", "insecure-storage"),
    (r"logcat|log\.[dveiw]\b|android\.util\.log|(token|password|secret|credential|session|\bpan\b|card (number|pan)|\bpii\b|\bcpf\b).*(logged|written to (the )?log|leaked? (to|via|into) (the )?log)|sensitive (data|info\w*).*(logged|in (the )?logs?|logcat)|(token|senha|segredo|credencial|cart[aã]o|cpf).*(nos registros|no log|em log|registrado)|gravado nos registros|dados sens[ií]veis.*(registros|logs?)", "sensitive-log"),
    (r"unsalted|\bmd5\b|\bsha1\b|weak.*(hash|crypto|cipher)|insecure.*(password storage|hash)|plaintext password|sem salt|\becb\b|aes/ecb|ecb mode|\bdes\b|\b3des\b|triple.?des|\brc4\b|no.?padding|static iv|fixed iv|null iv|zero iv|hardcoded iv|reused iv|hardcoded (aes|des|encryption|crypto|cipher|secret) key|(aes|des|encryption|cipher) key.*hardcod|hash fraco|criptografia fraca|cifra fraca|sem sal\b|algoritmo fraco|vetor de inicializa[cç][aã]o (fixo|est[aá]tico|nulo|reutilizado|codificado)", "weak-crypto"),
    (r"session fixation|session.*(not invalidat|never.*expir|without expir|no expir|does not expir|fixa)|(token|session).*(without expir|no expir|never expir|no invalidation|no logout)|not invalidated.*(session|token|logout)|no logout endpoint|predictable.*(session|remember|cookie)|remember.?me|fixa[cç][aã]o de sess[aã]o|sess[aã]o n[aã]o (é |e )?invalidada|sess[aã]o.*(n[aã]o expira|sem expira)|sequestro de (conta|sess[aã]o)|lembrar.?me", "session"),
    (r"\bcsrf\b|cross.?site request forgery|cross-site request|missing.*(anti.?csrf|anti.?forgery|csrf token|state param)|state param.*(missing|not (validat|requir|bound)|csrf)|oauth csrf|login csrf|samesite.*(missing|none)|no anti.?csrf|falsifica[cç][aã]o de requisi[cç][aã]o entre sites|requisi[cç][aã]o entre sites", "csrf"),
    (r"authentication bypass|auth(entication)? bypass|login bypass|bypass.*authentica|type.?juggl|magic hash|loose compar(e|ison)|strcmp.*bypass|saml.*(bypass|signature|assertion|forge)|signature (bypass|strip|exclusion|wrapping)|signature wrapping|\bxsw\b|assertion (forge|inject|tamper|strip|replay)|unsigned assertion|\bpkce\b|code.?(challenge|verifier)|authorization code (reuse|replay|inject)|code reuse|client authentication (not|missing)|missing client auth|oauth.*(downgrade|reuse|replay|code inject)|password reset|reset token|broken authentication|weak.*(password )?recovery|account takeover|forgot password|desvio de autentica[cç][aã]o|bypass de autentica[cç][aã]o|tomada de conta|redefini[cç][aã]o de senha|recupera[cç][aã]o de senha|compara[cç][aã]o frouxa|assinatura.*(forjad|removid|ignorad)", "auth"),
    (r"(exposed|expos[ti]\w*).*(redis|elasticsearch|elastic|mongodb|mongo|couchdb|couch|docker|memcached|mysql|postgres|mssql|kibana|jenkins|rabbitmq|kafka|zookeeper|\bftp\b|telnet|\bsmb\b|\brdp\b|\bvnc\b|\bnfs\b|ldap)|(redis|elasticsearch|mongodb|couchdb|memcached|docker (engine )?api).*(no auth|without auth|sem auth|admin party|unauthenticated|exposed)|unauthenticated (network )?service|admin party|(redis|elasticsearch|mongodb|couchdb|memcached|docker|mysql|postgres|mssql|kibana|jenkins|rabbitmq|kafka|zookeeper|\bftp\b|telnet|\bsmb\b|\brdp\b|\bvnc\b|\bnfs\b|ldap).*(sem autentica[cç][aã]o|n[aã]o autenticad|exposto|exposta|acess[ií]vel)|servi[cç]o.*(n[aã]o autenticado|sem autentica[cç][aã]o)", "exposed-service"),
    (r"default credential|default password|credenciais? padr[aã]o|senha padr[aã]o|admin/admin|weak default|default login|hardcoded credential|no password set|credenciais? padr[aã]o|login padr[aã]o|senha de f[aá]brica|senha do fabricante", "default-creds"),
    (r"cors (misconfig|misconfiguration)|cross.?origin.*(misconfig|reflect|wildcard|null origin)|access.?control.?allow.?origin.*(reflect|\*|null)|origin.*reflect.*credential|\bcors\b.*(reflect|null origin|wildcard|credential)|configura[cç][aã]o incorreta de cors|cors mal configurado|origem refletida|cors aceita|origem null|origin.?null", "cors-misconfig"),
    (r"host header (injection|poison)|host.?header.?injection|x-forwarded-host|password reset poison|reset.*link.*host|host header.*(trust|inject|reset)|inje[cç][aã]o de cabe[cç]alho host|cabe[cç]alho host", "host-header-injection"),
    (r"\bsmuggl|request smuggl|response smuggl|\bcl\.?te\b|\bte\.?cl\b|\bte\.?te\b|http desync|request desync|chunked.*content.?length.*(conflict|desync|smuggl)|contrabando de requisi", "smuggling"),
    (r"\bcrlf\b|response splitting|http response split|carriage return.*line feed|cr.?lf inject|header inject.*(crlf|newline|response)|divis[aã]o de resposta", "crlf"),
    (r"cache poison|web cache (poison|decept)|unkeyed (header|input|param)|cache.*(poison|decept)|envenenamento de cache", "cache-poisoning"),
    (r"graphql.*introspect|introspection (enabled|exposed|habilitada|on|ativ)|\b__schema\b|\b__type\b|graphql schema (expos|leak|dump)|introspec[cç][aã]o", "graphql"),
    # `dos` needs context: bare "dos" is a common Portuguese word ("vazamento dos tokens"),
    # and this rule sits above creds/backup, so an unguarded \bdos\b stole those findings.
    (r"denial of service|nega[çc][ãa]o de servi[çc]o|\bddos\b|\bdos\b[\s/-]*(attack|attempts?|condition|vulnerabilit\w*|risk|vector|via|through|by|exhaustion|flood|bomb|cpu|mem[oó]r?[iy]a?\w*)|(attack|ataque|vulnerabilit\w*|vulnerabilidade|potential|possible|application.?level|network.?level)[\s/-]+(de[\s/-]+)?\bdos\b|resource (exhaustion|consumption)|uncontrolled resource|query (depth|complexity)|(depth|complexity) (limit|attack|bomb)|amplification|exaust[aã]o de recursos|consumo excessivo de recursos", "dos"),
    (r"open.?redirect|unvalidated redirect|redirect.*unvalidat|url redirection|redirect.*untrusted|redirecionamento (aberto|n[aã]o validado)", "open-redirect"),
    (r"\.git\b|git.?expos|svn.?expos|reposit[oó]rio.*expos|source.*repo|version.?control.*expos", "scm"),
    (r"web\.config|connection string|machinekey|appsettings.*secret", "web-config"),
    # ── Mobile (Android) static-analysis classes — placed before web backup/admin-panel/
    # headers so the specific mobile class wins those collisions (e.g. "adb backup file") ──
    (r"android:debuggable|\bdebuggable\b|debug flag.*(true|enabled|on)|app.*debuggable|depur[aá]vel|sinalizador de depura[cç][aã]o", "debuggable"),
    (r"android:exported|exported (activity|service|receiver|provider|component)|(activity|service|receiver|provider|content provider).*(exported|no permission|without permission|sem permiss)|exported.*(component|without.*permission|no.?permission)|improperly exported|componente exportado", "exported-component"),
    (r"usescleartexttraffic|cleartexttrafficpermitted|cleartext traffic|clear.?text traffic|network.?security.?config.*(cleartext|permit|http)|cleartext.*(permitted|allowed|enabled|traffic|connection|http)|unencrypted (http|traffic|connection)|tr[aá]fego (em texto claro|n[aã]o criptografado)|texto claro.*(permitid|habilitad)", "cleartext-traffic"),
    (r"backup.*(dir|expos|arquivo|file)|\bbkp\b|\.bak\b|dump.*expos|sql.?dump|database (backup|dump)|\.sql\b.*(expos|public|access)", "backup"),
    (r"directory listing|index of|listagem de diret|autoindex|listagem de diret[oó]rios", "dir-listing"),
    (r"phpinfo", "phpinfo"),
    (r"admin panel|painel admin|management interface|interface de gerenc|phpmyadmin|tomcat manager|unauth.*admin|painel administrativo|console administrativ", "admin-panel"),
    (r"clickjack|x-frame|frame.?ancestors|frame.?busting|sequestro de clique", "clickjacking"),
    (r"http trace|trace.*habilit|\bxst\b|cross.?site tracing", "trace"),
    (r"cookie.*(flag|secure|httponly|samesite)|insecure.*cookie|sem flag", "cookie"),
    (r"security header|cabe[cç]alho.*segur|content.?security.?policy|\bcsp\b|\bhsts\b|x-content-type|referrer.?policy|permissions.?policy|strict.?transport|x-frame-options|missing.*header|pol[ií]tica de seguran[cç]a de conte[uú]do|cabe[cç]alhos? de seguran[cç]a", "headers"),
    (r"\beol\b|end.?of.?life|outdated|unsupported|sem patches|out of date|legacy.*version|fim de vida|fora de suporte|vers[aã]o obsoleta|sem suporte", "eol"),
    (r"version disclos|disclosure de vers|vers[aã]o.*expos|x-aspnet-version|x-powered-by|software.*banner|divulga[cç][aã]o (da|de) vers[aã]o|vers[aã]o.*(divulgad|revelad)", "version"),
    (r"credential|senhas|password.*file|creds.*expos|plaintext.*pass|cred.*expos|arquivo.*senha|\.env\b|environment file|secrets?.*(expos|leak|disclos|hardcod|in (the )?(apk|dex|strings|assets|smali|source|code))|api.?key.*(expos|leak|hardcod|in (the )?(apk|dex|strings|assets|smali|code))|secret.*disclosure|hardcoded secret|hard.?cod.*(secret|api.?key|token|\bkey\b|credential)|chave de api|credenciais? (expost|vazad|em texto (claro|plano)|em claro|no c[oó]digo|hardcoded)|segredo (embutid|codificad|no c[oó]digo)|(embutid|codificad)[oa]s?.*(no )?(c[oó]digo|aplicativo|fonte)", "creds"),
    (r"missing authentication|no authentication required|unauthenticated access|authentication not required|broken access control|missing authoriz|missing object.?level author|acesso sem autentica[cç][aã]o", "idor"),
    # rce is the LAST impact class: "<X> -> RCE" keeps root cause X (every specific
    # root cause that leads to RCE is above). Only pure command-injection lands here.
    (r"\brce\b|remote code|command inj|os command|code execution|inje[cç].*comando|execu[cç][aã]o remota de c[oó]digo|execu[cç][aã]o de c[oó]digo|inje[cç][aã]o de comando", "rce"),
    (r"info.*disclos|information disclosure|path disclos|internal path|caminho.*interno|vazamento|verbose error|erro verboso|stack.?trace|traceback|debug mode|field suggestion|unhandled exception|trace\.axd|asp.?net.*trace|\belmah\b|customerror|yellow screen of death|divulga[cç][aã]o de informa|rastreamento de pilha|modo de depura[cç][aã]o|erro detalhad|exce[cç][aã]o n[aã]o tratada", "info-disc"),
]


def _compile(taxonomy: Sequence[tuple[str, str]]) -> list[Rule]:
    """Compile the taxonomy, failing loudly on a malformed pattern."""
    rules: list[Rule] = []
    for index, (pattern, key) in enumerate(taxonomy):
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:  # pragma: no cover - guards authoring mistakes
            raise ValueError(f"invalid pattern for class {key!r} at index {index}: {exc}") from exc
        rules.append(Rule(key=key, pattern=compiled))
    return rules


#: Compiled taxonomy, in priority order.
RULES: list[Rule] = _compile(TAXONOMY)

#: Every canonical class key, deduplicated, in first-appearance order.
#: A key may back several rules (``creds`` and ``idor`` do), so dict.fromkeys
#: keeps the contract a set of distinct keys.
CLASS_KEYS: list[str] = list(dict.fromkeys([rule.key for rule in RULES] + [DEFAULT_CLASS]))


def classify_detail(text: str | None) -> Match:
    """Classify ``text`` and return the key plus the evidence for it."""
    haystack = text or ""
    for rule in RULES:
        found = rule.search(haystack)
        if found:
            return Match(key=rule.key, matched_text=found.group(0), pattern=rule.pattern.pattern)
    return Match(key=DEFAULT_CLASS)


@lru_cache(maxsize=_CACHE_SIZE)
def _classify_cached(text: str) -> str:
    return classify_detail(text).key


def classify(text: str | None) -> str:
    """Return the canonical class key for a free-text finding title/description."""
    return _classify_cached(text or "")


def classify_all(text: str | None) -> list[str]:
    """Return every class key whose pattern matches, in taxonomy order.

    Useful for auditing overlaps in the taxonomy; scoring uses :func:`classify`,
    which keeps only the first (most specific) match.
    """
    haystack = text or ""
    keys = [rule.key for rule in RULES if rule.search(haystack)]
    return list(dict.fromkeys(keys))


def _read_inputs(values: Iterable[str]) -> list[str]:
    """Expand a literal ``-`` argument into the non-empty lines of stdin."""
    items: list[str] = []
    for value in values:
        if value == "-":
            items.extend(line.strip() for line in sys.stdin if line.strip())
        else:
            items.append(value)
    return items


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="classify.py",
        description="Map free-text vulnerability findings to HackerDummy canonical class keys.",
        epilog="Use '-' as a title to read one finding per line from stdin.",
    )
    parser.add_argument("titles", nargs="*", help="finding titles to classify; '-' reads stdin")
    parser.add_argument("--json", action="store_true", help="emit one JSON object per line")
    parser.add_argument("--explain", action="store_true", help="show the matched text and pattern")
    parser.add_argument("--all", action="store_true", help="list every matching class, not just the winner")
    parser.add_argument("--list-classes", action="store_true", help="print every canonical class key and exit")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.list_classes:
        if args.json:
            json.dump(CLASS_KEYS, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            print("\n".join(CLASS_KEYS))
        return 0

    titles = _read_inputs(args.titles)
    if not titles:
        _build_parser().print_usage(sys.stderr)
        print("classify.py: no titles given", file=sys.stderr)
        return 2

    for title in titles:
        result = classify_detail(title)
        record: dict[str, object] = {"title": title, "class": result.key}
        if args.explain:
            record["matched"] = result.matched_text
            record["pattern"] = result.pattern
        if args.all:
            record["all_classes"] = classify_all(title)

        if args.json:
            print(json.dumps(record, ensure_ascii=False))
        elif args.explain:
            print(f"{title!r} -> {result.key}  (matched {result.matched_text!r})")
        elif args.all:
            print(f"{title!r} -> {result.key}  (all: {', '.join(record['all_classes'])})")
        else:
            print(f"{title!r} -> {result.key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
