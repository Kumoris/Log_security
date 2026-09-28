"""Finite, auditable identifier dictionary for values that reach a log sink.

Taken from agentlog_unified taxonomy 1.2.0 (rules, identifier normalisation, parent
context for ambiguous leaves, aggregate exclusion, precedence), plus one category that
agent-written code often logs: large-language-model content. Rules name what a value
*is called*; they never claim a runtime leak. ``annotate_entity`` of the original is
not used: logtrace records per-item evidence instead of a verdict.
"""
from __future__ import annotations

import re

TAXONOMY_VERSION = "1.2.0+logtrace.2"
CATEGORIES = {
    "AUTH": "认证秘密", "PII": "个人及敏感个人信息", "QID": "可关联标识",
    "BIZ": "业务内容", "CFG": "内部配置及资源", "DIAG": "诊断载体",
    "LLM": "大模型内容",
}

# category, subtype, Chinese label, identifier pattern, compatible legacy type.
# ponytail: these are an auditable finite dictionary, not open-world discovery;
# unknown values stay queued until reviewed or a versioned rule is added.
RULES = (
    ("AUTH", "password", "密码", r"password|passwd|pwd", "credential"),
    ("AUTH", "access_token", "访问令牌", r"(?:(?:access|refresh|auth|bearer|session)_?)?token|jwt", "credential"),
    ("AUTH", "api_key", "服务密钥", r"(?:api|access|secret)_?key|client_?secret", "credential"),
    ("AUTH", "private_key", "私钥", r"private_?key|signing_?key", "credential"),
    ("AUTH", "auth_cookie", "认证 Cookie", r"cookies?", "credential"),
    ("AUTH", "authorization_header", "认证头", r"authorization|auth_?header", "credential"),
    ("AUTH", "credential_bundle", "其他认证秘密或凭证对象", r"credentials?|secret", "credential"),
    ("PII", "email", "邮箱", r"email|e_?mail", "personal_identifier"),
    ("PII", "phone", "电话", r"phone|phone_?number|mobile_?number|telephone", "personal_identifier"),
    ("PII", "person_name", "个人姓名", r"(?:first|last|full|given|family|customer|person|patient|user)_?name|username", "personal_identifier"),
    # logtrace.2: in code "address" is almost always an IP / MAC / host / service / memory address, rarely a
    # postal one, so every *address* name is one type (was PII.postal_address, QID.device / network_identifier)
    ("QID", "address", "地址（网络、设备、服务或住址）", r"(?:\w*_)?address(?:es)?", "linkable_identifier"),
    ("PII", "government_identifier", "政府证件标识", r"ssn|social_?security_?(?:number|id)|(?:government|national|passport|tax)_?id|passport_?number|id_?card", "personal_identifier"),
    ("PII", "medical", "医疗健康信息", r"medical(?:_?(?:record|history|data))?|health_?(?:record|data)|diagnosis|prescription|patient_?record|lab_?results?", "medical_data"),
    ("PII", "financial", "个人金融信息", r"(?:credit|debit)_?card|card_?number|bank_?account|iban|salary|income|account_?balance|financial_?(?:record|data)", "financial_data"),
    ("PII", "precise_location", "精确位置候选", r"latitude|longitude|gps(?:_?(?:location|coordinates?))?|geo_?coordinates?|precise_?location", "precise_location"),
    ("PII", "biometric", "生物特征", r"biometric(?:_?(?:data|template))?|fingerprint_?(?:data|template)|face_?(?:embedding|template)|voice_?print|iris_?template", "biometric_data"),
    ("QID", "user_identifier", "用户或账户标识", r"(?:user|account|customer)_?id|customer_?number", "linkable_identifier"),
    ("QID", "session_identifier", "会话标识", r"session_?id", "session_identifier"),
    ("QID", "device_identifier", "设备标识", r"device_?id|advertising_?id|imei", "linkable_identifier"),
    ("QID", "network_identifier", "网络关联标识", r"client_?ip|remote_?addr", "linkable_identifier"),
    # logtrace.2: ids of conversations and messages (also the target of the *_id rule below)
    ("QID", "conversation_identifier", "对话 / 消息标识", r"(?:conversation|message|chat|thread)_?ids?", "linkable_identifier"),
    ("QID", "request_identifier", "请求关联标识", r"(?:request|correlation|trace|span)_?id", "linkable_identifier"),
    ("QID", "transaction_identifier", "业务关联标识", r"(?:order|transaction|payment|invoice)_?id", "linkable_identifier"),
    ("QID", "tenant_identifier", "租户标识", r"tenant_?id", "linkable_identifier"),
    ("BIZ", "request_body", "请求体载体", r"request(?:_?(?:body|data))?|req_?body|payload|form_?data", "opaque_object"),
    ("BIZ", "response_body", "响应体载体", r"response(?:_?(?:body|data))?|res_?body", "opaque_object"),
    ("BIZ", "http_headers", "请求响应头载体", r"headers?", "opaque_object"),
    ("BIZ", "document_content", "文档及内容载体", r"document(?:_?(?:text|content))?|file_?content|content", "content_visibility_unknown"),
    ("BIZ", "message_content", "业务聊天内容载体", r"chat_?(?:message|history|content)|message_?(?:body|content)", "content_visibility_unknown"),
    ("BIZ", "business_object", "业务对象载体", r"business_?(?:object|data)|customer|user|order|context|body", "opaque_object"),
    ("CFG", "database_connection", "数据库连接", r"database_?url|connection_?string|dsn|db_?host", "connection_string"),
    ("CFG", "internal_endpoint", "内部端点", r"internal_?(?:url|host|endpoint)|service_?endpoint|private_?ip", "internal_resource"),
    ("CFG", "filesystem_path", "内部文件路径", r"(?:file|absolute|internal|home|config)_?path|working_?directory", "internal_resource"),
    ("CFG", "environment", "环境变量载体", r"environment|env|environ", "internal_configuration"),
    ("CFG", "deployment_configuration", "配置及部署载体", r"config(?:uration)?|deployment_?(?:config|data)|cloud_?resource", "internal_configuration"),
    ("DIAG", "exception_message", "异常内容载体", r"exception|error|exc|err|current_exception_or_stack", "exception_data"),
    ("DIAG", "stack_trace", "堆栈载体", r"stack_?trace|traceback|stack", "exception_data"),
    ("DIAG", "failure_response", "失败响应载体", r"failure_?response|error_?response", "exception_data"),
    # These are field-name hints, not evidence of a real person's attributes.
    # Ambiguous age/race/school/job fields require an explicit person scope.
    ("PII", "birth_date", "出生日期", r"date_?of_?birth|birth_?date|dob", "personal_identifier"),
    ("PII", "age", "个人年龄", r"(?:person|personal|user|patient|employee|customer|member|applicant|candidate|profile|student)_?age|age_?in_?years", "personal_identifier"),
    ("PII", "sex_gender", "性别及性别认同", r"gender(?:_?identity)?|biological_?sex", "personal_identifier"),
    ("PII", "ethnicity", "族群及种族属性", r"ethnicity|ethnic_?origin|racial_?identity|(?:person|personal|user|patient|employee|customer|member|applicant|candidate|profile|student)_?race", "personal_identifier"),
    ("PII", "religious_belief", "宗教信仰及归属", r"religion|religious_?(?:beliefs?|affiliation)", "personal_identifier"),
    ("PII", "education", "个人教育背景", r"education_?(?:level|history)|educational_?attainment|highest_?degree|(?:person|personal|user|patient|employee|customer|member|applicant|candidate|profile|student)_?(?:education|school|degree)", "personal_identifier"),
    ("PII", "employment", "个人就业及职业背景", r"employment_?(?:status|history)|employer_?name|occupation|(?:person|personal|user|patient|employee|customer|member|applicant|candidate|profile|student)_?(?:job_?title|employer|employment|occupation)", "personal_identifier"),
)
# logtrace addition: large-language-model content
RULES = RULES + (
    ("LLM", "prompt", "提示词", r"(?:system|user|full|final|raw)?_?prompts?|prompt_?(?:text|template|messages)", "llm_content"),
    ("LLM", "messages", "对话消息及历史", r"messages|msgs|chat_?history|conversation(?:_?history)?|message_?history", "llm_content"),
    ("LLM", "completion", "模型输出", r"completions?|llm_?(?:response|output|result)|model_?(?:response|output)|generated_?text|assistant_?(?:message|response|reply)", "llm_content"),
    ("LLM", "tool_call", "工具调用参数", r"tool_?(?:calls?|args|arguments|inputs?)|function_?(?:calls?|args|arguments)", "llm_content"),
)
COMPILED = [(row, re.compile(r"(?:^|_)(?:" + row[3] + r")(?:$|_)", re.I)) for row in RULES]
AGGREGATE = re.compile(r"(?:^|_)(?:count|length|size|type|enabled|present|limit|index|usage|total)$", re.I)
CARRIERS = {"opaque_object", "content_visibility_unknown", "internal_configuration", "exception_data"}
SENSITIVE_TYPES = {row[4] for row in RULES} - CARRIERS
FALLBACKS = {
    "credential": ("AUTH", "credential_bundle"),
    "session_identifier": ("QID", "session_identifier"),
    "personal_identifier": ("PII", "unspecified_personal_information"),
    "linkable_identifier": ("QID", "unspecified_linkable_identifier"),
    "connection_string": ("CFG", "database_connection"),
    "opaque_object": ("BIZ", "unclassified_object"),
    "content_visibility_unknown": ("BIZ", "unclassified_content"),
    "internal_configuration": ("CFG", "deployment_configuration"),
    "internal_resource": ("CFG", "unclassified_internal_resource"),
    "exception_data": ("DIAG", "exception_message"),
    "medical_data": ("PII", "medical"), "financial_data": ("PII", "financial"),
    "precise_location": ("PII", "precise_location"), "biometric_data": ("PII", "biometric"),
}


_CONTEXT_LEAVES = {"id", "body", "data", "headers", "name", "age", "race",
                   "education", "school", "degree", "job_title", "employer",
                   "employment", "occupation"}
_FINAL_ACCESS = re.compile(r"(?:\.\s*([A-Za-z_]\w*)|\[\s*['\"]([^'\"]+)['\"]\s*\])\s*$")


def normalize_identifier(source: str) -> str:
    """Normalize finite identifier hints, preserving acronym word boundaries."""
    snake = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", source)
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", snake)
    return re.sub(r"[^A-Za-z0-9_]+", "_", snake).strip("_").lower()


def field_subject(leaf: str, parent: str | None = None) -> tuple[str, int]:
    """A direct field plus finite disambiguating parent; offset starts its leaf."""
    leaf = normalize_identifier(leaf)
    if parent is not None and leaf in _CONTEXT_LEAVES:
        prefix = normalize_identifier(parent)
        if prefix:
            return prefix + "_" + leaf, len(prefix) + 1
    return leaf, 0


def identifier_subject(source: str) -> tuple[str, int]:
    """Select the final projection and at most its immediate named receiver."""
    # Some source labels use _name(call) notation. This selects only the method
    # name; it does not resolve the call or treat its result as a known value.
    source = re.sub(r"\(\s*\)\s*$", "", source)
    access = _FINAL_ACCESS.search(source)
    if not access:
        return field_subject(source)
    leaf = next(part for part in access.groups() if part is not None)
    receiver = source[:access.start()].strip()
    previous = _FINAL_ACCESS.search(receiver)
    if previous:
        parent = next(part for part in previous.groups() if part is not None)
    else:
        parent = receiver if re.fullmatch(r"\$?[A-Za-z_]\w*", receiver) else None
    return field_subject(leaf, parent)


def matches_subject(regex: re.Pattern, subject: tuple[str, int]) -> bool:
    """Reject parent-only matches, including a consumed boundary underscore."""
    text, leaf_start = subject
    if AGGREGATE.search(text):
        return False
    start = 0
    while match := regex.search(text, start):
        if match.end() > leaf_start:
            return True
        start = match.start() + 1
    return False


CONTENT_SUBTYPES = {"messages", "prompt", "completion", "tool_call", "document_content", "message_content",
                    "request_body", "response_body", "business_object"}
CONVERSATION_SUBTYPES = {"messages", "prompt", "completion", "message_content"}
CONVERSATION_ID = next(row for row in RULES if row[1] == "conversation_identifier")


def _matches(source: str, *, parent: str | None = None) -> list[tuple]:
    subject = identifier_subject(source)
    if parent is not None and normalize_identifier(source) in _CONTEXT_LEAVES:
        subject = field_subject(source, parent)
    if AGGREGATE.search(subject[0]):
        return []
    matches = [row for row, regex in COMPILED if matches_subject(regex, subject)]
    # user_id, mac_address and error_response are specific fields, not a whole
    # user/address/response object merely because they contain those words.
    # logtrace.2: a name ending in _id / id is an identifier, never the content it points to
    if re.search(r"(?:^|_)ids?$", subject[0]):
        content = [row for row in matches if row[1] in CONTENT_SUBTYPES]
        matches = [row for row in matches if row[1] not in CONTENT_SUBTYPES]
        if content and not matches and any(row[1] in CONVERSATION_SUBTYPES for row in content):
            matches = [CONVERSATION_ID]
    if any(row[0] == "QID" for row in matches):
        matches = [row for row in matches if row[1] != "business_object"]
    if any(row[4] not in CARRIERS for row in matches):
        matches = [row for row in matches if row[1] not in {"business_object", "deployment_configuration"}]
    if any(row[0] == "AUTH" and row[1] != "credential_bundle" for row in matches):
        matches = [row for row in matches if row[1] != "credential_bundle"]
    if any(row[1] == "stack_trace" for row in matches):
        matches = [row for row in matches if row[1] != "exception_message"]
    if any(row[1] == "failure_response" for row in matches):
        matches = [row for row in matches if row[1] not in {"response_body", "exception_message"}]
    return matches


def identifier_types(source: str) -> set[str]:
    """Compatible coarse types; called only for output values/fields by parser."""
    return {row[4] for row in _matches(source)}


def taxonomy_catalog() -> dict:
    categories = []
    for category, label in CATEGORIES.items():
        rows = {row[1]: {"subtype": row[1], "label": row[2], "legacy_data_types": [row[4]]}
                for row in RULES if row[0] == category}
        for legacy, (parent, subtype) in FALLBACKS.items():
            if parent == category and subtype not in rows:
                rows[subtype] = {"subtype": subtype, "label": "细类待确定", "legacy_data_types": [legacy]}
        categories.append({"category": category, "label": label, "subtypes": list(rows.values())})
    return {"taxonomy_version": TAXONOMY_VERSION, "categories": categories,
            "evidence_boundary": "Static output-value hints; finite rules, no completeness or runtime disclosure claim."}


def match_identifier(source: str) -> list[tuple]:
    """Rules (category, subtype, label, pattern, legacy type) matched by one identifier or access path."""
    return _matches(source)
