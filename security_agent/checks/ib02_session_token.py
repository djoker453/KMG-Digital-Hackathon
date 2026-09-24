import ast
import json

from security_agent.checks.ast_utils import (
    iter_python_files,
    parse_python_file,
    get_decorators,
    get_function_source,
    get_call_names,
    get_url_view_references,
)


REQUIREMENT_ID = "ИБ-02"

REQUIREMENT = (
    "Сессионная или токенная аутентификация должна проверяться "
    "на серверной стороне при каждом запросе к защищённым "
    "endpoint'ам, включая API."
)


AUTH_DECORATORS = {
    "login_required",
    "permission_required",
    "user_passes_test",
}


TOKEN_CHECK_FUNCTIONS = {
    "token_user",
    "authenticate",
    "authentication",
    "verify_token",
    "validate_token",
    "check_token",
}


API_ROUTE_KEYWORDS = {
    "api",
}


def is_function_node(node):
    return node.__class__.__name__ in {
        "FunctionDef",
        "AsyncFunctionDef",
    }


def is_api_route(route):
    normalized = route.lower().strip("/")

    return any(
        part in API_ROUTE_KEYWORDS
        for part in normalized.split("/")
    )


def has_auth_decorator(decorators):
    """
    Проверяет стандартные Django-декораторы
    аутентификации.
    """

    for decorator in decorators:
        name = decorator.split(".")[-1]

        if name in AUTH_DECORATORS:
            return True

    return False


def has_token_check(source):
    """
    Проверяет вызов серверной функции проверки токена.
    """

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False

    calls = get_call_names(tree)

    return any(
        call in TOKEN_CHECK_FUNCTIONS
        for call in calls
    )


def has_explicit_auth_check(source):
    """
    Проверяет явную серверную проверку
    authenticated-состояния пользователя.
    """

    normalized = (
        source
        .replace(" ", "")
        .replace('"', "'")
        .lower()
    )

    patterns = (
        "is_authenticated",
        "request.user.is_authenticated",
        "user.is_authenticated",
    )

    return any(
        pattern in normalized
        for pattern in patterns
    )


def decorator_provides_auth(
    decorator_name,
    decorator_definitions,
    checked=None,
):
    """
    Рекурсивно проверяет пользовательский декоратор.

    Например:

        @access.manage_required

    ->
        def manage_required(...):
            @login_required
            ...
    """

    if checked is None:
        checked = set()

    name = decorator_name.split(".")[-1]

    if name in checked:
        return False

    checked.add(name)

    if name in AUTH_DECORATORS:
        return True

    source = decorator_definitions.get(name)

    if not source:
        return False

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False

    for node in ast.walk(tree):

        if not isinstance(node, ast.FunctionDef):
            continue

        decorators = get_decorators(node)

        if has_auth_decorator(decorators):
            return True

        for decorator in decorators:
            if decorator_provides_auth(
                decorator,
                decorator_definitions,
                checked,
            ):
                return True

    return False


def endpoint_has_auth(
    decorators,
    source,
    decorator_definitions,
):
    """
    Определяет, существует ли серверная
    аутентификация endpoint'а.
    """

    if has_auth_decorator(decorators):
        return True

    for decorator in decorators:

        if decorator_provides_auth(
            decorator,
            decorator_definitions,
        ):
            return True

    if has_token_check(source):
        return True

    if has_explicit_auth_check(source):
        return True

    return False


def analyze_endpoint(
    function_info,
    route,
    decorator_definitions,
):
    source = function_info["source"]
    decorators = function_info["decorators"]

    if endpoint_has_auth(
        decorators,
        source,
        decorator_definitions,
    ):
        return None

    return {
        "requirement_id": REQUIREMENT_ID,
        "requirement": REQUIREMENT,
        "location": {
            "file": function_info["file"],
            "line": function_info["line"],
            "function": function_info["function"],
            "route": route,
        },
        "evidence": source,
        "explanation": (
            "Endpoint доступен через маршрут проекта, "
            "но в его декораторах, связанных пользовательских "
            "декораторах или теле функции не обнаружена "
            "серверная проверка аутентификации или токена."
        ),
        "criticality": "HIGH",
        "recommendation": (
            "Добавить серверную проверку аутентификации "
            "на каждый защищённый запрос. Для API использовать "
            "централизованную проверку валидности токена "
            "до обработки запроса."
        ),
    }


def check_ib02(target="."):
    violations = []
    parse_errors = []
    parsed_files = []

    for path in iter_python_files(target):

        path_string = str(path)

        if path_string.startswith("security_agent/"):
            continue

        if path_string.startswith("src/helpdesk/"):
            continue

        source, tree, error = parse_python_file(path)

        if error:
            parse_errors.append(
                {
                    "file": path_string,
                    "error": error,
                }
            )
            continue

        parsed_files.append(
            (
                path_string,
                source,
                tree,
            )
        )

    function_index = {}
    decorator_definitions = {}

    for path_string, source, tree in parsed_files:

        for node in tree.body:

            if not is_function_node(node):
                continue

            function_source = get_function_source(
                source,
                node,
            )

            decorators = get_decorators(node)

            function_index[node.name] = {
                "file": path_string,
                "line": node.lineno,
                "function": node.name,
                "source": function_source,
                "decorators": decorators,
            }

            decorator_definitions[node.name] = (
                function_source
            )

    url_references = []

    for path_string, source, tree in parsed_files:

        if not path_string.endswith("urls.py"):
            continue

        url_references.extend(
            get_url_view_references(tree)
        )

    checked_endpoints = set()

    for reference in url_references:

        route = reference.get(
            "route",
            "",
        )

        function_name = reference.get(
            "function"
        )

        if not function_name:
            continue

        function_info = function_index.get(
            function_name
        )

        if not function_info:
            continue

        endpoint_key = (
            function_info["file"],
            function_name,
            route,
        )

        if endpoint_key in checked_endpoints:
            continue

        checked_endpoints.add(
            endpoint_key
        )

        violation = analyze_endpoint(
            function_info,
            route,
            decorator_definitions,
        )

        if violation:
            violations.append(
                violation
            )

    return {
        "requirement_id": REQUIREMENT_ID,
        "requirement": REQUIREMENT,
        "violations": violations,
        "parse_errors": parse_errors,
        "status": (
            "VIOLATION"
            if violations
            else "PASS"
        ),
    }


if __name__ == "__main__":

    result = check_ib02(".")

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )
