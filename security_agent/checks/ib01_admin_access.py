import json

from security_agent.checks.ast_utils import (
    iter_python_files,
    parse_python_file,
    get_decorators,
    get_function_source,
    get_url_view_references,
)


REQUIREMENT_ID = "ИБ-01"

REQUIREMENT = (
    "Административный функционал должен быть доступен исключительно "
    "пользователям с ролью administrator. Проверка роли должна "
    "выполняться на серверной стороне при каждом запросе."
)


ADMIN_ROUTE_KEYWORDS = (
    "manage",
    "admin",
    "export",
    "role",
    "grant",
    "reset",
)


def has_administrator_check(source):
    """
    Ищет признаки серверной проверки роли administrator.
    """

    normalized = source.replace('"', "'").lower()

    patterns = (
        "role == 'administrator'",
        "role != 'administrator'",
        "role in ('operator', 'administrator')",
        "administrator(user)",
        "administrator(request.user)",
        "is_superuser",
    )

    return any(
        pattern in normalized
        for pattern in patterns
    )


def has_admin_required_decorator(decorators):
    """
    Проверяет наличие централизованного admin_required.
    """

    return any(
        decorator.split(".")[-1] == "admin_required"
        for decorator in decorators
    )


def has_manage_required_decorator(decorators):
    """
    Проверяет наличие централизованного manage_required.
    """

    return any(
        decorator.split(".")[-1] == "manage_required"
        for decorator in decorators
    )


def is_admin_route(route):
    """
    Определяет, относится ли маршрут к административному функционалу.

    Например:
        manage/
        manage/users/1/role/
        exports/people.csv
        api/manage/queues/1/
    """

    normalized = route.lower().strip("/")

    if not normalized:
        return False

    parts = normalized.split("/")

    for part in parts:
        if part in ADMIN_ROUTE_KEYWORDS:
            return True

    return any(
        keyword in normalized
        for keyword in ADMIN_ROUTE_KEYWORDS
    )


def build_function_index(parsed_files):
    """
    Создаёт индекс:

        имя функции -> информация о функции
    """

    functions = {}

    for path_string, source, tree in parsed_files:

        for node in tree.body:

            if node.__class__.__name__ not in {
                "FunctionDef",
                "AsyncFunctionDef",
            }:
                continue

            functions[node.name] = {
                "file": path_string,
                "line": node.lineno,
                "source": get_function_source(
                    source,
                    node,
                ),
                "decorators": get_decorators(node),
            }

    return functions


def build_url_index(target):
    """
    Находит все endpoint'ы, объявленные через Django path().
    """

    references = []

    for path_string, source, tree in _parse_project_files(target):

        if not path_string.endswith("urls.py"):
            continue

        references.extend(
            get_url_view_references(tree)
        )

    return references


def _parse_project_files(target):
    """
    Парсит Python-файлы проекта один раз.
    """

    parsed_files = []

    for path in iter_python_files(target):

        path_string = str(path)

        if path_string.startswith("security_agent/"):
            continue

        if path_string.startswith("src/helpdesk/"):
            continue

        source, tree, error = parse_python_file(path)

        if error:
            continue

        parsed_files.append(
            (
                path_string,
                source,
                tree,
            )
        )

    return parsed_files


def check_ib01(target="."):
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

    function_index = build_function_index(
        parsed_files
    )

    url_references = []

    for path_string, source, tree in parsed_files:

        if not path_string.endswith("urls.py"):
            continue

        url_references.extend(
            get_url_view_references(tree)
        )

    checked_functions = set()

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

        if not is_admin_route(route):
            continue

        function_info = function_index.get(
            function_name
        )

        if not function_info:
            continue

        function_key = (
            function_info["file"],
            function_name,
        )

        if function_key in checked_functions:
            continue

        checked_functions.add(
            function_key
        )

        decorators = function_info[
            "decorators"
        ]

        function_source = function_info[
            "source"
        ]

        if has_admin_required_decorator(
            decorators
        ):
            continue

        if has_manage_required_decorator(
            decorators
        ):
            continue

        if has_administrator_check(
            function_source
        ):
            continue

        violations.append(
            {
                "requirement_id": REQUIREMENT_ID,
                "requirement": REQUIREMENT,
                "location": {
                    "file": function_info["file"],
                    "line": function_info["line"],
                    "function": function_name,
                    "route": route,
                },
                "evidence": function_source,
                "explanation": (
                    "Endpoint относится к административному "
                    "функционалу, но в самой функции и её "
                    "декораторах не обнаружена серверная "
                    "проверка роли administrator."
                ),
                "criticality": "HIGH",
                "recommendation": (
                    "Добавить серверную проверку роли "
                    "administrator на каждом запросе. "
                    "Предпочтительно использовать "
                    "централизованный admin_required-декоратор."
                ),
            }
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

    result = check_ib01(".")

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )
