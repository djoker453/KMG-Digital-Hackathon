import ast
from pathlib import Path


def iter_python_files(target="."):
    root = Path(target)

    for path in root.rglob("*.py"):
        if any(
            part in {
                ".git",
                ".venv",
                "__pycache__",
                "security-reports",
            }
            for part in path.parts
        ):
            continue

        yield path


def parse_python_file(path):
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        return source, tree, None
    except (OSError, UnicodeDecodeError, SyntaxError) as error:
        return None, None, str(error)


def get_decorator_name(decorator):
    if isinstance(decorator, ast.Name):
        return decorator.id

    if isinstance(decorator, ast.Attribute):
        parts = []
        current = decorator

        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.append(current.id)

        return ".".join(reversed(parts))

    if isinstance(decorator, ast.Call):
        return get_decorator_name(decorator.func)

    return ""


def get_decorators(function):
    return [
        get_decorator_name(decorator)
        for decorator in function.decorator_list
    ]


def get_function_source(source, node):
    lines = source.splitlines()

    start = node.lineno - 1
    end = getattr(node, "end_lineno", node.lineno)

    return "\n".join(lines[start:end])


def get_call_names(node):
    names = []

    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func

            if isinstance(func, ast.Name):
                names.append(func.id)

            elif isinstance(func, ast.Attribute):
                names.append(func.attr)

    return names


def get_string_values(node):
    values = []

    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            values.append(child.value)

    return values


def get_url_view_references(tree):
    references = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not isinstance(node.func, ast.Name):
            continue

        if node.func.id != "path":
            continue

        if len(node.args) < 2:
            continue

        route = ""

        if isinstance(node.args[0], ast.Constant):
            if isinstance(node.args[0].value, str):
                route = node.args[0].value

        view_node = node.args[1]

        for child in ast.walk(view_node):
            if not isinstance(child, ast.Attribute):
                continue

            if not isinstance(child.value, ast.Name):
                continue

            if child.value.id != "v":
                continue

            references.append(
                {
                    "module": child.value.id,
                    "function": child.attr,
                    "route": route,
                    "line": node.lineno,
                }
            )

    return references
