"""Parser registry: line parsers + file-level handlers, extensible by decoration."""

from typing import Callable, Iterator

LINE_PARSERS: dict[str, Callable[[str], dict | None]] = {}
FILE_HANDLERS: dict[str, Callable] = {}


def register_line(*formats: str) -> Callable:
    def deco(fn: Callable[[str], dict | None]) -> Callable:
        for f in formats:
            LINE_PARSERS[f] = fn
        return fn
    return deco


def register_file(*formats: str) -> Callable:
    def deco(fn) -> Callable:
        for f in formats:
            FILE_HANDLERS[f] = fn
        return fn
    return deco


def get_line_parser(fmt: str) -> Callable[[str], dict | None]:
    return LINE_PARSERS.get(fmt)


def get_file_handler(fmt: str):
    return FILE_HANDLERS.get(fmt)


def iter_records(fmt: str, path, chunk_iter: Iterator[list[str]]):
    """Unified record iterator yielding (line_no, raw, fields|None).

    Uses a file-level handler for structured/multiline formats, otherwise the
    registered line parser applied per streamed chunk.
    """
    handler = get_file_handler(fmt)
    if handler is not None:
        yield from handler(path)
        return
    parser = get_line_parser(fmt)
    line_no = 0
    for batch in chunk_iter:
        for raw in batch:
            line_no += 1
            fields = parser(raw) if parser else None
            yield line_no, raw, fields
