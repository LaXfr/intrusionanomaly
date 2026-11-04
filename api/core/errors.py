"""Safe, structured application errors for HTTP responses."""

from dataclasses import dataclass


@dataclass(slots=True)
class ApiError(Exception):
    status_code: int
    code: str
    message: str

    def __str__(self) -> str:
        return self.message
