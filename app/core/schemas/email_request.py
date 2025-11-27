from app.core.schemas import BaseSchema


class EmailRequest(BaseSchema):
    to: str
    subject: str | None = None
    body: str | None = None
