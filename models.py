from pydantic import BaseModel


class URLRequest(BaseModel):
    url: str
    user_id: str = "guest"
