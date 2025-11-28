from pydantic import BaseModel, ConfigDict
from pydantic_settings import SettingsConfigDict


class BaseSchema(BaseModel):
    # model_config = ConfigDict(from_attributes=True)
    model_config = SettingsConfigDict(env_file=".env", from_attributes=True)

