from typing import Annotated
from pydantic import BaseModel, StringConstraints


class AddressResponse(BaseModel):
    cep: str
    logradouro: str
    complemento: str
    bairro: str
    localidade: str
    uf: str
    ibge: str
    gia: str
    ddd: str
    siafi: str


class CEPQuery(BaseModel):
    cep: Annotated[str, StringConstraints(pattern=r"^\d{5}-?\d{3}$")]  # Only digits, exactly 8 characters
