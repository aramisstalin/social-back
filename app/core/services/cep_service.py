import httpx
from app.core.schemas import AddressResponse

async def fetch_address_by_cep(cep: str) -> AddressResponse:
    url = f"https://viacep.com.br/ws/{cep}/json/"

    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.get(url)

    if response.status_code != 200 or response.json().get("erro"):
        raise ValueError("CEP não encontrado")

    return AddressResponse(**response.json())
