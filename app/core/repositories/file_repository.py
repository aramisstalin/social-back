from functools import lru_cache

from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.schemas import FileResponse
from app.core.schemas.files import FileCreate
from app.core.repositories import BaseRepository
import uuid
import os
import shutil
from fastapi import UploadFile
from app.core.config import settings
from app.core.models import File


class FileRepository(BaseRepository):
    async def upload(self, db: AsyncSession, file: UploadFile):
        # Generate a unique ID for the file
        file_id = uuid.uuid4()

        # Get file extension
        _, ext = os.path.splitext(file.filename)

        # Create a unique filename
        unique_filename = f"{file_id}{ext}"
        file_path = os.path.join(settings.UPLOAD_DIR, unique_filename)

        # Save the file
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Get file size
        file_size = os.path.getsize(file_path)

        # Create file URL
        file_url = f"{settings.BASE_URL}/uploads/{unique_filename}"

        # Store file metadata
        file = FileCreate(
            id=file_id,
            filename=unique_filename,
            url=file_url,
            content_type=file.content_type,
            size=file_size,
            path=file_path
        )

        result = await self.create(db, item=file)
        return FileResponse.model_validate(result)

    async def exclude_file(self, db: AsyncSession, file):
        # Delete the file
        os.remove(file.path)
        # Remove file metadata
        return await self.delete(db, file.id)

    async def get_by_name(self, db: AsyncSession, filename):
        result = await db.execute(select(self.model).filter(self.model.filename == filename))
        return result.scalars().first()

@lru_cache()
def get_file_repository() -> FileRepository:
    return FileRepository(File)