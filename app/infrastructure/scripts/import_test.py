from app.infrastructure.database.db_setup import Base
import app.infrastructure.database.models

print(Base.metadata.tables.keys())