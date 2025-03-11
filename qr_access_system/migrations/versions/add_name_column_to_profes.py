from alembic import op
import sqlalchemy as sa

# Revisión ID
revision = 'add_name_column_to_profes'
down_revision = 'previous_revision_id'  # Reemplaza con el ID de la revisión anterior

def upgrade():
    op.add_column('profes', sa.Column('name', sa.String(length=100), nullable=False))

def downgrade():
    op.drop_column('profes', 'name')
