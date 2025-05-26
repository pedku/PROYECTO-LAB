from alembic import op
import sqlalchemy as sa

# Revisión ID
revision = 'add_name_column_to_profes'
down_revision = 'previous_revision_id'  # Reemplaza con el ID de la revisión anterior

def upgrade():
    op.add_column('profes', sa.Column('name', sa.String(length=100), nullable=False))
    op.add_column('schedules', sa.Column('user_id', sa.Integer(), nullable=False))
    op.create_foreign_key(None, 'schedules', 'users', ['user_id'], ['id'], ondelete='CASCADE')

def downgrade():
    op.drop_column('profes', 'name')
    op.drop_column('schedules', 'user_id')
