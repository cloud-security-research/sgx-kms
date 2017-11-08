"""add_encryption_keys_policies_table

Revision ID: ea6934da4b17
Revises: d2780d5aa510
Create Date: 2017-03-21 23:15:00.646286

"""

# revision identifiers, used by Alembic.
revision = 'ea6934da4b17'
#down_revision = 'c2cf30454188'
down_revision = 'd2780d5aa510'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ctx = op.get_context()
    con = op.get_bind()

    table_exists = ctx.dialect.has_table(con.engine, 'encryption_keys')
    if not table_exists:
        op.create_table(
            'encryption_keys',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('deleted_at', sa.DateTime(), nullable=True),
            sa.Column('deleted', sa.Boolean(), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('project_id', sa.String(length=36), nullable=False),
            sa.Column('session_key', sa.Text()),
            sa.Column('master_key', sa.Text()),
            sa.ForeignKeyConstraint(['project_id'], ['projects.id']),
            sa.PrimaryKeyConstraint('id')
        )

    table_exists = ctx.dialect.has_table(con.engine, 'project_policies')
    if not table_exists:
        op.create_table(
            'project_policies',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('deleted_at', sa.DateTime(), nullable=True),
            sa.Column('deleted', sa.Boolean(), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('project_id', sa.String(length=36), nullable=False),
            sa.Column('mr_s', sa.Text()),
            sa.Column('mr_e', sa.Text()),
            sa.Column('mr_e_list', sa.Text()),
            sa.Column('policy', sa.Integer()),
            sa.ForeignKeyConstraint(['project_id'], ['projects.id']),
            sa.PrimaryKeyConstraint('id')
        )

def downgrade():
    ctx = op.get_context()
    con = op.get_bind()

    table_exists = ctx.dialect.has_table(con.engine, 'encryption_keys')
    if table_exists:
        op.drop_table('encryption_keys')

    table_exists = ctx.dialect.has_table(con.engine, 'project_policies')
    if table_exists:
        op.drop_table('project_policies')
