"""Initial schema

Revision ID: 001
Revises: 
Create Date: 2025-10-01

"""
from alembic import op
import sqlalchemy as sa


revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('traffic_logs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
    sa.Column('source_ip', sa.String(length=45), nullable=True),
    sa.Column('destination_ip', sa.String(length=45), nullable=True),
    sa.Column('source_port', sa.Integer(), nullable=True),
    sa.Column('destination_port', sa.Integer(), nullable=True),
    sa.Column('protocol', sa.String(length=10), nullable=True),
    sa.Column('packet_length', sa.Integer(), nullable=True),
    sa.Column('flags', sa.String(length=50), nullable=True),
    sa.Column('features', sa.JSON(), nullable=True),
    sa.Column('raw_data', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_traffic_logs_destination_ip'), 'traffic_logs', ['destination_ip'], unique=False)
    op.create_index(op.f('ix_traffic_logs_id'), 'traffic_logs', ['id'], unique=False)
    op.create_index(op.f('ix_traffic_logs_source_ip'), 'traffic_logs', ['source_ip'], unique=False)
    op.create_index(op.f('ix_traffic_logs_timestamp'), 'traffic_logs', ['timestamp'], unique=False)
    
    op.create_table('predictions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
    sa.Column('traffic_log_id', sa.Integer(), nullable=True),
    sa.Column('model_name', sa.String(length=50), nullable=True),
    sa.Column('predicted_class', sa.String(length=100), nullable=True),
    sa.Column('confidence_score', sa.Float(), nullable=True),
    sa.Column('is_attack', sa.Boolean(), nullable=True),
    sa.Column('all_probabilities', sa.JSON(), nullable=True),
    sa.Column('processing_time_ms', sa.Float(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_predictions_id'), 'predictions', ['id'], unique=False)
    op.create_index(op.f('ix_predictions_is_attack'), 'predictions', ['is_attack'], unique=False)
    op.create_index(op.f('ix_predictions_model_name'), 'predictions', ['model_name'], unique=False)
    op.create_index(op.f('ix_predictions_predicted_class'), 'predictions', ['predicted_class'], unique=False)
    op.create_index(op.f('ix_predictions_timestamp'), 'predictions', ['timestamp'], unique=False)
    op.create_index(op.f('ix_predictions_traffic_log_id'), 'predictions', ['traffic_log_id'], unique=False)
    
    op.create_table('alerts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
    sa.Column('prediction_id', sa.Integer(), nullable=True),
    sa.Column('severity', sa.String(length=20), nullable=True),
    sa.Column('attack_type', sa.String(length=100), nullable=True),
    sa.Column('source_ip', sa.String(length=45), nullable=True),
    sa.Column('destination_ip', sa.String(length=45), nullable=True),
    sa.Column('confidence', sa.Float(), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('acknowledged', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_alerts_acknowledged'), 'alerts', ['acknowledged'], unique=False)
    op.create_index(op.f('ix_alerts_id'), 'alerts', ['id'], unique=False)
    op.create_index(op.f('ix_alerts_prediction_id'), 'alerts', ['prediction_id'], unique=False)
    op.create_index(op.f('ix_alerts_severity'), 'alerts', ['severity'], unique=False)
    op.create_index(op.f('ix_alerts_timestamp'), 'alerts', ['timestamp'], unique=False)
    
    op.create_table('model_metrics',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
    sa.Column('model_name', sa.String(length=50), nullable=True),
    sa.Column('model_version', sa.String(length=20), nullable=True),
    sa.Column('dataset_name', sa.String(length=100), nullable=True),
    sa.Column('accuracy', sa.Float(), nullable=True),
    sa.Column('precision', sa.Float(), nullable=True),
    sa.Column('recall', sa.Float(), nullable=True),
    sa.Column('f1_score', sa.Float(), nullable=True),
    sa.Column('confusion_matrix', sa.JSON(), nullable=True),
    sa.Column('class_metrics', sa.JSON(), nullable=True),
    sa.Column('training_duration_seconds', sa.Float(), nullable=True),
    sa.Column('parameters', sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_model_metrics_id'), 'model_metrics', ['id'], unique=False)
    op.create_index(op.f('ix_model_metrics_model_name'), 'model_metrics', ['model_name'], unique=False)
    op.create_index(op.f('ix_model_metrics_timestamp'), 'model_metrics', ['timestamp'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_model_metrics_timestamp'), table_name='model_metrics')
    op.drop_index(op.f('ix_model_metrics_model_name'), table_name='model_metrics')
    op.drop_index(op.f('ix_model_metrics_id'), table_name='model_metrics')
    op.drop_table('model_metrics')
    op.drop_index(op.f('ix_alerts_timestamp'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_severity'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_prediction_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_acknowledged'), table_name='alerts')
    op.drop_table('alerts')
    op.drop_index(op.f('ix_predictions_traffic_log_id'), table_name='predictions')
    op.drop_index(op.f('ix_predictions_timestamp'), table_name='predictions')
    op.drop_index(op.f('ix_predictions_predicted_class'), table_name='predictions')
    op.drop_index(op.f('ix_predictions_model_name'), table_name='predictions')
    op.drop_index(op.f('ix_predictions_is_attack'), table_name='predictions')
    op.drop_index(op.f('ix_predictions_id'), table_name='predictions')
    op.drop_table('predictions')
    op.drop_index(op.f('ix_traffic_logs_timestamp'), table_name='traffic_logs')
    op.drop_index(op.f('ix_traffic_logs_source_ip'), table_name='traffic_logs')
    op.drop_index(op.f('ix_traffic_logs_id'), table_name='traffic_logs')
    op.drop_index(op.f('ix_traffic_logs_destination_ip'), table_name='traffic_logs')
    op.drop_table('traffic_logs')
