-- =============================================================================
-- V7 - Fix: CHECK constraint de auth.usuario nao incluia ADMIN_ESTABELECIMENTO
-- Descrição: chk_tipo_perfil foi criada antes do role ADMIN_ESTABELECIMENTO
--            existir (V6) e nunca foi atualizada. Isso fazia todo
--            POST /auth/registrar com tipoPerfil=ADMIN_ESTABELECIMENTO falhar
--            com 500 (violacao de constraint no INSERT em auth.usuario),
--            mesmo com a role/permissoes corretas ja cadastradas.
-- =============================================================================

ALTER TABLE auth.usuario DROP CONSTRAINT IF EXISTS chk_tipo_perfil;

ALTER TABLE auth.usuario ADD CONSTRAINT chk_tipo_perfil
    CHECK (tipo_perfil IN ('MEDICO', 'PACIENTE', 'FUNCIONARIO', 'DESENVOLVEDOR', 'ADMIN_ESTABELECIMENTO'));
