-- =============================================================================
-- V6 - Funcionalidade: Role ADMIN_ESTABELECIMENTO
-- Descrição: Cadastra a role ADMIN_ESTABELECIMENTO em auth.role e clona o
--            conjunto de permissões de FUNCIONARIO (verificado manualmente no
--            banco: agendamento:cancel, agendamento:read, agendamento:write,
--            estabelecimento:read, medico:read, servico:read) — o novo perfil
--            tem as mesmas capacidades de FUNCIONARIO na rota, mas escopado a
--            estabelecimento na camada de serviço do sgsm.
-- =============================================================================

INSERT INTO auth.role (id, nome, descricao)
VALUES (gen_random_uuid(), 'ADMIN_ESTABELECIMENTO', 'Administrador de um ou mais estabelecimentos de saúde');

INSERT INTO auth.role_permissao (role_id, permissao_id)
SELECT
    (SELECT id FROM auth.role WHERE nome = 'ADMIN_ESTABELECIMENTO'),
    rp.permissao_id
FROM auth.role_permissao rp
JOIN auth.role r ON r.id = rp.role_id
WHERE r.nome = 'FUNCIONARIO';
