-- Trilha estruturada de eventos de autenticacao (evolucao do log de aplicacao
-- adicionado em AuthService — permite consulta SQL em vez de grep de log).
CREATE TABLE auth.log_autenticacao (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    usuario_id  UUID,
    email       VARCHAR(255),
    evento      VARCHAR(30) NOT NULL,
    detalhe     VARCHAR(255),
    criado_em   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_log_autenticacao_usuario ON auth.log_autenticacao(usuario_id);
CREATE INDEX idx_log_autenticacao_email ON auth.log_autenticacao(email);
