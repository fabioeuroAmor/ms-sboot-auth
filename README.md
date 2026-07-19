# ms-sboot-auth

Microsserviço de **Autenticação e Autorização** do ecossistema SGSM (Sistema de Gerenciamento de Serviços Médicos). Responsável por cadastro de usuários, login, emissão/renovação de tokens JWT e logout, para os perfis `MEDICO`, `PACIENTE`, `FUNCIONARIO` e `DESENVOLVEDOR`.

## Stack

- Java 21
- Spring Boot 4.0.6 (Web MVC, Security, Data JPA)
- PostgreSQL (schema `auth`)
- JWT via `jjwt` 0.12.6
- springdoc-openapi (Swagger UI)
- Maven

## Pré-requisitos

- JDK 21
- Maven 3.6+
- PostgreSQL rodando localmente com o schema `auth` já criado (o serviço não gerencia migrations — `ddl-auto: none`)

## Variáveis de ambiente

| Variável | Obrigatória | Descrição |
|---|---|---|
| `JWT_SECRET` | Sim | Chave usada para assinar/validar os tokens JWT. Deve ter no mínimo 256 bits (32 caracteres). Sem valor default — precisa ser definida em todo ambiente (dev, CI, produção). |

A aplicação não sobe sem `JWT_SECRET` configurada (o `JwtService` falha na inicialização com `WeakKeyException` se a chave for muito curta).

### Configurando localmente

**Via terminal (PowerShell):**

```powershell
$env:JWT_SECRET = "uma-chave-com-pelo-menos-32-caracteres"
mvn spring-boot:run
```

**Via IntelliJ IDEA:**

Run/Debug Configurations → `MsAuthApplication` → Environment variables → adicionar `JWT_SECRET`.

## Configuração do banco

Por padrão (`src/main/resources/application.yaml`), a aplicação conecta em:

```
jdbc:postgresql://localhost:5432/postgres
usuario: postgres / senha: postgres
schema: auth
```

Para outro ambiente, sobrescreva via profile (`application-local.yaml`, `application-prod.yaml` — já ignorados pelo `.gitignore`, nunca comitar credenciais reais).

## Rodando a aplicação

```bash
mvn clean install
mvn spring-boot:run
```

A API sobe em `http://localhost:8081`.

## Documentação da API

Com a aplicação rodando:

- Swagger UI: `http://localhost:8081/swagger-ui/index.html`
- OpenAPI JSON: `http://localhost:8081/v3/api-docs`

## Endpoints

Base path: `/v1/api/auth`

| Método | Rota | Descrição |
|---|---|---|
| POST | `/registrar` | Cria um usuário vinculado a uma entidade já existente no SGSM (`referenciaId` + `tipoPerfil`) |
| POST | `/login` | Autentica e retorna `accessToken` + `refreshToken` |
| GET | `/me` | Retorna os dados do usuário autenticado (a partir do token no header `Authorization`) |
| POST | `/refresh` | Renova o `accessToken` a partir de um `refreshToken` válido (rotaciona o refresh token) |
| POST | `/logout` | Revoga um `refreshToken` |

## Testes

```bash
mvn test
```

Cobertura mínima exigida (JaCoCo, gate no `mvn verify`): **90% de linha**, sobre `controller`, `service` e `exception` (DTOs, entidades, config e repositories são excluídos por não conterem lógica testável).

## Análise de segurança (execução manual)

Não fazem parte do build padrão — rodar sob demanda:

```bash
mvn org.owasp:dependency-check-maven:check
mvn spotbugs:check
```
