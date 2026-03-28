# BountyMind v4.0

Sistema multi-agente de automatización de bug bounty construido sobre LangGraph. Orquesta seis agentes de ataque especializados, diez puntos de control HITL (Human-in-the-Loop) y genera reportes profesionales listos para plataformas como HackerOne, Bugcrowd e Intigriti.

---

## Tabla de Contenidos

1. [Arquitectura General](#1-arquitectura-general)
2. [Flujo del Grafo LangGraph](#2-flujo-del-grafo-langgraph)
3. [Estado del Sistema — BountyMindState](#3-estado-del-sistema--bountymindstate)
4. [Agentes del Pipeline Principal](#4-agentes-del-pipeline-principal)
5. [El Swarm de Ataque — 6 Agentes Especializados](#5-el-swarm-de-ataque--6-agentes-especializados)
6. [Sistema HITL — Human-in-the-Loop](#6-sistema-hitl--human-in-the-loop)
7. [Subgrafo de Agente de Equipo](#7-subgrafo-de-agente-de-equipo)
8. [Modelos LLM y Configuración](#8-modelos-llm-y-configuración)
9. [API REST](#9-api-rest)
10. [Streaming en Tiempo Real — SSE](#10-streaming-en-tiempo-real--sse)
11. [Herramientas y Técnicas de Ataque](#11-herramientas-y-técnicas-de-ataque)
12. [Persistencia y Checkpointing](#12-persistencia-y-checkpointing)
13. [Frontend React](#13-frontend-react)
14. [Estructura de Archivos](#14-estructura-de-archivos)
15. [Instalación y Puesta en Marcha](#15-instalación-y-puesta-en-marcha)
16. [Variables de Entorno](#16-variables-de-entorno)
17. [Generación del Reporte Final](#17-generación-del-reporte-final)

---

## 1. Arquitectura General

BountyMind v4.0 sigue una arquitectura **de pipeline por fases con fan-out paralelo**:

```
┌─────────────────────────────────────────────────────────────────┐
│                        BOUNTYMIND v4.0                          │
│                                                                 │
│  Operador ──HITL──► Grafo LangGraph ◄──SSE── Frontend React    │
│                           │                                     │
│              ┌────────────┼────────────┐                        │
│          Fase 0        Fase 1       Fase 2                      │
│         (Recon)       (Ataque)    (Síntesis)                    │
│                       6 Agentes   + Reporte                     │
└─────────────────────────────────────────────────────────────────┘
```

**Componentes principales:**

| Componente | Tecnología | Rol |
|---|---|---|
| Orquestador | LangGraph (StateGraph) | Gestión del flujo y estado |
| Agentes | LangChain + Subgrafos | Ejecución de pruebas de seguridad |
| HITL | interrupt() + Command(resume=) | Control humano del pipeline |
| Backend | FastAPI + asyncio | API REST y streaming SSE |
| Frontend | React 18 + Zustand + Vite | Interfaz de monitoreo y control |
| LLM | Fireworks AI (7 modelos) | Razonamiento e inteligencia |
| Persistencia | SQLite (dev) / PostgreSQL (prod) | Checkpointing del grafo |

---

## 2. Flujo del Grafo LangGraph

El grafo tiene **11 nodos principales**, **10 nodos HITL**, **6 subgrafos de agentes de equipo** y **5 nodos de transición de fase**:

```
START
  │
  ▼
┌─────────────┐
│  commander  │  Inicializa estado, deriva scope, asigna thread_id
└──────┬──────┘
       │
  ▼ HITL ▼
┌──────────────────┐
│ hitl_SCOPE_REVIEW │  ⏸ Operador revisa y aprueba el scope del target
└────────┬─────────┘
         │
         ▼
┌───────────────┐
│ surface_recon │  Mapea endpoints, formularios, tecnologías, JavaScript
└───────┬───────┘
        │
        ▼
┌────────────────┐
│ behavior_recon │  Analiza flujos de usuario, autenticación, rate limiting
└───────┬────────┘
        │
        ▼
┌────────────┐
│ recon_join │  Consolida inventario de superficie de ataque
└─────┬──────┘
      │
      ▼
┌──────────┐
│ research │  OSINT: CVEs, GitHub advisories, Tavily, hacktivity
└────┬─────┘
     │
 ▼ HITL ▼
┌─────────────────────┐
│ hitl_STRATEGY_REVIEW │  ⏸ Operador valida la estrategia de ataque
└──────────┬──────────┘
           │
           ▼
┌──────────┐
│ strategy │  LLM genera loadouts por agente (misión, test cases, tools)
└────┬─────┘
     │
 ▼ HITL ▼
┌─────────────────────┐
│ hitl_LOADOUT_REVIEW │  ⏸ Operador ajusta y aprueba loadouts antes del ataque
└──────────┬──────────┘
           │
    [Send API — fan-out paralelo]
           │
    ┌──────┴───────────────────────────────────┐
    │              SWARM DE ATAQUE              │
    ├─► agent_WebTester      → findings locales ─┤
    ├─► agent_AuthProber     → findings locales ─┤ operator.add
    ├─► agent_LogicAnalyst   → findings locales ─┤ (acumulación thread-safe)
    ├─► agent_CodeInspector  → findings locales ─┤
    ├─► agent_IntegrationScout → findings locales┤
    └─► agent_InfraProber    → findings locales ─┘
           │
           ▼
┌─────────────┐
│ attack_join │  Fusiona raw_findings de todos los agentes
└──────┬──────┘
       │
       ▼
┌────────────┐
│ synthesizer│  Detecta cadenas de ataque multi-finding (CVSS compuesto)
└─────┬──────┘
      │
      ▼
┌───────────┐
│ validator │  Valida findings: plausibilidad, evidencia, reproducibilidad
└─────┬─────┘
      │
  ▼ HITL ▼
┌──────────────────┐
│ hitl_PRE_REPORT  │  ⏸ Operador revisión final antes del reporte
└───────┬──────────┘
        │
        ▼
┌──────────┐
│ reporter │  Genera reporte Markdown profesional con CVSS, remediation, impacto
└────┬─────┘
     │
     ▼
    END
```

### Puntos de interrupción condicional

Además de los tres HITL obligatorios del flujo principal, el sistema puede insertar interrupciones adicionales durante la fase de ataque cuando:

- Un agente descubre un finding con CVSS ≥ 9.0 → `hitl_HIGH_SEVERITY`
- Un agente está a punto de ejecutar una acción destructiva → `hitl_DESTRUCTIVE`
- Se detecta nueva superficie no contemplada en el scope → `hitl_NEW_SURFACE`
- Un agente alcanza `max_iterations` sin resultados → `hitl_AGENT_STALLED`
- El sintetizador genera una cadena con CVSS ≥ 9.5 → `hitl_CHAIN_CRITICAL`
- Se requieren credenciales para continuar → `hitl_CREDENTIALS`

---

## 3. Estado del Sistema — BountyMindState

El estado es un `TypedDict` que fluye a través de todo el grafo. Los campos marcados con `Annotated[list, operator.add]` se **acumulan de forma thread-safe** durante la ejecución paralela del swarm.

```python
class BountyMindState(TypedDict):
    # ── Entradas del operador ──────────────────────────────────────
    target_brief:         str          # URL + contexto del target
    operator_context:     dict         # Decisiones e instrucciones del operador
    scope_rules:          dict         # URLs in-scope / out-of-scope / restricciones
    run_config:           dict         # Configuración de la ejecución

    # ── Datos de reconocimiento ────────────────────────────────────
    surface_inventory:    dict         # Endpoints, formularios, tecnologías, JS findings
    target_context:       dict         # CVEs, técnicas probadas, patrones de sector (OSINT)

    # ── Planificación ──────────────────────────────────────────────
    attack_strategy:      dict         # Narrativa de ataque, áreas de amenaza
    agent_loadouts:       dict         # {agent_id: AgentLoadOut} — configuración por agente

    # ── Findings (acumulativos via operator.add) ───────────────────
    raw_findings:         Annotated[list, operator.add]  # Todos los findings del swarm
    validated_findings:   list          # Findings post-validación
    attack_chains:        list          # Cadenas de ataque sintetizadas
    false_positives:      list          # Findings rechazados por el validador

    # ── Tracking de ejecución ──────────────────────────────────────
    agent_status:         dict         # {agent_id: {phase, iteration, last_finding, active}}
    shared_memory:        dict         # Memoria compartida inter-agente
    phase:                str          # Fase actual del pipeline
    phase_history:        Annotated[list, operator.add]  # Línea de tiempo de fases
    messages:             Annotated[list, operator.add]  # Logs de agentes
    audit_log:            Annotated[list, operator.add]  # Trazabilidad de seguridad

    # ── HITL ────────────────────────────────────────────────────────
    pending_interrupts:   list         # Interrupciones en espera de respuesta
    interrupt_log:        Annotated[list, operator.add]  # Historial de interrupciones

    # ── Metadata ────────────────────────────────────────────────────
    thread_id:            str          # Identificador único de la ejecución
    confidence_threshold: float        # Umbral de confianza para promover findings (default: 0.85)
```

### Secuencia de fases

```
BRIEF → RECON → INTELLIGENCE → STRATEGY → ATTACK → SYNTHESIS → VALIDATION → REVIEW → REPORT
```

---

## 4. Agentes del Pipeline Principal

### Commander

**Archivo:** `graph/commander.py`

Nodo inicial del grafo. Recibe el `target_brief` del operador y realiza la inicialización de la sesión:

- Parsea la URL del target y extrae el dominio base
- Deriva `scope_rules` por defecto si no se proporcionan
- Genera el `thread_id` único de la sesión
- Inicializa el `audit_log` con el evento de inicio
- Establece la `confidence_threshold` desde `run_config` o valor por defecto (0.85)

---

### Surface Agent

**Archivo:** `agents/recon/surface_agent.py` | **Modelo:** MODEL_RECON (Llama 70B)

Construye el **inventario completo de la superficie de ataque**. Ejecuta en paralelo:

| Herramienta | Función |
|---|---|
| `httpx_probe` | Fingerprinting HTTP, headers de seguridad, cookies |
| `subfinder` | Descubrimiento de subdominios |
| `naabu` | Escaneo de puertos abiertos |
| `katana` | Rastreo de URLs y formularios |
| `gau` | URLs de wayback machine y índices |
| `wappalyzer` | Detección de tecnologías (frameworks, CMS, CDN) |
| `js_bundle_analyzer` | Análisis de bundles JavaScript (endpoints ocultos, tokens) |
| Browser (Playwright) | Renderizado completo para SPAs |

**Output:** `surface_inventory` con campos `endpoints`, `forms`, `auth_mechanisms`, `technologies`, `infrastructure`, `js_findings`.

---

### Behavior Agent

**Archivo:** `agents/recon/behavior_agent.py` | **Modelo:** MODEL_RECON

Analiza el comportamiento de la aplicación:

- Flujos de usuario y transiciones de estado
- Mecanismos de autenticación (JWT, sesiones, OAuth)
- Comportamiento de rate limiting
- Patrones de respuesta ante errores (información leakeada)
- Consistencia de headers de seguridad entre rutas

---

### Research Agent (OSINT)

**Archivo:** `agents/intelligence/research_agent.py` | **Modelo:** MODEL_RESEARCH (Mixtral 8x22B)

Realiza investigación de inteligencia sobre el target:

| Fuente | Información Obtenida |
|---|---|
| **GitHub Advisory DB** | CVEs vinculados a las tecnologías detectadas |
| **NVD (NIST)** | Detalles técnicos y CVSS de vulnerabilidades conocidas |
| **Tavily Search** | Hacktivity pública, writeups, técnicas específicas del sector |
| **HackerOne** | Reportes públicos de vulnerabilidades similares |

**Output:** `target_context` con `cve_list`, `proven_techniques`, `sector_patterns`, `interesting_observations`.

---

### Strategy Engine

**Archivo:** `agents/strategy/strategy_engine.py` | **Modelo:** MODEL_THINKER (DeepSeek R1)

El corazón del sistema de planificación. Usa structured output para generar:

**`AttackStrategy`:**
- Narrativa de ataque completa
- Áreas de amenaza prioritizadas con rationale
- Secuencia de testing
- Hipótesis globales y plan de colaboración entre agentes

**`AgentLoadOut` por agente (×6):**
```python
class AgentLoadOut(BaseModel):
    agent_id:             str
    active:               bool          # Si el agente debe ejecutarse
    priority:             int           # Orden de ejecución
    mission:              str           # Descripción clara del objetivo
    rationale:            str           # Por qué este agente en este target
    hypotheses:           list[str]     # Hipótesis de vulnerabilidades a verificar
    test_cases:           list[dict]    # Casos de prueba concretos con técnica y URL
    system_prompt:        str           # Prompt de sistema personalizado para el agente
    methodology:          list[str]     # Pasos metodológicos
    tools:                list[str]     # Herramientas habilitadas
    tool_configs:         dict          # Parámetros de herramientas
    write_channels:       list[str]     # Canales de memoria a escribir
    read_channels:        list[str]     # Canales de memoria a leer
    max_iterations:       int           # Máximo de iteraciones (default: 25)
    interrupt_conditions: list[str]     # Cuándo disparar un HITL
    success_criteria:     list[str]     # Criterios de éxito de la misión
```

Si el structured output falla, el motor de estrategia tiene un fallback rule-based que genera loadouts mínimos basados en el `surface_inventory`.

---

### Chain Synthesizer

**Archivo:** `agents/synthesis/chain_synthesizer.py` | **Modelo:** MODEL_SYNTHESIZER (DeepSeek V3)

Detecta **cadenas de ataque** combinando múltiples findings individuales:

- Busca combinaciones que amplifiquen el impacto conjunto
- Calcula `cvss_composed` (siempre mayor que el CVSS individual más alto)
- Genera `narrative` y `attack_scenario` narrativo para el reporte
- Tiene fallback rule-based para combinaciones conocidas (e.g., IDOR + auth bypass = escalada completa)

**Output:** `attack_chains` con campos `id`, `title`, `finding_ids`, `agents_involved`, `narrative`, `attack_scenario`, `cvss_composed`, `confidence`, `impact`.

---

### Validator Agent

**Archivo:** `agents/validator/validator_agent.py` | **Modelo:** MODEL_RESEARCH

Valida cada `RawFinding` antes de promoverlo a `ValidatedFinding`:

| Dimensión | Descripción |
|---|---|
| `plausibility` | ¿Es técnicamente posible en este target? |
| `evidence_quality` | ¿La evidencia (request/response) es convincente? |
| `impact_clarity` | ¿El impacto de negocio está bien definido? |
| `reproducibility` | ¿Los pasos de reproducción son completos y correctos? |
| `poc_result` | Resultado del PoC runner (si aplica) |
| `confidence_score` | Score compuesto (0.0–1.0) |

Los findings que superan `confidence_threshold` pasan a `validated_findings`. Los demás van a `false_positives`.

---

### Reporter Agent

**Archivo:** `agents/reporter/report_agent.py` | **Modelo:** MODEL_RESEARCH (temperature=0.1)

Genera el **reporte profesional final** en Markdown:

1. Lee `validated_findings` (máx. 15) y `attack_chains` (máx. 5)
2. Envía resúmenes en JSON al LLM con el prompt de sistema `REPORTER_SYSTEM`
3. El LLM devuelve JSON estructurado con `executive_summary`, `findings_reports` (remediation + impacto por finding) y `chains_reports`
4. Construye el Markdown final usando las plantillas de `templates.py`
5. El reporte queda en `operator_context.final_report_markdown`

Si el LLM falla, el fallback `_fallback_report()` genera un reporte estructurado rule-based con todos los findings.

**Estructura del reporte:**
```markdown
# Bug Bounty Security Report
**Target:** ...  **Generated:** ...  **Total Validated Findings:** N
**Critical / High:** N  **Attack Chains Identified:** N

## Executive Summary
...

## Findings
### CRITICAL — [Título del Finding]
**CVSS:** 9.8 | **URL:** ... | **Type:** SQL Injection
**Description:** ...
**Reproduction Steps:** ...
**Impact:** ...
**Remediation:** ...

## Attack Chains
### [Título de la Cadena]
**Composed CVSS:** 10.0 | **Confidence:** 95%
...
```

---

## 5. El Swarm de Ataque — 6 Agentes Especializados

El swarm se lanza con **LangGraph Send API** (fan-out), ejecutando todos los agentes activos en paralelo. Cada agente corre su propio subgrafo interno.

### WebTester

**Modelo:** MODEL_AGENT_STD (Llama v3.3 70B) | **Especialidad:** Vulnerabilidades HTTP/Web

| Técnica | Método |
|---|---|
| **XSS Reflejado** | Inyecta payloads en parámetros GET/POST, busca reflexión en respuesta |
| **XSS Almacenado** | Envía payload vía formularios y verifica persistencia |
| **CSRF** | Verifica ausencia de tokens anti-CSRF en formularios mutantes |
| **Open Redirect** | Muta parámetros `redirect`, `next`, `url` con dominios externos |
| **HTTP Parameter Pollution** | Duplica parámetros clave para explotar inconsistencias de parseo |

Cuando la técnica programática no es concluyente, llama al LLM para análisis heurístico de la respuesta HTTP.

---

### AuthProber

**Modelo:** MODEL_AGENT_STD | **Especialidad:** Autenticación y sesiones

| Técnica | Método |
|---|---|
| **Timing Attack** | Mide diferencia de tiempo entre usuarios existentes/no existentes (≥100ms = vulnerable) |
| **Reset Token Analysis** | Solicita múltiples tokens y evalúa entropía / secuencialidad |
| **OAuth redirect_uri** | Prueba parámetros `redirect_uri` manipulados en flujos OAuth |
| **User Enumeration** | Compara respuestas de login para usuarios válidos vs inválidos |
| **Session Fixation** | Verifica si el session ID cambia tras autenticación exitosa |
| **Brute Force Check** | Detecta ausencia de rate limiting en endpoints de autenticación |

---

### LogicAnalyst

**Modelo:** MODEL_SYNTHESIZER (DeepSeek V3) | **Especialidad:** Lógica de negocio

| Técnica | Método |
|---|---|
| **IDOR** | Manipula IDs numéricos/UUIDs en endpoints REST para acceder a recursos ajenos |
| **Mass Assignment** | Inyecta campos de privilegios (`role`, `is_admin`, `plan`) en body de request |
| **Privilege Escalation** | Prueba endpoints de administración con tokens de usuario normal |
| **Workflow Bypass** | Salta pasos del flujo (e.g., pago → confirmación sin proceso intermedio) |

Usa el modelo de razonamiento DeepSeek V3 para análisis más profundo de la lógica de negocio.

---

### CodeInspector

**Modelo:** MODEL_AGENT_CODE (Qwen 2.5 Coder 32B) | **Especialidad:** Análisis de código cliente

| Técnica | Método |
|---|---|
| **JS Secret Scanning** | Analiza bundles JS buscando API keys, tokens, secrets hardcodeados |
| **Source Map Leaks** | Verifica exposición de archivos `.map` con código fuente original |
| **API Key Exposure** | Detecta credenciales embebidas en JS con patrones regex (AWS, Stripe, etc.) |

Usa el modelo especializado en código (Qwen 2.5 Coder) para análisis semántico de JavaScript ofuscado.

---

### IntegrationScout

**Modelo:** MODEL_AGENT_STD | **Especialidad:** Integraciones y terceros

| Técnica | Método |
|---|---|
| **SSRF** | Inyecta URLs internas (`http://127.0.0.1`, `http://169.254.169.254`) en parámetros de fetch |
| **CORS Misconfiguration** | Prueba orígenes arbitrarios y verifica `Access-Control-Allow-Origin: *` + credenciales |
| **Webhook Injection** | Verifica si endpoints de webhook realizan fetch a URLs controladas por el atacante |
| **Third-party Redirects** | Detecta redirects a dominios externos sin validación |

---

### InfraProber

**Modelo:** MODEL_AGENT_STD | **Especialidad:** Infraestructura y despliegue

| Técnica | Método |
|---|---|
| **Port Scan** | Detecta servicios peligrosos expuestos (Redis :6379, MongoDB :27017, Docker :2375, Kibana :5601, etc.) |
| **Exposed Files** | Verifica acceso a `.env`, `.git/HEAD`, `config.php`, `wp-config.php`, `database.yml`, `phpinfo.php` |
| **Cloud Metadata** | Intenta acceder a `http://169.254.169.254` (AWS), `http://metadata.google.internal` (GCP) |
| **Sensitive Files** | Detecta archivos de configuración con credenciales en respuestas HTTP 200 |

---

## 6. Sistema HITL — Human-in-the-Loop

El sistema HITL usa la API nativa de LangGraph: `interrupt()` para pausar y `Command(resume=response)` para reanudar. Cada tipo de interrupción tiene un nodo propio en el grafo.

### Los 10 Tipos de Interrupción

| Tipo | ID | Obligatorio | Cuándo se Dispara |
|---|---|---|---|
| `SCOPE_REVIEW` | HITL-0 | ✅ Sí | Antes del reconocimiento — valida target y metodología |
| `STRATEGY_REVIEW` | HITL-1a | ✅ Sí | Tras OSINT — aprobación de la estrategia de ataque |
| `LOADOUT_REVIEW` | HITL-1b | ✅ Sí | Antes del swarm — revisión final de loadouts por agente |
| `CREDENTIALS` | HITL-2 | ❌ No | Cuando se necesitan credenciales para testing autenticado |
| `HIGH_SEVERITY` | HITL-3 | ❌ No | Finding con CVSS ≥ 9.0 — requiere aprobación manual |
| `DESTRUCTIVE` | HITL-4 | ❌ No | Acción destructiva (stress test, modificación de cuenta) |
| `AGENT_STALLED` | HITL-5 | ❌ No | Agente alcanza `max_iterations` sin findings |
| `NEW_SURFACE` | HITL-6 | ❌ No | Nueva superficie descubierta durante el ataque |
| `CHAIN_CRITICAL` | HITL-7 | ❌ No | Cadena de ataque con CVSS ≥ 9.5 |
| `PRE_REPORT` | HITL-8 | ✅ Sí | Revisión final de findings validados antes del reporte |

### Flujo de una Interrupción

```
Grafo pausado (interrupt(payload))
        │
        ▼
POST /api/runs/{thread_id}/interrupt/{hitl_type}/respond
        │
        │ Body: { "state_updates": {...}, "response": {...} }
        │
        ▼
interrupt_manager._apply_response(state, response)
        │
        ▼
Command(resume=response) → grafo reanuda desde el mismo nodo
```

### Acciones del Operador por HITL

**SCOPE_REVIEW:** Aprobar scope, editar `scope_rules`, añadir contexto adicional al target.

**STRATEGY_REVIEW:** Aprobar estrategia, editar `attack_strategy` (añadir áreas de amenaza, modificar hipótesis globales).

**LOADOUT_REVIEW:** Aprobar loadouts, editar `test_cases` de agentes específicos, desactivar agentes (`active: false`), modificar `tool_configs`, ajustar `max_iterations`.

**CREDENTIALS:** Inyectar credenciales en `operator_context.credentials` para testing autenticado.

**HIGH_SEVERITY:** Aprobar finding (pasa a `validated_findings`), rechazar finding (va a `false_positives`), solicitar re-verificación con PoC adicional.

**DESTRUCTIVE:** Aprobar la acción, rechazarla, o modificar sus parámetros (e.g., reducir intensidad).

**AGENT_STALLED:** Re-forjar el LoadOut con nuevas hipótesis, terminar el agente, añadir test cases específicos.

**NEW_SURFACE:** Añadir al scope y generar nuevos test cases, o ignorar la superficie.

**CHAIN_CRITICAL:** Confirmar la cadena y escalar su severidad, rechazarla, añadir contexto de negocio.

**PRE_REPORT:** Aprobar findings finales, descartar false positives identificados manualmente, añadir contexto de negocio para el reporte.

---

## 7. Subgrafo de Agente de Equipo

Cada uno de los 6 agentes de equipo compila su propio subgrafo interno de 5 nodos:

```
START
  ↓
[check_active]   → Si loadout.active == False: retorna inmediatamente con skipped=True
  ↓
[orient]         → Lee loadout de BountyMindState, prepara contexto de la misión
  ↓
[execute]        → Ejecuta test_cases iterativamente, genera local_findings
  │
  ├── [collaborate] → (cada 3 iteraciones) Escribe/lee shared_memory inter-agente
  │        ↓
  └────────┘
  ↓
[report]         → Propaga local_findings → raw_findings (operator.add en BountyMindState)
  ↓
END
```

### AgentState (estado interno del subgrafo)

```python
class AgentState(TypedDict):
    loadout:             dict                         # AgentLoadOut del agente
    iteration:           int                         # Iteración actual
    test_idx:            int                         # Índice del test case actual
    local_findings:      list                        # Findings acumulados
    messages:            Annotated[list, operator.add]
    memory_writes:       list
    thread_id:           str
    scope_rules:         dict
    _should_collaborate: bool                        # Trigger para el nodo collaborate
    raw_findings:        Annotated[list, operator.add]  # Propagación a BountyMindState
```

### RawFinding — Estructura de un Finding

```python
class RawFinding(BaseModel):
    id:                  str       # UUID único
    agent_id:            str       # Agente que lo descubrió
    vuln_type:           str       # "XSS", "IDOR", "SSRF", etc.
    title:               str
    description:         str
    severity:            str       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    cvss_estimate:       float
    url:                 str
    method:              str       # HTTP method
    payload:             str
    request:             dict      # Request completo
    response_diff:       dict      # Diferencia relevante en la respuesta
    reproduction_steps:  list[str]
    confidence:          float
    timestamp:           str
```

---

## 8. Modelos LLM y Configuración

### Aliases de Modelos

| Alias | Modelo Fireworks | Uso |
|---|---|---|
| `MODEL_COMMANDER` | `deepseek-r1` | Inicialización y planificación estratégica |
| `MODEL_THINKER` | `deepseek-r1` | Strategy Engine (razonamiento profundo) |
| `MODEL_RESEARCH` | `mixtral-8x22b-instruct` | Research agent, Validator, Reporter |
| `MODEL_RECON` | `llama-v3p1-70b-instruct` | Surface agent, Behavior agent |
| `MODEL_AGENT_STD` | `llama-v3p3-70b-instruct` | WebTester, AuthProber, LogicAnalyst, IntegrationScout, InfraProber |
| `MODEL_AGENT_CODE` | `qwen2p5-coder-32b-instruct` | CodeInspector (análisis de código) |
| `MODEL_SYNTHESIZER` | `deepseek-v3` | Chain Synthesizer, LogicAnalyst |

### Cliente LLM

Todos los modelos se instancian via `langchain_openai.ChatOpenAI` apuntando a la API de Fireworks (compatible con OpenAI):

```python
# core/fireworks.py
@retry(retry=retry_if_exception_type(Exception),
       wait=wait_exponential(multiplier=1, min=2, max=10),
       stop=stop_after_attempt(3), reraise=True)
def get_model(alias: str, temperature: float = 0.1) -> ChatOpenAI:
    return ChatOpenAI(
        model=ModelConfig.get(alias),
        openai_api_key=app_config.FIREWORKS_API_KEY,
        openai_api_base=app_config.FIREWORKS_BASE_URL,
        temperature=temperature,
        max_tokens=4096,
        streaming=True,
    )
```

El decorador `@retry` de `tenacity` reintenta automáticamente hasta 3 veces con backoff exponencial ante errores de red o rate limiting.

---

## 9. API REST

### Runs

```
POST   /api/runs
       Body: { "target_brief": "...", "scope_rules": {...}, "run_config": {...} }
       Response: { "thread_id": "uuid", "phase": "BRIEF", "status": "running" }

GET    /api/runs/{thread_id}
       Response: Estado completo del run (fase, findings, audit_log, etc.)

GET    /api/runs
       Response: Lista de runs (requiere checkpointer persistente)
```

### HITL

```
POST   /api/runs/{thread_id}/interrupt/{hitl_type}/respond
       Body: { "state_updates": {...}, "response": {...} }
       Reanuda el grafo con la decisión del operador

GET    /api/runs/{thread_id}/interrupt/pending
       Response: Lista de interrupciones pendientes de respuesta
```

### Stream

```
GET    /api/runs/{thread_id}/stream
       Content-Type: text/event-stream (SSE)
       Emite eventos en tiempo real del tipo: token, node_update, state_snapshot, run_complete
```

### Health

```
GET    /health
       Response: { "status": "ok", "graph_ready": true }
```

---

## 10. Streaming en Tiempo Real — SSE

El endpoint `/api/runs/{thread_id}/stream` usa **Server-Sent Events** via `graph.astream()` con tres modos simultáneos:

```python
async for part in graph.astream(
    None,
    config={"configurable": {"thread_id": thread_id}},
    stream_mode=["messages", "updates", "values"],
    subgraphs=True,
):
    event = _format_sse_part(part)
    yield f"data: {json.dumps(event)}\n\n"
```

### Tipos de Evento SSE

| Tipo | Cuándo | Contenido |
|---|---|---|
| `token` | Cada chunk del LLM | `namespace`, `content` (texto parcial), `node` |
| `node_update` | Al completar un nodo | `namespace`, `updates` (delta del estado) |
| `state_snapshot` | En checkpoints | `namespace`, `phase`, `state` (snapshot completo) |
| `run_complete` | Al finalizar | `timestamp` |
| `stream_error` | En excepciones | `error` (mensaje) |

El campo `namespace` permite identificar si el evento proviene del grafo principal o de un subgrafo de agente (e.g., `agent_WebTester`).

---

## 11. Herramientas y Técnicas de Ataque

### Registro de Herramientas

Las herramientas se registran con un decorador en `tools/registry.py`:

```python
@ToolRegistry.register("port_scan", "Escanea puertos TCP del target")
async def port_scan(target: str, ports: str = "top-100") -> dict:
    ...
```

Los agentes declaran en su `AgentLoadOut.tools` qué herramientas tienen habilitadas, y el scope checker valida que la URL esté dentro del scope antes de ejecutar cualquier petición.

### Scope Checker

```python
# tools/scope_checker.py
def validate_scope(url: str, scope_rules: dict) -> bool:
    """Valida que la URL esté en scope antes de ejecutar cualquier técnica."""
```

Todos los agentes llaman a `validate_scope` antes de realizar requests. Si la URL está fuera de scope se lanza `ScopeViolationError` y el finding se descarta automáticamente.

### Herramientas de Reconocimiento

| Herramienta | Descripción |
|---|---|
| `httpx_tool` | Requests HTTP async con análisis de headers, cookies, redirects |
| `katana_tool` | Rastreo de URLs con Katana (headless + JS rendering) |
| `naabu_tool` | Escaneo de puertos TCP rápido |
| `subfinder_tool` | Enumeración de subdominios pasiva |
| `gau_tool` | URLs de fuentes públicas (wayback, otx, urlscan) |
| `wappalyzer_tool` | Detección de tecnologías por fingerprinting |
| `js_bundle_tool` | Análisis de bundles JavaScript |
| `vercel_browser` | Scraping con navegador para SPAs |

### Herramientas OSINT

| Herramienta | Fuente |
|---|---|
| `github_search` | GitHub Advisory Database |
| `nvd_api` | NIST National Vulnerability Database |
| `tavily_search` | Tavily AI Search (writeups, hacktivity) |

---

## 12. Persistencia y Checkpointing

LangGraph requiere un checkpointer para soportar `interrupt()`. El sistema selecciona automáticamente el más apropiado:

```
APP_ENV == "production" && POSTGRES_URL definida
    → AsyncPostgresSaver (PostgreSQL)
    → Fallo → fallback a SQLite

APP_ENV == "development" (default)
    → AsyncSqliteSaver (bountymind_dev.db)
    → Fallo → MemorySaver (no persistente, solo para CI/testing)
```

El checkpointer se inicializa en el `lifespan` de FastAPI antes de compilar el grafo:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    checkpointer = await get_checkpointer()
    await build_graph(checkpointer=checkpointer)
    yield
```

Gracias al checkpointing, cada `thread_id` mantiene su estado completo entre peticiones HTTP, lo que permite:
- Reanudar ejecuciones tras reinicios del servidor
- Inspeccionar el estado en cualquier punto del historial
- Revertir a checkpoints anteriores si es necesario

---

## 13. Frontend React

**Stack:** React 18 + TypeScript + Vite + Zustand + TailwindCSS

### Páginas

| Ruta | Componente | Función |
|---|---|---|
| `/` | Dashboard | Vista principal con formulario de nuevo run |
| `/runs/:threadId` | Dashboard | Monitoreo de un run activo |

### Componentes Principales

| Componente | Función |
|---|---|
| `NewRunForm` | Formulario para iniciar un run (target_brief, scope, config) |
| `PhaseTimeline` | Progreso visual de las fases del pipeline |
| `SwarmMonitor` | Estado en tiempo real de los 6 agentes del swarm |
| `InterruptQueue` | Cola de interrupciones HITL pendientes |
| `InterruptCard` | UI de decisión del operador para cada HITL |
| `FindingsPanel` | Findings raw y validados con CVSS y detalles |
| `StrategyViewer` | Visualización de la estrategia de ataque |
| `LoadOutViewer` | Loadouts por agente (test cases, herramientas, hipótesis) |
| `SurfaceMapViewer` | Mapa visual de la superficie de ataque |
| `TargetContextViewer` | CVEs y técnicas probadas del OSINT |
| `EventLog` | Stream de mensajes y audit log en tiempo real |
| `CheckpointBrowser` | Navegación por checkpoints históricos del run |

### Estado Global (Zustand)

`stores/runStore.ts` mantiene sincronizado el estado de la UI con el backend vía SSE:

```typescript
interface RunStore {
    threadId: string | null
    phase: string
    findings: RawFinding[]
    validatedFindings: ValidatedFinding[]
    pendingInterrupts: HITLInterrupt[]
    agentStatus: Record<string, AgentStatus>
    messages: Message[]
    // ...
}
```

### Hooks

- **`useSSEStream`** — Conecta al endpoint SSE y actualiza el store en tiempo real
- **`useHITL`** — Gestiona la respuesta a interrupciones del operador

---

## 14. Estructura de Archivos

```
bountymind/
├── backend/
│   ├── pyproject.toml
│   ├── requirements.txt
│   └── bountymind/
│       ├── api/
│       │   ├── main.py                   FastAPI app + lifespan
│       │   ├── websocket.py
│       │   └── routers/
│       │       ├── runs.py               POST/GET /api/runs
│       │       ├── hitl.py               POST /api/runs/{id}/interrupt/*/respond
│       │       ├── state.py              GET /api/runs/{id}/state
│       │       └── stream.py             GET /api/runs/{id}/stream (SSE)
│       ├── core/
│       │   ├── config.py                 AppConfig + ModelConfig
│       │   ├── state.py                  BountyMindState TypedDict
│       │   ├── models.py                 Pydantic: AgentLoadOut, RawFinding,
│       │   │                             ValidatedFinding, AttackChain,
│       │   │                             RunRequest, RunResponse, ScopeRules
│       │   └── fireworks.py              get_model() con retry tenacity
│       ├── graph/
│       │   ├── builder.py                build_graph() — compila el StateGraph
│       │   ├── commander.py              Nodo de inicialización
│       │   ├── checkpointer.py           get_checkpointer() — SQLite/Postgres
│       │   └── edges.py                  Funciones de routing condicional
│       ├── hitl/
│       │   ├── interrupt_types.py        HITLType enum (10 tipos)
│       │   ├── interrupt_manager.py      create_hitl_node() factory
│       │   └── handlers.py               Lógica de aplicación de respuestas
│       ├── agents/
│       │   ├── team/
│       │   │   ├── base_agent.py         BaseTeamAgent + AgentState + subgrafo
│       │   │   ├── web_tester.py         XSS, CSRF, Open Redirect, HPP
│       │   │   ├── auth_prober.py        Timing, tokens, OAuth, sesiones
│       │   │   ├── logic_analyst.py      IDOR, mass assignment, privilege escalation
│       │   │   ├── code_inspector.py     JS secrets, source maps, API keys
│       │   │   ├── integration_scout.py  SSRF, CORS, webhooks
│       │   │   └── infra_prober.py       Ports, exposed files, cloud metadata
│       │   ├── recon/
│       │   │   ├── surface_agent.py      Inventario de superficie de ataque
│       │   │   └── behavior_agent.py     Análisis comportamental
│       │   ├── intelligence/
│       │   │   ├── research_agent.py     OSINT: CVE, advisories, hacktivity
│       │   │   └── sources.py            Clientes de fuentes OSINT
│       │   ├── strategy/
│       │   │   ├── strategy_engine.py    Generación de loadouts con DeepSeek R1
│       │   │   └── loadout_validator.py  Validación de loadouts generados
│       │   ├── synthesis/
│       │   │   └── chain_synthesizer.py  Detección de cadenas de ataque
│       │   ├── validator/
│       │   │   ├── validator_agent.py    Validación y scoring de findings
│       │   │   └── poc_runner.py         Ejecución de PoC para verificación
│       │   └── reporter/
│       │       ├── report_agent.py       Generación de reporte profesional
│       │       └── templates.py          Plantillas Markdown del reporte
│       ├── tools/
│       │   ├── registry.py               ToolRegistry (decorador @register)
│       │   ├── scope_checker.py          validate_scope() + ScopeViolationError
│       │   ├── osint/                    github_search, nvd_api, tavily_search
│       │   ├── recon/                    httpx, katana, naabu, subfinder, gau, wappalyzer
│       │   ├── web/                      js_bundle_tool, vercel_browser
│       │   └── attack/                   Herramientas específicas de ataque
│       └── memory/
│           ├── shared.py                 Memoria compartida inter-agente
│           └── long_term.py              Memoria persistente entre runs
└── frontend/
    ├── package.json
    ├── vite.config.ts
    └── src/
        ├── App.tsx
        ├── api/client.ts                 Cliente tipado de la API
        ├── hooks/
        │   ├── useHITL.ts
        │   └── useSSEStream.ts
        ├── stores/runStore.ts            Zustand global store
        ├── pages/Dashboard.tsx
        └── components/                   15+ componentes de UI
```

---

## 15. Instalación y Puesta en Marcha

### Requisitos

- Python ≥ 3.11
- Node.js ≥ 18
- (Opcional para recon extendido) `naabu`, `subfinder`, `katana`, `gau` en PATH
- (Opcional para recon web completo) Playwright browsers: `playwright install chromium`

### Backend

```bash
cd bountymind/backend

# Instalar dependencias
pip install -e .
# o
pip install -r requirements.txt

# Configurar variables de entorno
cp .env.example .env
# Editar .env con FIREWORKS_API_KEY y demás variables

# Iniciar servidor
uvicorn bountymind.api.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd bountymind/frontend

npm install
npm run dev
# → http://localhost:5173
```

### Docker (recomendado para producción)

```bash
# Backend con PostgreSQL
docker-compose up -d

# Variables de entorno requeridas en docker-compose.yml:
# FIREWORKS_API_KEY, POSTGRES_URL, APP_ENV=production
```

---

## 16. Variables de Entorno

```env
# ── REQUERIDAS ─────────────────────────────────────────────────────────────
FIREWORKS_API_KEY=fw_xxxxxxxxxxxxxxxxxxxx    # API key de Fireworks AI

# ── LLM (opcional — sobreescribe defaults) ──────────────────────────────────
FIREWORKS_BASE_URL=https://api.fireworks.ai/inference/v1

# ── BASE DE DATOS ────────────────────────────────────────────────────────────
APP_ENV=development                          # "development" o "production"
POSTGRES_URL=postgresql://user:pass@host/db # Solo necesario en producción

# ── OBSERVABILIDAD ───────────────────────────────────────────────────────────
LANGSMITH_API_KEY=ls__xxxxxxxxxxxxxxxxxxxx  # LangSmith tracing (opcional)
LANGSMITH_PROJECT=bountymind-dev
LANGCHAIN_TRACING_V2=true

# ── HERRAMIENTAS EXTERNAS ────────────────────────────────────────────────────
TAVILY_API_KEY=tvly-xxxxxxxxxx              # Búsqueda web en research agent
GITHUB_TOKEN=ghp_xxxxxxxxxx                 # GitHub Advisory API (recomendado)
SHODAN_API_KEY=xxxxxxxxxx                   # Shodan (opcional)

# ── CONFIGURACIÓN DE EJECUCIÓN ───────────────────────────────────────────────
CONFIDENCE_THRESHOLD=0.85                   # Umbral para promover findings
MAX_AGENT_ITERATIONS=25                     # Máximo de iteraciones por agente
```

---

## 17. Generación del Reporte Final

El reporte final se almacena en `state.operator_context.final_report_markdown` y es accesible vía:

```
GET /api/runs/{thread_id}
→ response.operator_context.final_report_markdown
```

### Ejemplo de Estructura del Reporte

```markdown
# Bug Bounty Security Report

**Target:** https://example.com
**Generated:** 2026-03-28T15:42:00Z
**Total Validated Findings:** 7
**Critical / High:** 3
**Attack Chains Identified:** 2

---

## Executive Summary

La evaluación de seguridad de example.com identificó 7 vulnerabilidades validadas,
incluyendo una inyección SQL crítica en el endpoint de búsqueda y una cadena de
ataque que combina IDOR con escalada de privilegios permitiendo acceso completo
a cuentas de administrador. La superficie de ataque expone tecnologías sin
parchear con CVEs conocidos de severidad alta.

---

## Findings

### CRITICAL — SQL Injection en /api/search

**CVSS:** 9.8 | **URL:** https://example.com/api/search | **Type:** SQL Injection

**Description:** El parámetro `q` de la API de búsqueda es vulnerable a inyección
SQL clásica. Un atacante puede extraer el esquema completo de la base de datos
y acceder a datos de todos los usuarios mediante una consulta UNION-based.

**Reproduction Steps:**
1. Enviar GET /api/search?q=test'+UNION+SELECT+1,username,password+FROM+users--
2. Observar datos de usuarios en la respuesta JSON

**Impact:** Permite a un atacante no autenticado exfiltrar la base de datos completa
incluyendo credenciales, datos personales y tokens de sesión de todos los usuarios.

**Remediation:** Utilizar prepared statements parametrizados en todas las consultas
SQL. Implementar un WAF con reglas de detección de SQLi. Revisar y sanitizar
todos los inputs que se incorporen a consultas de base de datos.

---

## Attack Chains

### IDOR + Privilege Escalation → Account Takeover Completo

**Composed CVSS:** 10.0 | **Confidence:** 92%

Un atacante autenticado como usuario normal puede primero explotar el IDOR en
`/api/users/{id}/profile` para leer el token de sesión de un administrador,
luego usar ese token para acceder al panel de administración...

**Combined Impact:** La cadena permite a cualquier usuario registrado escalar
a administrador completo del sistema en menos de 3 peticiones HTTP.
```

---

## Notas de Seguridad

- **BountyMind es una herramienta para testing autorizado.** Úsala únicamente en targets para los que tengas permiso explícito.
- El `scope_checker` bloquea automáticamente requests a URLs fuera del scope definido.
- Las credenciales nunca se incluyen en los logs de audit ni en los payloads HITL enviados al LLM.
- Las acciones destructivas (HITL-4) requieren aprobación explícita del operador antes de ejecutarse.
- El `audit_log` registra todas las acciones del sistema con timestamp UTC para trazabilidad completa.
