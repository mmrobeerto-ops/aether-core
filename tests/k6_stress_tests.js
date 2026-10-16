import http from 'k6/http';
import { check, sleep } from 'k6';

// =====================================================================
//      TZANiX-Æther-Core: Suite de Estrés y Carga con k6
// =====================================================================
//
// Esta suite automatiza las pruebas distribuidas y locales para el motor.
// Permite evaluar la latencia en internet, el veto de paquetes corruptos
// y la resiliencia en memoria.
//
// USO LOCAL:
//   k6 run tests/k6_stress_tests.js
//
// USO PERSONALIZADO (ej. ejecutar Escenario 3 durante 10 minutos):
//   k6 run -e SCENARIO=3 -e DURATION=10m tests/k6_stress_tests.js
//

// URL base del servidor TZANiX (se puede sobreescribir desde variables de entorno)
const BASE_URL = __ENV.TARGET_URL || 'http://localhost:8000';
const SCENARIO_ENV = __ENV.SCENARIO || 'all'; // 'all', '1', '2', '3'
const DURATION_ENV = __ENV.DURATION || '30s'; // duración de cada fase

// Configuración de los escenarios de carga de k6
let runOptions = {
  thresholds: {
    http_req_failed: ['rate<0.01'], // menos del 1% de errores del sistema
  },
};

if (SCENARIO_ENV === 'all') {
  // Ejecuta una ronda secuencial de humo para verificar todos los escenarios
  runOptions.scenarios = {
    escenario_1_latencia: {
      executor: 'constant-arrival-rate',
      rate: 1000, // 1,000 rps para simulación local
      timeUnit: '1s',
      duration: DURATION_ENV,
      preAllocatedVUs: 50,
      maxVUs: 150,
      exec: 'escenario1',
    },
    escenario_2_veto: {
      executor: 'constant-arrival-rate',
      rate: 3000,
      timeUnit: '1s',
      duration: DURATION_ENV,
      preAllocatedVUs: 100,
      maxVUs: 300,
      startTime: '35s',
      exec: 'escenario2',
    },
    escenario_3_resiliencia: {
      executor: 'ramping-arrival-rate',
      startRate: 50,
      timeUnit: '1s',
      stages: [
        { target: 1000, duration: '20s' },
        { target: 1000, duration: '20s' },
      ],
      preAllocatedVUs: 50,
      maxVUs: 200,
      startTime: '70s',
      exec: 'escenario3',
    },
  };
} else if (SCENARIO_ENV === '1') {
  // Escenario 1 Puro: Latencia de Red Real (2,000 rps sostenidos)
  runOptions.scenarios = {
    escenario_1: {
      executor: 'constant-arrival-rate',
      rate: 2000,
      timeUnit: '1s',
      duration: DURATION_ENV,
      preAllocatedVUs: 100,
      maxVUs: 500,
      exec: 'escenario1',
    },
  };
} else if (SCENARIO_ENV === '2') {
  // Escenario 2 Puro: Inyección masiva para veto geométrico (8,000 rps sostenidos)
  runOptions.scenarios = {
    escenario_2: {
      executor: 'constant-arrival-rate',
      rate: 8000,
      timeUnit: '1s',
      duration: DURATION_ENV,
      preAllocatedVUs: 200,
      maxVUs: 1000,
      exec: 'escenario2',
    },
  };
} else if (SCENARIO_ENV === '3') {
  // Escenario 3 Puro: Prueba de Resiliencia del SO (10 minutos sostenidos de ataque temporal)
  runOptions.scenarios = {
    escenario_3: {
      executor: 'constant-arrival-rate',
      rate: 5000, // Carga intensa de cálculo
      timeUnit: '1s',
      duration: DURATION_ENV,
      preAllocatedVUs: 150,
      maxVUs: 800,
      exec: 'escenario3',
    },
  };
}

export const options = runOptions;

// --- FUNCIONES DE EJECUCIÓN ---

// Escenario 1: Tráfico Legítimo Masivo (Canales coherentes)
export function escenario1() {
  const url = `${BASE_URL}/api/v1/query`;
  const payload = JSON.stringify({
    channel_alpha: [800, 800, 800, 800, 800, 800, 800, 800],
    channel_beta: [600, 600, 600, 600, 600, 600, 600, 600],
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  const res = http.post(url, payload, params);

  check(res, {
    'Status 200 OK (Allowed)': (r) => r.status === 200,
    'Contenido Allowed': (r) => r.body.includes('Allowed'),
  });
}

// Escenario 2: Mitigación de Pérdida de Paquetes (Veto Geométrico/NaN)
export function escenario2() {
  const url = `${BASE_URL}/api/v1/query`;
  
  // Enviamos una firma NaN que debe ser bloqueada inmediatamente (HTTP 403)
  const payload = JSON.stringify({
    tensor: ["NaN", 1.0, "inf"]
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  const res = http.post(url, payload, params);

  check(res, {
    'Status 403 Forbidden (Blocked)': (r) => r.status === 403,
    'Veto Activo': (r) => r.body.includes('Blocked by TZANiX Q-Guard'),
  });
}

// Escenario 3: La Prueba de Resiliencia del Sistema Operativo
export function escenario3() {
  // Solicitamos cálculos pesados al auditor temporal
  // Esto simula la CPU en estrés. El servidor debe limitar o permitir
  // sin fugar memoria ni colapsar.
  const url = `${BASE_URL}/api/v1/heavy-calc?stress=true`;

  const res = http.get(url);

  check(res, {
    'Status 200 (OK) o 403 (Veto Temporal)': (r) => r.status === 200 || r.status === 403,
  });
}
