// TZANiX Deep Tech - Lucy Core Module
// "El tiempo es la única unidad de medida verdadera." - Lucy (2014)

#[cfg(feature = "std")]
use std::time::Instant;

pub struct LucyTimeAuditor {
    pub umbral_nanosegundos: u128,
}

impl LucyTimeAuditor {
    pub fn new(limite_ns: u128) -> Self {
        LucyTimeAuditor { umbral_nanosegundos: limite_ns }
    }

    /// Evalúa la "existencia" y legitimidad de la consulta basándose puramente en el tiempo
    #[cfg(feature = "std")]
    pub fn auditar_potencial_tensor<F>(&self, mut f_vector: F) -> Result<u128, &'static str>
    where
        F: FnMut(),
    {
        let tiempo_inicial = Instant::now();

        // Se ejecuta la ecuación matemática o la inferencia del vector entrante
        f_vector();

        // Calculamos el delta de tiempo puro (La prueba de existencia de la materia)
        let duracion = tiempo_inicial.elapsed().as_nanos();

        // Ecuación de Relatividad de TZANiX: Si la latencia se deforma (tiende a infinito),
        // significa que el ataque está intentando "congelar" la CPU (Denegación de Servicio).
        if duracion > self.umbral_nanosegundos {
            // El sistema alcanza su "100%" y desvía la carga al vacío
            return Err("Singularidad Temporal Detectada: Tráfico bloqueado por Q-Balam.");
        }

        Ok(duracion)
    }

    /// Evalúa la legitimidad basándose en ciclos de reloj de CPU (TSC) para entornos no_std
    #[cfg(all(not(feature = "std"), target_arch = "x86_64"))]
    pub fn auditar_potencial_tensor_cycles<F>(&self, mut f_vector: F) -> Result<u64, &'static str>
    where
        F: FnMut(),
    {
        let start_cycles = unsafe { core::arch::x86_64::_rdtsc() };

        f_vector();

        let elapsed_cycles = unsafe { core::arch::x86_64::_rdtsc() } - start_cycles;

        if elapsed_cycles as u128 > self.umbral_nanosegundos {
            return Err("Singularidad Temporal Detectada: Tráfico bloqueado por Q-Balam.");
        }

        Ok(elapsed_cycles)
    }
}
