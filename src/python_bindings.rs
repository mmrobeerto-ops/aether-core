#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use crate::{AetherSignalEngine, DenseSignalSnapshot, SIGNAL_CHANNELS};

/// Exposición de la estructura a Python
#[cfg(feature = "python")]
#[pyclass]
#[derive(Clone, Debug)]
pub struct PyDenseSignalSnapshot {
    pub channel_alpha: [u32; SIGNAL_CHANNELS],
    pub channel_beta: [u32; SIGNAL_CHANNELS],
}

#[cfg(feature = "python")]
#[pymethods]
impl PyDenseSignalSnapshot {
    #[new]
    pub fn new(alpha: [u32; 8], beta: [u32; 8]) -> Self {
        PyDenseSignalSnapshot {
            channel_alpha: alpha,
            channel_beta: beta,
        }
    }
}

/// Función que ejecuta una carga pesada liberando el GIL de Python
#[cfg(feature = "python")]
#[pyfunction]
pub fn compute_signal_entropy_stress(py: Python<'_>, snapshot: &PyDenseSignalSnapshot, iterations: u64) -> PyResult<f64> {
    let native_snapshot = DenseSignalSnapshot {
        channel_alpha: snapshot.channel_alpha,
        channel_beta: snapshot.channel_beta,
    };
    
    // Liberamos el GIL para permitir que Python corra a 60 FPS
    // mientras Rust satura la CPU calculando entropía masiva en el fondo.
    let final_entropy = py.allow_threads(|| {
        let mut e = 0.0;
        let mut temp_snapshot = native_snapshot.clone();
        for i in 0..iterations {
            // Mutamos para evitar optimización extrema del compilador
            temp_snapshot.channel_alpha[0] = temp_snapshot.channel_alpha[0].wrapping_add(i as u32);
            e += AetherSignalEngine::compute_signal_entropy(&temp_snapshot);
        }
        e / (iterations as f64)
    });

    Ok(final_entropy)
}

/// Declaración del módulo raíz de Python (tzanix_aether_core)
#[cfg(feature = "python")]
#[pymodule]
fn tzanix_aether_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyDenseSignalSnapshot>()?;
    m.add_function(wrap_pyfunction!(compute_signal_entropy_stress, m)?)?;
    Ok(())
}
