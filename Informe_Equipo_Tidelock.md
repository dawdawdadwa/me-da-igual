# Informe de Trabajo del Equipo

| **Nombre del Proyecto** | TDD-Practica |
| ----------------------- | ------------ |
| **Nombre del Equipo**   | Tidelock     |
| **Fecha de entrega**    | 15/05/2025   |

## 1. Análisis del Trabajo
**Interpretación del proyecto:**
Desarrollamos un gestor de credenciales seguro siguiendo la metodología S-TDD. Implementamos funciones básicas (añadir, verificar, eliminar y listar credenciales) asegurando desde el principio requisitos de seguridad como autenticación, cifrado, validación de entradas y políticas de contraseñas robustas.

**Aportaciones originales:**
- Aplicamos S-TDD estrictamente: primero los tests, luego el código
- Usamos Design-by-Contract con `icontract` para reforzar pre/postcondiciones
- Incorporamos fuzzing con Hypothesis para probar la robustez de la política de contraseñas
- Añadimos tests de seguridad para escenarios como acceso concurrente y manipulación de datos
- Nos centramos en protección contra inyección y almacenamiento seguro con bcrypt
- Implementamos logging para auditoría sin exponer datos sensibles
- Aplicamos principios SOLID para mejorar la arquitectura y seguridad del código
- Implementamos principios de seguridad como Fail-Safe Defaults y Mínimo Privilegio

## 2. Seguimiento y Herramientas de Gestión
**Herramientas de planificación y coordinación:**
Planificamos con reuniones de equipo, nos comunicamos por Discord y WhatsApp, y usamos GitHub para control de versiones y colaboración.

**Frecuencia de revisión:**
Revisábamos el progreso diariamente por chat y semanalmente en reuniones estructuradas. Los commits y pull requests nos permitieron seguir el desarrollo continuamente.

## 3. Contribuciones Individuales

### Ignacio Ferrer
| Tarea           | Creación de tests funcionales y de seguridad |
| --------------- | -------------------------------------------- |
| Colaboradores   | Ninguno                                      |
| Tiempo empleado | 30 minutos                                   |
| Entregables     | tests/gestor_credenciales/                   |
| Notas           | Creó todos los tests del proyecto            |

### Gonzalo Ramos
| Tarea           | Implementación del código para pasar los tests |
| --------------- | ---------------------------------------------- |
| Colaboradores   | Cayetano López                                 |
| Tiempo empleado | 1 hora                                         |
| Entregables     | src/gestor_credenciales/gestor_credenciales.py |
| Notas           | Desarrolló la clase GestorCredenciales         |

### Jorge Varea
| Tarea           | Implementación de contratos con icontract      |
| --------------- | ---------------------------------------------- |
| Colaboradores   | Ninguno                                        |
| Tiempo empleado | 45 minutos                                     |
| Entregables     | src/gestor_credenciales/gestor_credenciales.py |
| Notas           | Definió pre y postcondiciones con icontract    |

### Cayetano López
| Tarea           | Revisión y refactorización del código                  |
| --------------- | ------------------------------------------------------ |
| Colaboradores   | Ninguno                                                |
| Tiempo empleado | 45 minutos                                             |
| Entregables     | src/gestor_credenciales/gestor_credenciales.py, tests/ |
| Notas           | Revisó el código para cumplir todos los requisitos     |

### Equipo completo
| Tarea           | Aplicación de principios SOLID                 |
| --------------- | ---------------------------------------------- |
| Colaboradores   | Todos                                          |
| Tiempo empleado | 2 horas                                        |
| Entregables     | src/gestor_credenciales/gestor_credenciales.py |
| Notas           | Refactorización para aplicar SRP, OCP y DIP    |

### Equipo completo
| Tarea           | Aplicación de principios de seguridad          |
| --------------- | ---------------------------------------------- |
| Colaboradores   | Todos                                          |
| Tiempo empleado | 3 horas                                        |
| Entregables     | src/gestor_credenciales/gestor_credenciales.py |
| Notas           | Implementación de Fail-Safe, Mediación y otros |

## 4. Evaluación del Trabajo en Equipo
**¿Qué ha funcionado bien y qué se puede mejorar?**

El equipo funcionó bien gracias a una clara distribución de tareas. La comunicación por Discord y WhatsApp resolvió dudas rápidamente, y GitHub facilitó la integración del trabajo.

Lo que funcionó:
- La especialización de cada miembro permitió avanzar en paralelo
- Las revisiones cruzadas detectaron problemas temprano
- Cumplimos con los plazos establecidos

Podemos mejorar:
- La documentación del código desde el principio
- Implementar un sistema más formal de revisión de código
- Llegar a consensos más rápidos sobre decisiones técnicas

## 5. Evaluación de la experiencia con S-TDD
**¿Qué os ha parecido útil y qué se puede mejorar?**

S-TDD fue clave para desarrollar software seguro desde su concepción. Al escribir primero los tests de seguridad, consideramos estos aspectos antes de escribir código, resultando en un diseño inherentemente más seguro.

Aspectos positivos:
- La seguridad se integró desde el inicio, no como añadido posterior
- El fuzzing con Hypothesis descubrió casos extremos difíciles de identificar
- Los contratos con icontract añadieron verificación en tiempo de ejecución
- Logramos casi 100% de cobertura de pruebas

Consideraciones:
- Requiere más trabajo inicial, pero compensa con menos vulnerabilidades
- Tiene una curva de aprendizaje pronunciada para quienes no conocen seguridad
- Exige un cambio cultural en equipos acostumbrados a métodos tradicionales

En conclusión, S-TDD mejoró significativamente la seguridad de nuestro gestor. Aunque requiere más tiempo inicial, es ideal para proyectos donde la seguridad es crítica.

## 6. Aplicación de Principios SOLID

En la refactorización del código, aplicamos los siguientes principios SOLID:

### Single Responsibility Principle (SRP)
Dividimos la funcionalidad en clases con responsabilidades únicas:
- `AutenticadorBcrypt`: Gestiona la autenticación con la clave maestra
- `PoliticaPasswordEstandar`: Verifica que las contraseñas cumplan con las políticas de seguridad
- `AlmacenamientoEnMemoria`: Maneja el almacenamiento de credenciales
- `CifradorBcrypt`: Se encarga del cifrado y verificación de contraseñas
- `ValidadorEntrada`: Valida la entrada del usuario

### Open-Closed Principle (OCP)
El diseño permite extender la funcionalidad sin modificar el código existente:
- Podemos añadir nuevas políticas de contraseñas (ej. `PoliticaPasswordAvanzada`)
- Podemos implementar nuevos métodos de cifrado (ej. `CifradorAES`)
- Podemos crear nuevos sistemas de almacenamiento (ej. `AlmacenamientoEnArchivo`, `AlmacenamientoEnBD`)

### Dependency Inversion Principle (DIP)
Implementamos interfaces para eliminar dependencias directas:
- `IAutenticador`: Abstracción para autenticación
- `IPoliticaPassword`: Abstracción para políticas de contraseñas
- `IAlmacenamiento`: Abstracción para almacenamiento
- `ICifrador`: Abstracción para cifrado

La clase `GestorCredenciales` depende de estas abstracciones, no de implementaciones concretas, lo que permite:
- Cambiar fácilmente entre diferentes implementaciones
- Facilitar pruebas unitarias mediante mocks
- Mejorar la seguridad al poder cambiar algoritmos de cifrado sin modificar la lógica principal

Esta refactorización ha mejorado significativamente la mantenibilidad, extensibilidad y seguridad del código, permitiendo adaptarse a nuevos requisitos o cambios en las políticas de seguridad sin modificar el código existente.

## 7. Aplicación de Principios de Seguridad

Además de los principios SOLID, aplicamos varios principios fundamentales de seguridad:

### Economía de Mecanismos
Implementamos reglas de seguridad claras y simples:
- Política de contraseñas con criterios concretos y verificables
- Validación de entradas con expresiones regulares precisas
- Estructura de almacenamiento simple pero efectiva

### Fail-Safe Defaults (A prueba de fallos por defecto)
Diseñamos el sistema para que los valores por defecto sean los más seguros:
- Inicialización segura de componentes (ej. intentos fallidos a 0)
- Verificación de patrones inseguros en contraseñas
- Devolución de `None` cuando no se encuentra una credencial
- Bloqueo automático tras múltiples intentos fallidos de autenticación

### Mediación Completa
Implementamos verificaciones exhaustivas en cada punto de acceso:
- Validación estricta de entradas para prevenir inyecciones
- Verificación de autenticación en cada operación
- Comprobación de permisos antes de cada acción sensible
- Validación de formato para servicios y usuarios

### Mínimo Privilegio
Aplicamos un sistema de niveles de privilegio para operaciones:
- Nivel 1 (bajo): solo operaciones de lectura como listar servicios
- Nivel 2 (medio): operaciones como verificar y añadir credenciales
- Nivel 3 (alto): operaciones críticas como eliminar credenciales
- Por defecto, solo se otorgan los privilegios necesarios para cada operación

### Registro de Compromiso
Implementamos un sistema completo de auditoría:
- Registro de todos los eventos de seguridad (éxitos y fallos)
- Sanitización de datos sensibles antes de registrarlos
- Identificador único de sesión para correlacionar eventos
- Almacenamiento de logs en archivos con timestamp para evitar sobrescrituras
- Registro estructurado en formato JSON para facilitar análisis

Estos principios de seguridad, combinados con la arquitectura SOLID, han resultado en un sistema robusto que:
- Resiste ataques de fuerza bruta mediante bloqueo temporal
- Protege contra inyecciones mediante validación estricta
- Asegura que solo usuarios autorizados puedan realizar operaciones sensibles
- Mantiene un registro detallado para análisis forense en caso de incidentes
- Establece valores por defecto seguros para minimizar riesgos

## 8. Aplicación de Patrones de Diseño y Seguridad

### Strategy Pattern
El patrón Strategy se ha aplicado de forma explícita en la clase `GestorCredenciales`. Esta clase ahora se configura en su constructor con implementaciones concretas de las siguientes interfaces (estrategias):
- `IAutenticador`: Define la estrategia de autenticación (ej. `AutenticadorBcrypt`).
- `IPoliticaPassword`: Define la estrategia para validar la fortaleza de las contraseñas (ej. `PoliticaPasswordEstandar`).
- `IAlmacenamiento`: Define la estrategia de almacenamiento de credenciales (ej. `AlmacenamientoEnMemoria`).
- `ICifrador`: Define la estrategia de cifrado y verificación de contraseñas (ej. `CifradorBcrypt`).
- `IRegistroAuditoria`: Define la estrategia para el registro de eventos (ej. `RegistroAuditoria`).
- `GestorPermisos`: Aunque es una clase concreta, actúa como una estrategia para la gestión de permisos.

**Beneficios:**
- **Flexibilidad y Extensibilidad:** Permite cambiar o añadir nuevos algoritmos o mecanismos (ej. un nuevo tipo de almacenamiento, otra política de contraseñas) sin modificar la clase `GestorCredenciales`. Simplemente se crea una nueva clase que implemente la interfaz de la estrategia correspondiente y se inyecta en el `GestorCredenciales`.
- **Separación de Intereses:** Cada estrategia se enfoca en una tarea específica, lo que mejora la cohesión y reduce el acoplamiento.
- **Configurabilidad:** La elección de las estrategias se realiza en el momento de la instanciación del `GestorCredenciales`, lo que permite configurar su comportamiento de forma externa.
- **Testabilidad:** Facilita las pruebas unitarias, ya que se pueden inyectar _mocks_ o _stubs_ de las estrategias para aislar el comportamiento de `GestorCredenciales`.

Este enfoque mejora la mantenibilidad y adaptabilidad del sistema, permitiendo que evolucione fácilmente para incorporar nuevas funcionalidades o requisitos de seguridad relacionados con estas áreas estratégicas.