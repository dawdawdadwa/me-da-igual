import unittest
from src.gestor_credenciales.gestor_credenciales import GestorCredenciales, ErrorPoliticaPassword, ErrorAutenticacion, ErrorServicioNoEncontrado, ErrorCredencialExistente
from hypothesis import given, settings
from hypothesis.strategies import text


class TestSeguridadGestorCredenciales(unittest.TestCase):
    def setUp(self):
        self.master_password = "ClaveMaestraSegura123!"
        self.gestor = GestorCredenciales(self.master_password)
        self.servicio = "GitHub"
        self.usuario = "user1"
        self.password = "PasswordSegura123!"
        self.fuzz_iteration_count = 0  # Counter for unique service names in fuzz test

    # Tests de seguridad

    # Política de passwords:
    #   Mínimo 8 caracteres
    #   Al menos una letra mayúscula
    #   Al menos una letra minúscula
    #   Al menos un número
    #   Al menos un símbolo especial(!@  # $%^&* etc.)

    def test_password_no_almacenado_en_plano(self):
        self.gestor.añadir_credencial(self.master_password, self.servicio, self.usuario, self.password)
        # Verificar que el almacenamiento no contiene el password en plano
        self.assertNotEqual(self.gestor._credenciales[self.servicio][self.usuario], self.password)
        # El valor almacenado debe ser cifrado/hasheado (no igual al original)
        self.assertIsInstance(self.gestor._credenciales[self.servicio][self.usuario], str)

    # Este es un test parametrizado usando subTests
    def test_deteccion_inyeccion_servicio(self):
        casos_inyeccion = ["serv;icio", "servicio|mal", "servicio&", "servicio'--"]
        for servicio in casos_inyeccion:
            with self.subTest(servicio=servicio):
                with self.assertRaises(ValueError):
                    self.gestor.añadir_credencial(
                        self.master_password,
                        servicio,
                        self.usuario,
                        self.password
                    )

    # Test con Fuzzing (usa Hypothesis)
    @settings(deadline=4000)
    @given(text(min_size=1, max_size=20))  # Genera contraseñas de hasta 20 caracteres
    def test_fuzz_politica_passwords_con_passwords_debiles(self, contrasena_generada):
        """Prueba diferentes passwords que no cumplen la política
        Args:
            contrasena_generada (str): La contraseña generada por Hypothesis

        Returns:
            Nada. Es un test
        """
        # Usar un nombre de servicio único para cada iteración para evitar ErrorCredencialExistente
        self.fuzz_iteration_count += 1
        servicio_unico = f"{self.servicio}_fuzz_{self.fuzz_iteration_count}"

        # Re-initialize the gestor for each fuzz call to ensure a clean state.
        # This is a robust way to prevent state leakage between Hypothesis examples.
        current_gestor = GestorCredenciales(self.master_password)

        try:
            current_gestor.añadir_credencial(self.master_password, servicio_unico, self.usuario, contrasena_generada)
        except ErrorPoliticaPassword:
            pass  # ✅ Comportamiento esperado
        except ErrorCredencialExistente:
            self.fail(
                f"ErrorCredencialExistente inesperado con servicio único: {servicio_unico} y contraseña: {contrasena_generada}")
        except ValueError as e:
            # This can happen if contrasena_generada leads to an invalid char in servicio_unico, though less likely now.
            # Or if other ValueError conditions in añadir_credencial are met by fuzz data (e.g. empty user, though self.user is fixed here)
            self.fail(f"ValueError inesperado: {e} con servicio: {servicio_unico}, contraseña: {contrasena_generada}")
        except Exception as e:
            self.fail(f"Se lanzó una excepción inesperada: {e} con contraseña: {contrasena_generada}")
        else:
            # Si la contraseña fue aceptada, debería cumplir con las condiciones
            self.assertTrue(current_gestor.es_password_segura(contrasena_generada),
                            f"Se aceptó una contraseña débil: {contrasena_generada}")

    def test_politica_passwords_con_password_robusta(self):
        password = "PasswordRobusta123!"
        try:
            self.gestor.añadir_credencial(self.master_password, self.servicio, self.usuario, password)
        except ErrorPoliticaPassword:
            self.fail("Se rechazó una contraseña robusta")

    def test_acceso_con_clave_maestra_erronea(self):
        self.gestor.añadir_credencial(self.master_password, self.servicio, self.usuario, self.password)
        with self.assertRaises(ErrorAutenticacion):
            # Try to verify with correct password but wrong master key
            self.gestor.verificar_password("claveIncorrecta", self.servicio, self.usuario, self.password)

    # --- Nuevos tests de seguridad ---
    def test_no_se_puede_listar_servicios_sin_autenticacion(self):
        with self.assertRaises(ErrorAutenticacion):
            self.gestor.listar_servicios("claveIncorrecta")

    def test_no_se_puede_eliminar_credencial_sin_autenticacion(self):
        self.gestor.añadir_credencial(self.master_password, self.servicio, self.usuario, self.password)
        with self.assertRaises(ErrorAutenticacion):
            self.gestor.eliminar_credencial("claveIncorrecta", self.servicio, self.usuario)

    def test_no_se_puede_añadir_credencial_con_usuario_vacio(self):
        with self.assertRaises(ValueError):
            self.gestor.añadir_credencial(self.master_password, self.servicio, "", self.password)

    def test_no_se_puede_añadir_credencial_con_servicio_vacio(self):
        with self.assertRaises(ValueError):
            self.gestor.añadir_credencial(self.master_password, "", self.usuario, self.password)

    def test_no_se_puede_añadir_credencial_con_password_vacio(self):
        with self.assertRaises(ErrorPoliticaPassword):
            self.gestor.añadir_credencial(self.master_password, self.servicio, self.usuario, "")

    def test_no_se_puede_almacenar_duplicados(self):
        self.gestor.añadir_credencial(self.master_password, self.servicio, self.usuario, self.password)
        with self.assertRaises(ErrorCredencialExistente):
            self.gestor.añadir_credencial(self.master_password, self.servicio, self.usuario, self.password)

    def test_no_se_exponen_passwords_en_listar_servicios(self):
        self.gestor.añadir_credencial(self.master_password, self.servicio, self.usuario, self.password)
        servicios = self.gestor.listar_servicios(self.master_password)
        self.assertNotIn(self.password, servicios)


if __name__ == "__main__":
    unittest.main()
