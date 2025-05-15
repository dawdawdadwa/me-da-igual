import unittest
from src.gestor_credenciales.gestor_credenciales import GestorCredenciales, ErrorPoliticaPassword, ErrorAutenticacion, ErrorServicioNoEncontrado, ErrorCredencialExistente


class TestFuncionalesGestorCredenciales(unittest.TestCase):
    def setUp(self):
        self.master_password = "ClaveMaestraSegura123!"
        self.gestor = GestorCredenciales(self.master_password)
        self.servicio = "GitHub"
        self.usuario = "user1"
        self.password = "PasswordSegura123!"

    def test_añadir_credencial_exito(self):
        self.gestor.añadir_credencial(self.master_password, self.servicio, self.usuario, self.password)
        self.assertIn(self.servicio, self.gestor._credenciales)
        self.assertIn(self.usuario, self.gestor._credenciales[self.servicio])

    def test_añadir_credencial_existente(self):
        self.gestor.añadir_credencial(self.master_password, self.servicio, self.usuario, self.password)
        with self.assertRaises(ErrorCredencialExistente):
            self.gestor.añadir_credencial(self.master_password, self.servicio, self.usuario, self.password)

    def test_verificar_credencial_exito(self):
        self.gestor.añadir_credencial(self.master_password, self.servicio, self.usuario, self.password)
        self.assertTrue(self.gestor.verificar_password(
            self.master_password, self.servicio, self.usuario, self.password))
        self.assertFalse(self.gestor.verificar_password(self.master_password,
                         self.servicio, self.usuario, "IncorrectPassword123!"))

    def test_verificar_credencial_no_existente(self):
        with self.assertRaises(ErrorServicioNoEncontrado):
            self.gestor.verificar_password(self.master_password, "NoExiste", self.usuario, self.password)

    def test_eliminar_credencial_exito(self):
        self.gestor.añadir_credencial(self.master_password, self.servicio, self.usuario, self.password)
        self.gestor.eliminar_credencial(self.master_password, self.servicio, self.usuario)
        self.assertNotIn(self.usuario, self.gestor._credenciales.get(self.servicio, {}))

    def test_eliminar_credencial_no_existente(self):
        with self.assertRaises(ErrorServicioNoEncontrado):
            self.gestor.eliminar_credencial(self.master_password, "NoExiste", self.usuario)

    def test_listar_servicios(self):
        servicios = ["GitHub", "Google", "Outlook"]
        for s in servicios:
            self.gestor.añadir_credencial(self.master_password, s, self.usuario, self.password)
        lista = self.gestor.listar_servicios(self.master_password)
        self.assertCountEqual(lista, servicios)

    def test_listar_servicios_vacio(self):
        lista = self.gestor.listar_servicios(self.master_password)
        self.assertEqual(lista, [])


if __name__ == "__main__":
    unittest.main()
