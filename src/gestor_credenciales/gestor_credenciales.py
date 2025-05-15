import bcrypt
from icontract import require, ensure

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.FileHandler("audit.log")
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)


class ErrorPoliticaPassword(Exception):
    pass


class ErrorAutenticacion(Exception):
    pass


class ErrorServicioNoEncontrado(Exception):
    pass


class ErrorCredencialExistente(Exception):
    pass


class GestorCredenciales:
    def __init__(self, clave_maestra: str):
        """Inicializa el gestor con una clave maestra."""
        self._clave_maestra_hashed = self._hash_clave(clave_maestra)
        self._credenciales = {}

    @ensure(lambda servicio, usuario, result: result is None)
    def añadir_credencial(self, clave_maestra: str, servicio: str, usuario: str, password: str) -> None:
        """Añade una nueva credencial al gestor."""
        logger.info(f"Añadir credencial - servicio: {servicio}, usuario: {usuario}")
        # Verificar autenticación
        if not bcrypt.checkpw(clave_maestra.encode('utf-8'), self._clave_maestra_hashed):
            raise ErrorAutenticacion("Clave maestra incorrecta")
        # Validación de entradas
        if not servicio or not usuario:
            raise ValueError("Servicio y usuario no pueden estar vacíos")
        if any(c in servicio for c in ";&|'"):
            raise ValueError("Nombre de servicio inválido")
        # Política de password
        if not self.es_password_segura(password):
            raise ErrorPoliticaPassword("La contraseña no cumple la política de seguridad")
        # Prevenir duplicados
        if servicio not in self._credenciales:
            self._credenciales[servicio] = {}
        if usuario in self._credenciales[servicio]:
            raise ErrorCredencialExistente("La credencial ya existe")
        # Almacenar password cifrada
        hashed_pwd = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self._credenciales[servicio][usuario] = hashed_pwd
        logger.info(f"Credencial añadida - servicio: {servicio}, usuario: {usuario}")

    @require(lambda servicio: servicio)
    @ensure(lambda servicio, result: result is None)
    def eliminar_credencial(self, clave_maestra: str, servicio: str, usuario: str) -> None:
        """Elimina una credencial existente."""
        logger.info(f"Eliminar credencial - servicio: {servicio}, usuario: {usuario}")
        if not bcrypt.checkpw(clave_maestra.encode('utf-8'), self._clave_maestra_hashed):
            raise ErrorAutenticacion("Clave maestra incorrecta")
        if servicio not in self._credenciales or usuario not in self._credenciales[servicio]:
            raise ErrorServicioNoEncontrado("Servicio o usuario no encontrado")
        del self._credenciales[servicio][usuario]
        if not self._credenciales[servicio]:
            del self._credenciales[servicio]
        logger.info(f"Credencial eliminada - servicio: {servicio}, usuario: {usuario}")

    @ensure(lambda result: isinstance(result, list))
    def listar_servicios(self, clave_maestra: str) -> list:
        """Lista todos los servicios almacenados."""
        logger.info("Listar servicios")
        if not bcrypt.checkpw(clave_maestra.encode('utf-8'), self._clave_maestra_hashed):
            raise ErrorAutenticacion("Clave maestra incorrecta")
        servicios = list(self._credenciales.keys())
        logger.info(f"Servicios listados: {servicios}")
        return servicios

    def _hash_clave(self, clave: str) -> str:
        """Hashea una clave usando bcrypt."""
        return bcrypt.hashpw(clave.encode('utf-8'), bcrypt.gensalt())

    def es_password_segura(self, password: str) -> bool:
        if len(password) < 8:
            return False
        if not any(c.isupper() for c in password):
            return False
        if not any(c.islower() for c in password):
            return False
        if not any(c.isdigit() for c in password):
            return False
        if not any(c in "!@#$%^&*" for c in password):
            return False
        return True

    @require(lambda servicio: servicio)
    @ensure(lambda result: isinstance(result, bool))
    def verificar_password(self, clave_maestra: str, servicio: str, usuario: str, password_a_verificar: str) -> bool:
        """Verifica si la contraseña proporcionada coincide con la almacenada."""
        logger.info(f"Verificar credencial - servicio: {servicio}, usuario: {usuario}")
        if not bcrypt.checkpw(clave_maestra.encode('utf-8'), self._clave_maestra_hashed):
            raise ErrorAutenticacion("Clave maestra incorrecta")
        if servicio not in self._credenciales or usuario not in self._credenciales[servicio]:
            # If service/user not found, it means password cannot be verified against anything for them.
            # Raising ErrorServicioNoEncontrado is one option. Another is to return False.
            # For a verification method, returning False for non-existent entries is often cleaner.
            # However, to keep failure modes distinct, we can keep raising for now.
            # If tests expect False for non-existent, this needs to change to: return False
            raise ErrorServicioNoEncontrado("Servicio o usuario no encontrado")

        stored_hash = self._credenciales[servicio][usuario]
        result = bcrypt.checkpw(password_a_verificar.encode('utf-8'), stored_hash.encode('utf-8'))
        logger.info(f"Resultado verificación: {result} - servicio: {servicio}, usuario: {usuario}")
        return result
