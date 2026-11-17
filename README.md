# Resolución: Vulnerabilidad *sshole* (CVE-2026-123158)

## 1. Arquitectura y Dependencias
Para que un sistema sea vulnerable a *sshole*, se requiere la convergencia estricta de tres componentes específicos en su arquitectura:

1. **Biblioteca C (libc):** El sistema debe utilizar **`musl libc`** en lugar de la tradicional `glibc`. Esto es muy común en distribuciones ligeras orientadas a contenedores Docker, como Alpine Linux.
2. **Gestor de Autenticación:** El servicio SSH debe estar operando **sin el soporte de PAM** (*Pluggable Authentication Modules*). Esto ocurre si OpenSSH fue compilado sin soporte PAM o si está explícitamente deshabilitado (`UsePAM no` en la configuración).
3. **Demonio SSH:** Una versión vulnerable de **OpenSSH** que dependa directamente de la función `crypt()` del sistema para validar las contraseñas contra el archivo `/etc/shadow`.

**¿Por qué los sistemas con `glibc` y PAM están exentos?**
Los sistemas tradicionales (como Ubuntu o Debian) utilizan `glibc`, cuya implementación de `crypt()` maneja las entradas anómalas de manera diferente. Más importante aún, al utilizar **PAM** (`UsePAM yes`), la validación de la cuenta no se limita a una simple comparación de cadenas de texto (hashes). PAM verifica de manera independiente y robusta el estado de la cuenta (si está bloqueada, expirada o deshabilitada), bloqueando el acceso antes de que cualquier colisión a nivel de `crypt()` pueda ser explotada.

---

## 2. Mecánica de la Colisión

El bypass de autenticación se produce por una falla lógica fatal en cómo interactúan estos tres elementos: la gestión del *salt* en OpenSSH, el manejo de errores de `musl libc` y el envío de un payload sobredimensionado. El proceso ocurre de la siguiente manera:

1. **Gestión del Salt en OpenSSH:** Cuando un usuario intenta iniciar sesión, OpenSSH busca la cuenta en `/etc/shadow` y extrae su campo de contraseña. En cuentas bloqueadas o de sistema (como `root` en Alpine, o `bin`), este campo no contiene un hash real, sino un asterisco (`*`) o una exclamación (`!`). OpenSSH toma esta cadena completa y la pasa como el parámetro **salt** a la función `crypt(password, salt)`.
2. **Inyección de Contraseña Larga:** El atacante intenta autenticarse en esa cuenta bloqueada inyectando una contraseña anormalmente larga (superior a 256 caracteres).
3. **Manejo de Errores en musl libc:** La función `crypt()` de la librería `musl` recibe la contraseña gigante y el *salt* (que es `*`). Debido a una limitación interna de `musl`, no procesa contraseñas de más de 256 caracteres. En lugar de detener el servicio, la función aborta la operación de forma controlada y devuelve una cadena de error estandarizada, que resulta ser exactamente un asterisco (`*`).
4. **La Colisión y el Falso Positivo:** OpenSSH recibe el resultado de `crypt()` (el asterisco de error) y lo compara con el "hash" original almacenado en `/etc/shadow` (que también es un asterisco). Al evaluar la condición (`* == *`), la comparación resulta verdadera. OpenSSH asume erróneamente que la contraseña ingresada generó el hash correcto, ignorando que la cuenta es inaccesible, y otorga acceso interactivo al atacante.
---

## 3. Mitigación y Endurecimiento
Además de actualizar el paquete OpenSSH, se deben implementar medidas de **Defensa en Profundidad (Hardening)** editando el archivo de configuración `/etc/ssh/sshd_config` para reducir drásticamente la superficie de ataque:

* **Medida 1: Habilitar PAM (Pluggable Authentication Modules)**
  Obligar a OpenSSH a delegar la autenticación en PAM garantiza que se validen correctamente los estados de las cuentas bloqueadas.
  ```ini
  UsePAM yes
  ```

* **Medida 2: Restricción explícita de usuarios (AllowUsers / DenyUsers)**
  Implementar listas de control de acceso a nivel de SSH. Esto previene que se intente iniciar sesión en cuentas de sistema o cuentas bloqueadas, incluso si existe una colisión de hashes.
  ```ini
  # Solo permitir a usuarios humanos específicos
  AllowUsers admin d.zapata
  
  # Bloquear explícitamente el acceso de root u otras cuentas
  PermitRootLogin no
  ```

---

## 4. Análisis Forense de Incidente (HackTheBox Sherlock - *sshole*)

A continuación, se documentan los hallazgos tras investigar los artefactos de registro proporcionados en el laboratorio forense **Sherlock "*sshole*" de HackTheBox**. Asumiendo el rol de analista SOC/DFIR, se investigó la intrusión en el entorno contenedorizado basada en la vulnerabilidad CVE-2026-123158.

### Análisis de Artefactos y Trazabilidad del Ataque

Al examinar los registros del sistema operativo del contenedor (típicamente ubicados en `/var/log/auth.log`, el registro de `journald` o los logs del propio servicio `sshd`), se logró reconstruir la cadena del ataque:

**Hallazgo 1: Identificación del Vector de Ataque y Payload**
Se detectó tráfico de autenticación anómalo dirigido al servicio SSH. El atacante inyectó deliberadamente una contraseña con una longitud extrema (superior a 256 caracteres). El propósito de esta cadena es provocar el desbordamiento de la función `crypt()` en la librería `musl libc`, forzando que esta devuelva el código de error estándar (`*`).

> **Evidencia 1: Registro del intento de conexión y payload anómalo**
> *[Inserta aquí la captura del log que muestre la IP del atacante, la fecha/hora y el intento de conexión inusual]*

**Hallazgo 2: Confirmación del Bypass de Autenticación**
La colisión lógica se ejecutó con éxito. Los registros demuestran que OpenSSH comparó el asterisco devuelto por `crypt()` con el asterisco almacenado en el archivo `/etc/shadow` para una cuenta bloqueada o de servicio. Como resultado, el demonio validó erróneamente las credenciales.

> **Evidencia 2: Inicio de sesión exitoso (Falso Positivo)**
> *[Inserta aquí la captura del log que evidencia el mensaje "Accepted password" o "Session opened" para la cuenta comprometida, a pesar de estar bloqueada]*

**Hallazgo 3: Acciones Post-Explotación (Opcional según las preguntas del laboratorio)**
Una vez obtenida la shell interactiva, el atacante pudo ejecutar comandos no autorizados en el sistema con los privilegios de la cuenta vulnerada.

> **Evidencia 3: Ejecución de comandos / Artefactos adicionales**
> *[Inserta aquí capturas de logs de auditoría, bash_history u otros artefactos solicitados por las preguntas del laboratorio de HTB]*

> **Evidencia de desafio completado**
<img width="1270" height="745" alt="image" src="https://github.com/user-attachments/assets/18b6e82d-c44a-4bef-9378-e5eaad2efe48" />

