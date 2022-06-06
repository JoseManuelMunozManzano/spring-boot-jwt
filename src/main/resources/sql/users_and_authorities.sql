-- Estas tablas son para generarlas en MySqlWorkBench

-- Se puede llamar de cualquier manera, pero el standard es llamarlo users
-- El campo password para encriptación de bcrypt, de 60 caracteres
-- El campo enabled es vale 1 o 0
CREATE TABLE `db_springboot`.`users` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(45) NOT NULL,
  `password` VARCHAR(60) NOT NULL,
  `enabled` TINYINT(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `username_UNIQUE` (`username` ASC) VISIBLE);

-- Se puede llamar de cualquier manera, pero el standard es llamarlo authorities. Son los roles
-- El campo user_id es la llave foránea. user en singular seguido de _id es el standard para el nombre.
-- Cuando se actualice/elimine el usuario en la tabla users, que en cascada se actualicen/eliminen los registros
--   en esta tabla authorities relacionada.
CREATE TABLE `db_springboot`.`authorities` (
`id` INT NOT NULL AUTO_INCREMENT,
`user_id` INT NOT NULL,
`authority` VARCHAR(45) NOT NULL,
PRIMARY KEY (`id`),
UNIQUE INDEX `user_id_authority_unique` (`user_id` ASC, `authority` ASC) VISIBLE,
CONSTRAINT `fk_authorities_users`
  FOREIGN KEY (`user_id`)
  REFERENCES `db_springboot`.`users` (`id`)
  ON DELETE CASCADE
  ON UPDATE CASCADE);


-- Registros a dar de alta de ejemplo

-- Usuarios
-- Como la contraseña es encriptada, para obtenerla, tal y como tenemos el proyecto ahora mismo, generábamos dos
-- contraseñas a partir del string 1234 (ver SpringBootDataJpaApplication.java)
-- Ejecutamos el proyecto y cogemos esas 2 claves que se pueden visualizar en la consola.
INSERT INTO users (username, password, enabled) VALUES('jmunoz', '$2a$10$xPfk35XZJQdlJrAFAeSVa.9Y/xZ3E3U4uoFd7cVoy5JZWSP/M/q/2', 1);
INSERT INTO users (username, password, enabled) VALUES('admin', '$2a$10$yoVp69dAWHAvxZZ27mFe2.B8dn/pGgfVFqqdL34Td8P5BakQNzU2m', 1);

-- Roles
INSERT INTO authorities (user_id, authority) VALUES(1, 'ROLE_USER');
INSERT INTO authorities (user_id, authority) VALUES(2, 'ROLE_USER');
INSERT INTO authorities (user_id, authority) VALUES(2, 'ROLE_ADMIN');