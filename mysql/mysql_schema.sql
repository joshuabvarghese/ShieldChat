-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE=`ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION`;

-- -----------------------------------------------------
-- Schema safedb
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `safedb` DEFAULT CHARACTER SET utf8 ;
USE `safedb` ;

-- -----------------------------------------------------
-- Table 'safedb'.'users'
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `safedb`.`users` (
  `user_id` INT NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(45) NULL,
  `password` VARCHAR(100) NULL,
  PRIMARY KEY (`user_id`),
  UNIQUE INDEX `user_id_UNIQUE` (`user_id` ASC) VISIBLE)
ENGINE = InnoDB;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;

INSERT INTO users (username, password) VALUES ('test1', 'password1');
INSERT INTO users (username, password) VALUES ('test2', 'password2');
INSERT INTO users (username, password) VALUES ('bob', '$argon2id$v=19$m=102400,t=2,p=8$9GGUzFE9zu9fCKGN2inBcg$l8GWjhG3lAW8USexAvObXA');
INSERT INTO users (username, password) VALUES ('alice', '$argon2id$v=19$m=102400,t=2,p=8$c7vMBhoZr2edXggwqlwt5g$ADjOT/uFmZTww1+mMh5zNg');

