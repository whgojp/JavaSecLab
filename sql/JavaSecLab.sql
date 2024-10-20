/*
 Navicat Premium Data Transfer

 Source Server         : mysql_docker_mac
 Source Server Type    : MySQL
 Source Server Version : 80200 (8.2.0)
 Source Host           : localhost:13306
 Source Schema         : JavaSecLab

 Target Server Type    : MySQL
 Target Server Version : 80200 (8.2.0)
 File Encoding         : 65001

 Date: 26/08/2024 19:15:41
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for hsqli
-- ----------------------------
DROP TABLE IF EXISTS `hsqli`;
CREATE TABLE `hsqli` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `password` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `username` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ----------------------------
-- Records of hsqli
-- ----------------------------
BEGIN;
COMMIT;

-- ----------------------------
-- Table structure for log
-- ----------------------------
DROP TABLE IF EXISTS `log`;
CREATE TABLE `log` (
  `logId` varchar(255) COLLATE utf8mb4_general_ci NOT NULL COMMENT 'log_id',
  `username` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '用户名',
  `optionName` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '用户操作',
  `optionTerminal` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '操作终端',
  `optionIp` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT 'Ip地址',
  `optionTime` date DEFAULT NULL COMMENT '创建时间',
  PRIMARY KEY (`logId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ----------------------------
-- Records of log
-- ----------------------------
BEGIN;
COMMIT;

-- ----------------------------
-- Table structure for sqli
-- ----------------------------
DROP TABLE IF EXISTS `sqli`;
CREATE TABLE `sqli` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户名',
  `password` varchar(255) COLLATE utf8mb4_general_ci NOT NULL COMMENT '密码',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=730 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ----------------------------
-- Records of sqli
-- ----------------------------
BEGIN;
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (706, '321', 'qwe');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (707, '2', '1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (708, '1', '21');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (713, '1', '1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (714, 'qwe', 'qwe');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (715, '1', '1\' AND GTID_SUBSET(CONCAT(0x71706a7a71,(SELECT (ELT(7170=7170,1))),0x7171717071),7170) AND \'1\'=\'1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (716, '1', '1\' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) AND \'1\'=\'1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (717, '1', '1\' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) AND \'1\'=\'1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (718, '1', '1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (719, 'test', '1\' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) AND \'1\'=\'1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (720, 'test', '1\' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) AND \'1\'=\'1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (721, 'test', '1\' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) AND \'1\'=\'1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (722, 'test', '1\' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) AND \'1\'=\'1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (723, 'test', '1\' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) AND \'1\'=\'1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (724, 'test', '1\' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) AND \'1\'=\'1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (725, 'test', '1\' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) AND \'1\'=\'1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (726, '1', '1\' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) AND \'1\'=\'1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (727, '1', '1\' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) AND \'1\'=\'1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (728, '1', '1\' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) AND \'1\'=\'1');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (729, '1', '1\' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) AND \'1\'=\'1');
COMMIT;

-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `username` varchar(255) COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户名',
  `password` varchar(255) COLLATE utf8mb4_general_ci NOT NULL COMMENT '密码',
  PRIMARY KEY (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ----------------------------
-- Records of user
-- ----------------------------
BEGIN;
INSERT INTO `user` (`username`, `password`) VALUES ('1', '1');
INSERT INTO `user` (`username`, `password`) VALUES ('123', '123');
INSERT INTO `user` (`username`, `password`) VALUES ('admin', 'admin');
COMMIT;

-- ----------------------------
-- Table structure for xss
-- ----------------------------
DROP TABLE IF EXISTS `xss`;
CREATE TABLE `xss` (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '主键id',
  `content` text COLLATE utf8mb4_general_ci NOT NULL COMMENT '插入内容',
  `ua` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'User-Agent',
  `date` varchar(255) COLLATE utf8mb4_general_ci NOT NULL COMMENT '插入时间',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=74 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ----------------------------
-- Records of xss
-- ----------------------------
BEGIN;
INSERT INTO `xss` (`id`, `content`, `ua`, `date`) VALUES (65, '123<u>A</u>123', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36', '2024-06-30 23:36:48');
INSERT INTO `xss` (`id`, `content`, `ua`, `date`) VALUES (66, '123<a href=javascript:alert(/xss/)>Click Me</a>123', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36', '2024-06-30 23:37:02');
INSERT INTO `xss` (`id`, `content`, `ua`, `date`) VALUES (69, '123', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0', '2024-07-21 10:07:34');
COMMIT;

SET FOREIGN_KEY_CHECKS = 1;
