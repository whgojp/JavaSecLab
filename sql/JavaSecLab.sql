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

 Date: 22/06/2024 17:35:45
*/
CREATE DATABASE IF NOT EXISTS JavaSecLab;
USE JavaSecLab;

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

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
INSERT INTO `user` (`username`, `password`) VALUES ('admin', 'admin');
COMMIT;

-- ----------------------------
-- Table structure for xss
-- ----------------------------
DROP TABLE IF EXISTS `xss`;
CREATE TABLE `xss` (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '主键id',
  `content` text COLLATE utf8mb4_general_ci NOT NULL COMMENT '插入内容',
  `date` varchar(255) COLLATE utf8mb4_general_ci NOT NULL COMMENT '插入时间',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=35 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ----------------------------
-- Records of xss
-- ----------------------------
BEGIN;
INSERT INTO `xss` (`id`, `content`, `date`) VALUES (34, '1', '2024-06-11 14:29:36');
COMMIT;

SET FOREIGN_KEY_CHECKS = 1;
