-- phpMyAdmin SQL Dump
-- version 3.5.8.2
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Jan 13, 2014 at 02:29 PM
-- Server version: 5.1.71
-- PHP Version: 5.3.3

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `stonix`
--
CREATE DATABASE `stonix` DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci;
USE `stonix`;

-- --------------------------------------------------------

--
-- Table structure for table `RunData`
--

CREATE TABLE IF NOT EXISTS `RunData` (
  `MetaDataId` bigint(20) NOT NULL,
  `Rule` varchar(100) COLLATE utf8_unicode_ci DEFAULT NULL,
  `Finding` mediumtext COLLATE utf8_unicode_ci,
  `RowId` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  UNIQUE KEY `RowId` (`RowId`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=97 ;

-- --------------------------------------------------------

--
-- Table structure for table `RunMetaData`
--

CREATE TABLE IF NOT EXISTS `RunMetaData` (
  `RowId` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `RunTime` datetime NOT NULL,
  `Hostname` varchar(50) COLLATE utf8_unicode_ci DEFAULT NULL,
  `UploadAddress` varchar(15) COLLATE utf8_unicode_ci DEFAULT NULL,
  `IPAddress` varchar(15) COLLATE utf8_unicode_ci DEFAULT NULL,
  `OS` varchar(100) COLLATE utf8_unicode_ci DEFAULT NULL,
  `PropertyNumber` varchar(20) COLLATE utf8_unicode_ci DEFAULT NULL,
  `SystemSerialNo` varchar(36) COLLATE utf8_unicode_ci DEFAULT NULL,
  `ChassisSerialNo` varchar(36) COLLATE utf8_unicode_ci DEFAULT NULL,
  `SystemManufacturer` varchar(30) COLLATE utf8_unicode_ci DEFAULT NULL,
  `ChassisManufacturer` varchar(30) COLLATE utf8_unicode_ci DEFAULT NULL,
  `UUID` varchar(100) COLLATE utf8_unicode_ci DEFAULT NULL,
  `MACAddress` varchar(20) COLLATE utf8_unicode_ci DEFAULT NULL,
  `xmlFileName` varchar(100) COLLATE utf8_unicode_ci DEFAULT NULL,
  `STONIXversion` varchar(80) DEFAULT NULL,
  `RuleCount` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`RowId`),
  UNIQUE KEY `RowId` (`RowId`),
  KEY `RunTime` (`RunTime`,`Hostname`,`IPAddress`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=6 ;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
