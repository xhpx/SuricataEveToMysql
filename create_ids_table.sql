CREATE TABLE `ids_alert_event` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sid` int(11) DEFAULT NULL COMMENT '规则id',
  `msg` varchar(512) DEFAULT NULL COMMENT '入侵事件名称',
  `src_ip` varchar(128) DEFAULT NULL COMMENT '源IP地址',
  `src_port` varchar(50) DEFAULT NULL COMMENT '源端口',
  `dst_ip` varchar(128) DEFAULT NULL COMMENT '目的IP地址',
  `dst_port` varchar(50) DEFAULT NULL COMMENT '目的端口',
  `protocol` varchar(100) DEFAULT NULL COMMENT '协议',
  `risk_category` varchar(100) DEFAULT NULL COMMENT '事件类别',
  `risk_level` varchar(50) DEFAULT NULL COMMENT '风险等级',
  `rule_version` int(11) DEFAULT NULL COMMENT '规则版本', 
  `create_time` datetime DEFAULT NULL COMMENT '创建时间',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='入侵威胁事件';
