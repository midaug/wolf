

-- upgrade to 0.5.x (ldap version)

ALTER TABLE `user` ADD COLUMN auth_type smallint DEFAULT 1 comment 'user authentication type, 1: password, 2: LDAP, 3: usersign';

-- upgrade to 0.5.5 (authentication type add sign)
ALTER TABLE `user` MODIFY COLUMN auth_type smallint DEFAULT 1 comment 'user authentication type, 1: password, 2: LDAP, 3: usersign';
ALTER TABLE `user` ADD COLUMN ukey varchar(36) comment 'Signature authentication key';
ALTER TABLE `user` ADD COLUMN usecret varchar(36) comment 'Signature authentication secret';
alter table `user` add unique ukey (`ukey`);
