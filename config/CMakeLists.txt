install(FILES breeder.conf.example DESTINATION ${SYSCONF_INSTALL_DIR}/ProjectRiddle RENAME breeder.conf)

configure_file(configPath.h.in configPath.h)